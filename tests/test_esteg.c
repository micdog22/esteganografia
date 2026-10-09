/*
 * test_esteg.c: testes de unidade.
 *
 * Vetores oficiais para SHA-256 (FIPS 180-4), HMAC (RFC 4231), PBKDF2,
 * HKDF (RFC 5869) e ChaCha20 (RFC 8439); leitura de BMPs em vários
 * formatos; ida e volta com dados aleatórios; erros de capacidade, senha
 * e corrupção; e o ataque do qui-quadrado.
 */
#include "teste.h"

#include "bmp_sintetico.h"
#include "cripto.h"
#include "esteg.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------ utilidades */

static uint64_t rng_state = 99;

static uint64_t rng_next(void)
{
    uint64_t z = (rng_state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static void random_bytes(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)rng_next();
}

static int hex_equal(const uint8_t *bytes, size_t n, const char *hex)
{
    if (strlen(hex) != 2 * n)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        char pair[3] = {hex[2 * i], hex[2 * i + 1], 0};
        v = (unsigned)strtoul(pair, NULL, 16);
        if (bytes[i] != v)
            return 0;
    }
    return 1;
}

static void from_hex(const char *hex, uint8_t *out)
{
    for (size_t i = 0; hex[2 * i]; i++) {
        char pair[3] = {hex[2 * i], hex[2 * i + 1], 0};
        out[i] = (uint8_t)strtoul(pair, NULL, 16);
    }
}

static int load_synth(const synth_params *p, bmp_image *img)
{
    size_t size;
    uint8_t *data = synth_bmp(p, &size);
    if (data == NULL)
        return 0;
    if (bmp_parse(img, data, size) != EST_OK) {
        free(data);
        return 0;
    }
    return 1;
}

static synth_params params(int w, int h, int bpp, int top, int header, int rgba, int pattern)
{
    synth_params p;
    memset(&p, 0, sizeof p);
    p.width = w;
    p.height = h;
    p.bpp = bpp;
    p.top_down = top;
    p.header = header;
    p.rgba = rgba;
    p.pattern = pattern;
    p.seed = 7;
    return p;
}

static const uint8_t SALT[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

static est_options options(const char *password, int encrypt, int bits)
{
    est_options o = est_default_options();
    o.password = password;
    o.encrypt = encrypt;
    o.bits = bits;
    o.iterations = 1000;   /* rápido nos testes */
    o.salt = SALT;
    return o;
}

/* ---------------------------------------------------------- criptografia */

static void test_sha256(void)
{
    SECTION("SHA-256 (FIPS 180-4)");
    uint8_t d[32];
    sha256("", 0, d);
    CHECK(hex_equal(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    sha256("abc", 3, d);
    CHECK(hex_equal(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(m448, strlen(m448), d);
    CHECK(hex_equal(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    /* Um milhão de 'a', em pedaços de tamanhos variados. */
    sha256_ctx c;
    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof chunk);
    sha256_init(&c);
    size_t left = 1000000, step = 1;
    while (left > 0) {
        size_t take = step < left ? step : left;
        sha256_update(&c, chunk, take);
        left -= take;
        step = step * 3 % 997 + 1;
    }
    sha256_final(&c, d);
    CHECK(hex_equal(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

    /* Dividir a mensagem em dois pedaços, em qualquer ponto, dá o mesmo hash. */
    uint8_t msg[200], whole[32];
    random_bytes(msg, sizeof msg);
    sha256(msg, sizeof msg, whole);
    int ok = 1;
    for (size_t cut = 0; cut <= sizeof msg; cut++) {
        sha256_init(&c);
        sha256_update(&c, msg, cut);
        sha256_update(&c, msg + cut, sizeof msg - cut);
        sha256_final(&c, d);
        if (memcmp(d, whole, 32) != 0)
            ok = 0;
    }
    CHECK(ok);
}

static void test_hmac_kdf(void)
{
    SECTION("HMAC-SHA256 (RFC 4231), PBKDF2 e HKDF");
    uint8_t d[64];
    uint8_t key[131];

    memset(key, 0x0b, 20);
    hmac_sha256(key, 20, "Hi There", 8, d);
    CHECK(hex_equal(d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    hmac_sha256((const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, d);
    CHECK(hex_equal(d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    /* Caso 6: chave maior que o bloco (vira o próprio hash). */
    memset(key, 0xaa, 131);
    const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    hmac_sha256(key, 131, m6, strlen(m6), d);
    CHECK(hex_equal(d, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));

    pbkdf2_hmac_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 1, d, 32);
    CHECK(hex_equal(d, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
    pbkdf2_hmac_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 4096, d, 32);
    CHECK(hex_equal(d, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
    /* Saída de 40 bytes: dois blocos do PBKDF2. */
    const char *pw = "passwordPASSWORDpassword", *st = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    pbkdf2_hmac_sha256((const uint8_t *)pw, strlen(pw), (const uint8_t *)st, strlen(st), 4096, d,
                       40);
    CHECK(hex_equal(d, 40, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"));

    /* RFC 5869, caso 1: o primeiro bloco do HKDF-Expand. */
    uint8_t prk[32];
    from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", prk);
    char info[11];
    for (int i = 0; i < 10; i++)
        info[i] = (char)(0xf0 + i);
    info[10] = '\0';
    hkdf_expand32(prk, info, d);
    CHECK(hex_equal(d, 32, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"));

    uint8_t a[4] = {1, 2, 3, 4}, b[4] = {1, 2, 3, 5};
    CHECK(ct_equal(a, a, 4));
    CHECK(!ct_equal(a, b, 4));
}

static void test_chacha20(void)
{
    SECTION("ChaCha20 (RFC 8439)");
    uint8_t key[32], nonce[12], out[64];
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)i;
    /* Seção 2.3.2: a função de bloco. */
    from_hex("000000090000004a00000000", nonce);
    chacha20_block(key, 1, nonce, out);
    CHECK(hex_equal(out, 64,
                    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"));

    /* Seção 2.4.2: cifrando o texto do "sunscreen". */
    const char *plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one "
                        "tip for the future, sunscreen would be it.";
    size_t n = strlen(plain);
    uint8_t buf[128];
    memcpy(buf, plain, n);
    from_hex("000000000000004a00000000", nonce);
    chacha20_ctx c;
    chacha20_init(&c, key, nonce, 1);
    /* Em pedaços de tamanhos diferentes, para testar a continuação do fluxo. */
    chacha20_xor(&c, buf, 7);
    chacha20_xor(&c, buf + 7, 64);
    chacha20_xor(&c, buf + 71, n - 71);
    CHECK(hex_equal(buf, n,
                    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab"
                    "8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e"
                    "52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"));
    chacha20_init(&c, key, nonce, 1);
    chacha20_xor(&c, buf, n);
    CHECK(memcmp(buf, plain, n) == 0);   /* decifrar = cifrar de novo */
}

static void test_crc(void)
{
    SECTION("CRC-32");
    CHECK_EQ(est_crc32(0, "123456789", 9), 0xCBF43926u);
    CHECK_EQ(est_crc32(0, "", 0), 0);
}

/* -------------------------------------------------------------------- BMP */

static void test_bmp_formats(void)
{
    SECTION("BMP: 24 e 32 bits, V4 e V5, as duas ordens de linhas");
    const struct {
        int bpp, header, rgba;
    } kinds[] = {{24, 40, 0}, {32, 40, 0}, {24, 124, 0}, {32, 108, 0}, {32, 124, 0}, {32, 124, 1}};
    int ok = 1;
    for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
        for (int top = 0; top < 2; top++) {
            for (int w = 1; w <= 7; w++) {
                synth_params p = params(w, 5, kinds[k].bpp, top, kinds[k].header, kinds[k].rgba,
                                        PATTERN_NOISE);
                bmp_image img;
                if (!load_synth(&p, &img)) {
                    ok = 0;
                    continue;
                }
                size_t stride = ((size_t)w * (size_t)kinds[k].bpp + 31) / 32 * 4;
                if (img.width != w || img.height != 5 || img.top_down != top ||
                    img.stride != stride || img.bits_per_pixel != kinds[k].bpp ||
                    img.header_size != (uint32_t)kinds[k].header)
                    ok = 0;
                if (bmp_channels(&img) != (size_t)w * 5 * 3)
                    ok = 0;
                /* O canal i, na ordem da imagem, é a cor que o gerador desenhou. */
                for (int y = 0; y < 5; y++)
                    for (int x = 0; x < w; x++) {
                        uint8_t rgb[3];
                        synth_color(&p, x, y, rgb);
                        size_t base = ((size_t)y * (size_t)w + (size_t)x) * 3;
                        if (*bmp_channel(&img, base) != rgb[2] ||       /* azul */
                            *bmp_channel(&img, base + 1) != rgb[1] ||   /* verde */
                            *bmp_channel(&img, base + 2) != rgb[0])     /* vermelho */
                            ok = 0;
                    }
                if (kinds[k].bpp == 32 && img.alpha_offset != 3)
                    ok = 0;
                bmp_free(&img);
            }
        }
    }
    CHECK(ok);
}

static void test_bmp_errors(void)
{
    SECTION("BMP: arquivos inválidos e formatos não suportados");
    bmp_image img;
    uint8_t png[60] = {0x89, 'P', 'N', 'G'};
    uint8_t *copy;
    size_t size;
    synth_params p = params(4, 4, 24, 0, 40, 0, PATTERN_NOISE);
    uint8_t *good = synth_bmp(&p, &size);

    CHECK_EQ(bmp_parse(&img, png, sizeof png), EST_ERR_NOT_BMP);
    CHECK_EQ(bmp_parse(&img, good, 30), EST_ERR_CORRUPT_BMP);

    /* Cada caso altera uma cópia do BMP bom. */
    struct {
        size_t offset;
        uint32_t value;
        int width;   /* bytes: 2 ou 4 */
        est_status expected;
    } cases[] = {
        {28, 8, 2, EST_ERR_UNSUPPORTED},    /* 8 bits por pixel */
        {28, 16, 2, EST_ERR_UNSUPPORTED},   /* 16 bits por pixel */
        {30, 1, 4, EST_ERR_UNSUPPORTED},    /* compressão RLE8 */
        {30, 3, 4, EST_ERR_UNSUPPORTED},    /* bitfields em 24 bits */
        {14, 12, 4, EST_ERR_UNSUPPORTED},   /* BITMAPCOREHEADER (OS/2) */
        {18, 0, 4, EST_ERR_CORRUPT_BMP},    /* largura zero */
        {22, 0, 4, EST_ERR_CORRUPT_BMP},    /* altura zero */
        {26, 2, 2, EST_ERR_CORRUPT_BMP},    /* dois planos */
        {10, 100000, 4, EST_ERR_CORRUPT_BMP},  /* pixels fora do arquivo */
        {18, 1000, 4, EST_ERR_CORRUPT_BMP}, /* largura maior que os dados */
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        copy = malloc(size);
        memcpy(copy, good, size);
        for (int b = 0; b < cases[i].width; b++)
            copy[cases[i].offset + (size_t)b] = (uint8_t)(cases[i].value >> (8 * b));
        est_status st = bmp_parse(&img, copy, size);
        CHECK_EQ(st, cases[i].expected);
        if (st == EST_OK)
            bmp_free(&img);
        else
            free(copy);
    }
    /* Arquivo cortado no meio dos pixels. */
    copy = malloc(size);
    memcpy(copy, good, size);
    CHECK_EQ(bmp_parse(&img, copy, size - 1), EST_ERR_CORRUPT_BMP);
    free(copy);

    /* Bitfields com máscaras de 10 bits por cor (formato 10-10-10). */
    synth_params p32 = params(4, 4, 32, 0, 124, 0, PATTERN_NOISE);
    uint8_t *v5 = synth_bmp(&p32, &size);
    uint32_t masks[3] = {0x3FF00000u, 0x000FFC00u, 0x000003FFu};
    for (int m = 0; m < 3; m++)
        for (int b = 0; b < 4; b++)
            v5[54 + 4 * m + b] = (uint8_t)(masks[m] >> (8 * b));
    CHECK_EQ(bmp_parse(&img, v5, size), EST_ERR_UNSUPPORTED);
    free(v5);
    free(good);
}

/* --------------------------------------------------------- ida e volta */

/* Confere que só os LSBs dos canais de cor mudaram (nada de alfa,
   preenchimento ou cabeçalho). */
static int only_lsbs_changed(const bmp_image *before, const bmp_image *after, int bits)
{
    uint8_t *mask = calloc(1, before->file_size);
    if (mask == NULL)
        return 0;
    for (size_t i = 0; i < bmp_channels(before); i++)
        mask[bmp_channel(before, i) - before->file] = 1;
    int ok = 1;
    for (size_t i = 0; i < before->file_size; i++) {
        uint8_t x = before->file[i] ^ after->file[i];
        if (x != 0 && (!mask[i] || x >= (1u << bits)))
            ok = 0;
    }
    free(mask);
    return ok;
}

static void test_roundtrip(void)
{
    SECTION("ida e volta: formatos x bits x modos");
    const struct {
        int bpp, top, header, rgba;
    } kinds[] = {{24, 0, 40, 0}, {24, 1, 40, 0}, {32, 0, 40, 0}, {32, 1, 124, 0}, {32, 0, 108, 1},
                 {32, 1, 124, 1}};
    const struct {
        const char *password;
        int encrypt;
    } modes[] = {{NULL, 1}, {"segredo", 1}, {"segredo", 0}};
    int ok = 1, runs = 0;

    for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
        for (int bits = 1; bits <= 2; bits++) {
            for (size_t m = 0; m < sizeof modes / sizeof modes[0]; m++) {
                synth_params p = params(37 + (int)k, 29, kinds[k].bpp, kinds[k].top,
                                        kinds[k].header, kinds[k].rgba, PATTERN_NOISE);
                bmp_image img, orig;
                if (!load_synth(&p, &img) || !load_synth(&p, &orig)) {
                    ok = 0;
                    continue;
                }
                est_options o = options(modes[m].password, modes[m].encrypt, bits);
                int with_pw = modes[m].password != NULL;
                const char *name = "relatório final.pdf";
                uint64_t cap = est_capacity(&img, bits, with_pw, with_pw && modes[m].encrypt,
                                            strlen(name));
                /* Tamanhos: vazio, pequeno, aleatório e exatamente a capacidade. */
                size_t sizes[4] = {0, 1, (size_t)(rng_next() % cap), (size_t)cap};
                for (int s = 0; s < 4; s++) {
                    bmp_image work;
                    if (!load_synth(&p, &work)) {
                        ok = 0;
                        continue;
                    }
                    size_t len = sizes[s];
                    uint8_t *data = malloc(len ? len : 1);
                    random_bytes(data, len);
                    est_info hi, ri;
                    uint8_t *back = NULL;
                    size_t back_len = 0;
                    runs++;
                    if (est_hide(&work, data, len, name, &o, &hi) != EST_OK ||
                        est_reveal(&work, modes[m].password, &back, &back_len, &ri) != EST_OK ||
                        back_len != len || (len && memcmp(back, data, len) != 0) ||
                        strcmp(ri.name, name) != 0 || ri.bits != bits ||
                        ri.encrypted != (with_pw && modes[m].encrypt) ||
                        ri.has_password != with_pw || !only_lsbs_changed(&orig, &work, bits)) {
                        ok = 0;
                        fprintf(stderr, "  falhou: formato %zu, %d bit(s), modo %zu, %zu bytes\n",
                                k, bits, m, len);
                    }
                    free(back);
                    free(data);
                    bmp_free(&work);
                }
                /* Um byte a mais que a capacidade não cabe. */
                uint8_t *big = calloc(1, (size_t)cap + 1);
                CHECK_EQ(est_hide(&img, big, (size_t)cap + 1, name, &o, NULL), EST_ERR_CAPACITY);
                free(big);
                bmp_free(&img);
                bmp_free(&orig);
            }
        }
    }
    CHECK(ok);
    CHECK_EQ(runs, 6 * 2 * 3 * 4);
}

static void test_capacity_math(void)
{
    SECTION("conta da capacidade");
    synth_params p = params(100, 100, 24, 0, 40, 0, PATTERN_NOISE);
    bmp_image img;
    CHECK(load_synth(&p, &img));
    /* 30000 canais; a área fixa usa 48 (6 bytes x 8) ou 208 (26 x 8) canais. */
    CHECK_EQ(est_capacity(&img, 1, 0, 0, 0), (30000 - 48) / 8 - 16);
    CHECK_EQ(est_capacity(&img, 2, 0, 0, 0), (30000 - 48) * 2 / 8 - 16);
    CHECK_EQ(est_capacity(&img, 1, 1, 1, 0), (30000 - 208) / 8 - 64);
    CHECK_EQ(est_capacity(&img, 1, 1, 0, 10), (30000 - 208) / 8 - 16 - 10);
    CHECK_EQ(est_capacity(&img, 3, 0, 0, 0), 0);
    bmp_free(&img);

    /* Imagem minúscula: nada cabe. */
    synth_params tiny = params(2, 2, 24, 0, 40, 0, PATTERN_NOISE);
    CHECK(load_synth(&tiny, &img));
    CHECK_EQ(est_capacity(&img, 2, 1, 1, 0), 0);
    uint8_t b = 1;
    est_options o = options(NULL, 1, 1);
    CHECK_EQ(est_hide(&img, &b, 1, "x", &o, NULL), EST_ERR_CAPACITY);
    uint8_t *data;
    size_t len;
    CHECK_EQ(est_reveal(&img, NULL, &data, &len, NULL), EST_ERR_NOT_FOUND);
    bmp_free(&img);
}

static void test_passwords_and_corruption(void)
{
    SECTION("senha errada (HMAC), imagem corrompida (CRC) e sem dados");
    synth_params p = params(120, 80, 32, 1, 124, 0, PATTERN_NOISE);
    bmp_image img;
    uint8_t secret[2000], *out = NULL;
    size_t out_len;
    est_info info;
    random_bytes(secret, sizeof secret);

    /* Imagem sem nada escondido. */
    CHECK(load_synth(&p, &img));
    CHECK_EQ(est_reveal(&img, NULL, &out, &out_len, NULL), EST_ERR_NOT_FOUND);
    bmp_free(&img);

    /* Cifrada: senha errada e falta de senha. */
    est_options o = options("cavalo correto bateria grampo", 1, 1);
    CHECK(load_synth(&p, &img));
    CHECK_EQ(est_hide(&img, secret, sizeof secret, "a.bin", &o, NULL), EST_OK);
    CHECK_EQ(est_reveal(&img, "cavalo correto bateria grampO", &out, &out_len, &info), EST_ERR_AUTH);
    CHECK_EQ(est_reveal(&img, NULL, &out, &out_len, &info), EST_ERR_NEEDS_PASSWORD);
    CHECK_EQ(info.iterations, 1000);
    CHECK_EQ(est_reveal(&img, "cavalo correto bateria grampo", &out, &out_len, &info), EST_OK);
    free(out);
    /* Um LSB trocado no meio dos dados (posição embaralhada): o HMAC pega. */
    int detected = 1;
    for (size_t ch = 300; ch < bmp_channels(&img); ch += 997) {
        *bmp_channel(&img, ch) ^= 1;
        est_status st = est_reveal(&img, "cavalo correto bateria grampo", &out, &out_len, NULL);
        if (st == EST_OK) {
            /* O canal pode estar fora da área usada: aí os dados continuam certos. */
            if (out_len != sizeof secret || memcmp(out, secret, sizeof secret) != 0)
                detected = 0;
            free(out);
        } else if (st != EST_ERR_AUTH) {
            detected = 0;
        }
        *bmp_channel(&img, ch) ^= 1;
    }
    CHECK(detected);
    bmp_free(&img);

    /* Senha sem cifra: sem HMAC, a senha errada vira cabeçalho inválido ou CRC. */
    o = options("outra senha", 0, 2);
    CHECK(load_synth(&p, &img));
    CHECK_EQ(est_hide(&img, secret, sizeof secret, "b.bin", &o, NULL), EST_OK);
    est_status st = est_reveal(&img, "senha errada", &out, &out_len, NULL);
    CHECK(st == EST_ERR_BAD_HEADER || st == EST_ERR_CRC);
    bmp_free(&img);

    /* Sem senha: um LSB trocado nos dados dá erro de CRC. */
    o = options(NULL, 1, 1);
    CHECK(load_synth(&p, &img));
    CHECK_EQ(est_hide(&img, secret, sizeof secret, "c.bin", &o, NULL), EST_OK);
    size_t data_channel = 48 + (16 + 5) * 8 + 4000;   /* dentro do conteúdo */
    *bmp_channel(&img, data_channel) ^= 1;
    CHECK_EQ(est_reveal(&img, NULL, &out, &out_len, NULL), EST_ERR_CRC);
    *bmp_channel(&img, data_channel) ^= 1;
    /* Assinatura estragada: não encontra nada. */
    *bmp_channel(&img, 3) ^= 1;
    CHECK_EQ(est_reveal(&img, NULL, &out, &out_len, NULL), EST_ERR_NOT_FOUND);
    *bmp_channel(&img, 3) ^= 1;
    /* Tamanho estragado (bit alto do campo tamanho): cabeçalho inválido. */
    *bmp_channel(&img, 48 + 7 * 8) ^= 1;
    CHECK_EQ(est_reveal(&img, NULL, &out, &out_len, NULL), EST_ERR_BAD_HEADER);
    *bmp_channel(&img, 48 + 7 * 8) ^= 1;
    CHECK_EQ(est_reveal(&img, NULL, &out, &out_len, &info), EST_OK);
    CHECK(strcmp(info.name, "c.bin") == 0);
    free(out);
    bmp_free(&img);
}

static void test_permutation(void)
{
    SECTION("posições: em ordem sem senha, espalhadas com senha");
    synth_params p = params(120, 100, 24, 0, 40, 0, PATTERN_LANDSCAPE);   /* LSBs todos zero */
    bmp_image a, b, c;
    uint8_t secret[400];
    memset(secret, 0xFF, sizeof secret);   /* todo bit 1 vira um LSB ligado */
    CHECK(load_synth(&p, &a));
    CHECK(load_synth(&p, &b));
    CHECK(load_synth(&p, &c));
    size_t n = bmp_channels(&a);

    est_options o = options(NULL, 1, 1);
    CHECK_EQ(est_hide(&a, secret, sizeof secret, "", &o, NULL), EST_OK);
    o = options("senha um", 0, 1);
    CHECK_EQ(est_hide(&b, secret, sizeof secret, "", &o, NULL), EST_OK);
    o = options("senha dois", 0, 1);
    CHECK_EQ(est_hide(&c, secret, sizeof secret, "", &o, NULL), EST_OK);

    /* Sem senha, nada muda na segunda metade; com senha, muda em toda parte. */
    size_t a_late = 0, b_late = 0, b_early = 0, differ = 0;
    for (size_t i = 0; i < n; i++) {
        int la = *bmp_channel(&a, i) & 1, lb = *bmp_channel(&b, i) & 1, lc = *bmp_channel(&c, i) & 1;
        if (i >= n / 2) {
            a_late += (size_t)la;
            b_late += (size_t)lb;
        } else {
            b_early += (size_t)lb;
        }
        differ += (size_t)(lb != lc);
    }
    CHECK_EQ(a_late, 0);
    CHECK(b_late > 1000 && b_early > 1000);
    CHECK(differ > 2000);   /* senhas diferentes, posições diferentes */
    bmp_free(&a);
    bmp_free(&b);
    bmp_free(&c);
}

/* ------------------------------------------------------- esteganálise */

static void test_chi_square(void)
{
    SECTION("ataque do qui-quadrado");
    /* A cauda do qui-quadrado confere com as fórmulas fechadas. */
    int ok = 1;
    const double xs[] = {0.1, 0.5, 1.0, 2.5, 7.0, 15.0, 40.0};
    for (size_t i = 0; i < sizeof xs / sizeof xs[0]; i++) {
        double x = xs[i];
        double two = exp(-x / 2);                        /* 2 graus de liberdade */
        double one = erfc(sqrt(x / 2));                  /* 1 grau */
        double y = x / 2, term = 1, sum = 0;             /* 10 graus: a = 5 inteiro */
        for (int k = 0; k < 5; k++) {
            sum += term;
            term *= y / (k + 1);
        }
        double ten = exp(-y) * sum;
        if (fabs(est_chi2_tail(x, 2) - two) > 1e-12 || fabs(est_chi2_tail(x, 1) - one) > 1e-12 ||
            fabs(est_chi2_tail(x, 10) - ten) > 1e-12)
            ok = 0;
    }
    CHECK(ok);
    CHECK(fabs(est_chi2_tail(0, 5) - 1.0) < 1e-15);
    CHECK(est_chi2_tail(1000, 5) < 1e-100);

    /* Paisagem com LSBs zerados: limpa, nada suspeito. */
    synth_params p = params(320, 240, 24, 0, 40, 0, PATTERN_LANDSCAPE);
    bmp_image img;
    CHECK(load_synth(&p, &img));
    size_t n = bmp_channels(&img);
    CHECK(est_chi_square(&img, 0, n) < 0.001);

    /* Metade da capacidade, sem senha: a primeira metade acende, a segunda não. */
    size_t len = (size_t)est_capacity(&img, 1, 0, 0, 0) / 2;
    uint8_t *secret = malloc(len);
    random_bytes(secret, len);
    est_options o = options(NULL, 1, 1);
    CHECK_EQ(est_hide(&img, secret, len, "", &o, NULL), EST_OK);
    double early = est_chi_square(&img, n / 10, n / 4);
    double late = est_chi_square(&img, n * 6 / 10, n / 4);
    CHECK(early > 0.9);
    CHECK(late < 0.01);
    free(secret);
    bmp_free(&img);
}

static void test_safe_name(void)
{
    SECTION("nome do arquivo revelado");
    char out[64];
    est_safe_name("../../.bashrc", out, sizeof out);
    CHECK(strcmp(out, ".bashrc") == 0);
    est_safe_name("/etc/passwd", out, sizeof out);
    CHECK(strcmp(out, "passwd") == 0);
    est_safe_name("pasta\\arquivo.txt", out, sizeof out);
    CHECK(strcmp(out, "arquivo.txt") == 0);
    est_safe_name("..", out, sizeof out);
    CHECK(strcmp(out, "arquivo_revelado") == 0);
    est_safe_name("x/", out, sizeof out);
    CHECK(strcmp(out, "arquivo_revelado") == 0);
    est_safe_name("a\nb\tc", out, sizeof out);
    CHECK(strcmp(out, "a_b_c") == 0);
    est_safe_name("relatório.pdf", out, sizeof out);
    CHECK(strcmp(out, "relatório.pdf") == 0);
    est_safe_name("muito_comprido.txt", out, 6);
    CHECK(strcmp(out, "muito") == 0);
}

static void test_strerror(void)
{
    SECTION("mensagens de erro");
    int ok = 1;
    for (int i = EST_OK; i <= EST_ERR_ARGUMENT; i++) {
        const char *m = est_strerror((est_status)i);
        if (m == NULL || m[0] == '\0')
            ok = 0;
        for (int j = EST_OK; j < i; j++)
            if (strcmp(m, est_strerror((est_status)j)) == 0)
                ok = 0;
    }
    CHECK(ok);
}

int main(void)
{
    test_sha256();
    test_hmac_kdf();
    test_chacha20();
    test_crc();
    test_bmp_formats();
    test_bmp_errors();
    test_roundtrip();
    test_capacity_math();
    test_passwords_and_corruption();
    test_permutation();
    test_chi_square();
    test_safe_name();
    test_strerror();
    return test_summary();
}
