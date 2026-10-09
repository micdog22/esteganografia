/*
 * esteg.c: esconder e revelar arquivos nos bits menos significativos (LSB).
 *
 * Formato (todos os números em little-endian):
 *
 *   Área fixa: sempre 1 bit por canal, nos primeiros canais da imagem
 *     "EST1"          4 bytes   assinatura
 *     versão          1 byte    (1)
 *     flags           1 byte    bit 0: senha, bit 1: cifrado, bit 2: 2 bits por canal
 *     iterações       4 bytes   PBKDF2 (só com senha)
 *     sal             16 bytes  (só com senha)
 *
 *   Área de dados: 1 ou 2 bits por canal, nos canais seguintes. Com senha,
 *   a ordem dos canais é uma permutação pseudoaleatória derivada da senha.
 *     tamanho         8 bytes   tamanho do arquivo
 *     tamanho do nome 1 byte
 *     reservado       3 bytes   (zeros)
 *     CRC-32          4 bytes   do arquivo original
 *     [etiqueta]      16 bytes  HMAC-SHA256 truncado (só cifrado)
 *     nome            n bytes
 *     conteúdo        tamanho bytes
 *     [etiqueta]      32 bytes  HMAC-SHA256 de tudo (só cifrado)
 *
 * Cifrado: os 16 bytes do cabeçalho e depois nome e conteúdo passam pelo
 * ChaCha20; as etiquetas autenticam o texto cifrado (encrypt-then-MAC). A
 * primeira etiqueta permite descobrir uma senha errada sem confiar em
 * nenhum tamanho decifrado.
 */
#include "cripto.h"
#include "esteg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC "EST1"
#define FORMAT_VERSION 1
#define FLAG_PASSWORD 0x01u
#define FLAG_ENCRYPTED 0x02u
#define FLAG_TWO_BITS 0x04u
#define FLAG_KNOWN (FLAG_PASSWORD | FLAG_ENCRYPTED | FLAG_TWO_BITS)

#define FIXED_PLAIN 6                         /* assinatura, versão e flags */
#define FIXED_PASSWORD (FIXED_PLAIN + 4 + ESTEG_SALT_SIZE)
#define RECORD_HEADER 16
#define HEADER_TAG 16
#define FULL_TAG 32
#define MAX_ITERATIONS 10000000u   /* teto: uma imagem maliciosa não pode travar a leitura */

est_status est_random_bytes(uint8_t *out, size_t n);   /* aleatorio.c */

const char *est_strerror(est_status st)
{
    switch (st) {
    case EST_OK: return "sucesso";
    case EST_ERR_MEMORY: return "memória insuficiente";
    case EST_ERR_IO: return "erro de leitura ou escrita de arquivo";
    case EST_ERR_NOT_BMP: return "não é um arquivo BMP";
    case EST_ERR_UNSUPPORTED:
        return "BMP não suportado: use 24 ou 32 bits por pixel, sem compressão";
    case EST_ERR_CORRUPT_BMP: return "BMP corrompido: os tamanhos do cabeçalho não batem com o arquivo";
    case EST_ERR_CAPACITY: return "o arquivo não cabe na imagem";
    case EST_ERR_NOT_FOUND: return "nenhum dado escondido encontrado (assinatura EST1 ausente)";
    case EST_ERR_NEEDS_PASSWORD: return "esta imagem foi protegida com senha: use --senha";
    case EST_ERR_AUTH:
        return "senha incorreta ou imagem adulterada: a verificação HMAC-SHA256 falhou";
    case EST_ERR_CRC: return "dados corrompidos: o CRC-32 do arquivo escondido não confere";
    case EST_ERR_BAD_HEADER:
        return "cabeçalho escondido inválido (imagem alterada ou senha errada?)";
    case EST_ERR_RANDOM: return "não foi possível ler bytes aleatórios de /dev/urandom";
    case EST_ERR_ARGUMENT: return "parâmetro inválido";
    }
    return "erro desconhecido";
}

est_options est_default_options(void)
{
    est_options o = {NULL, 1, 1, 0, NULL};
    return o;
}

void est_safe_name(const char *stored, char *out, size_t cap)
{
    const char *b = stored;
    size_t n = 0;
    if (cap == 0)
        return;
    for (const char *p = stored; *p; p++)
        if (*p == '/' || *p == '\\')
            b = p + 1;
    for (; *b && n + 1 < cap; b++) {
        unsigned char c = (unsigned char)*b;
        out[n++] = (c < 0x20 || c == 0x7F) ? '_' : (char)c;
    }
    out[n] = '\0';
    if (n == 0 || strcmp(out, ".") == 0 || strcmp(out, "..") == 0)
        snprintf(out, cap, "arquivo_revelado");
}

/* --------------------------------------------------------------- CRC-32 */

uint32_t est_crc32(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = data;
    crc = ~crc;
    while (len--) {
        crc ^= *p++;
        for (int k = 0; k < 8; k++)
            crc = (crc & 1u) ? 0xEDB88320u ^ (crc >> 1) : crc >> 1;
    }
    return ~crc;
}

static void put_le32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* ------------------------------------------------- posições dos dados */

/*
 * Gera as posições dos canais da área de dados. Sem senha, em ordem. Com
 * senha, é um Fisher-Yates "preguiçoso": o vetor [0, n) nunca existe de
 * verdade; um mapa guarda só as posições já trocadas. Assim uma foto de
 * 12 megapixels não precisa de um vetor de 36 milhões de índices.
 */
typedef struct {
    size_t base;          /* primeiro canal da área de dados */
    size_t n;             /* canais na área de dados */
    size_t next;          /* quantas posições já saíram */
    int shuffled;
    chacha20_ctx rng;     /* gerador pseudoaleatório (chave das posições) */
    size_t *keys;         /* mapa aberto: índice -> valor trocado */
    size_t *values;
    size_t cap, count;
} position_gen;

#define EMPTY_KEY ((size_t)-1)

static void posgen_init(position_gen *g, size_t base, size_t n, const uint8_t *perm_key)
{
    memset(g, 0, sizeof *g);
    g->base = base;
    g->n = n;
    if (perm_key != NULL) {
        static const uint8_t zero_nonce[12] = {0};
        g->shuffled = 1;
        chacha20_init(&g->rng, perm_key, zero_nonce, 0);
    }
}

static void posgen_free(position_gen *g)
{
    free(g->keys);
    free(g->values);
    secure_zero(&g->rng, sizeof g->rng);
}

static size_t hash_index(size_t key, size_t cap)
{
    uint64_t h = (uint64_t)key * UINT64_C(0x9E3779B97F4A7C15);
    return (size_t)(h >> 17) & (cap - 1);
}

static est_status map_grow(position_gen *g)
{
    size_t cap = g->cap ? g->cap * 2 : 1024;
    size_t *keys = malloc(cap * sizeof *keys), *values = malloc(cap * sizeof *values);
    if (keys == NULL || values == NULL) {
        free(keys);
        free(values);
        return EST_ERR_MEMORY;
    }
    for (size_t i = 0; i < cap; i++)
        keys[i] = EMPTY_KEY;
    for (size_t i = 0; i < g->cap; i++) {
        if (g->keys[i] == EMPTY_KEY)
            continue;
        size_t h = hash_index(g->keys[i], cap);
        while (keys[h] != EMPTY_KEY)
            h = (h + 1) & (cap - 1);
        keys[h] = g->keys[i];
        values[h] = g->values[i];
    }
    free(g->keys);
    free(g->values);
    g->keys = keys;
    g->values = values;
    g->cap = cap;
    return EST_OK;
}

/* Valor atual da posição key no vetor virtual (sem troca: a própria key). */
static size_t map_get(const position_gen *g, size_t key)
{
    if (g->cap == 0)
        return key;
    size_t h = hash_index(key, g->cap);
    while (g->keys[h] != EMPTY_KEY) {
        if (g->keys[h] == key)
            return g->values[h];
        h = (h + 1) & (g->cap - 1);
    }
    return key;
}

static est_status map_set(position_gen *g, size_t key, size_t value)
{
    if ((g->count + 1) * 2 > g->cap) {
        est_status st = map_grow(g);
        if (st != EST_OK)
            return st;
    }
    size_t h = hash_index(key, g->cap);
    while (g->keys[h] != EMPTY_KEY && g->keys[h] != key)
        h = (h + 1) & (g->cap - 1);
    if (g->keys[h] == EMPTY_KEY) {
        g->keys[h] = key;
        g->count++;
    }
    g->values[h] = value;
    return EST_OK;
}

/* Inteiro uniforme em [0, range), sem o viés do resto da divisão. */
static uint64_t uniform(chacha20_ctx *rng, uint64_t range)
{
    uint64_t threshold = (0 - range) % range;   /* 2^64 mod range */
    for (;;) {
        uint64_t r = chacha20_u64(rng);
        if (r >= threshold)
            return r % range;
    }
}

static est_status posgen_next(position_gen *g, size_t *channel)
{
    if (g->next >= g->n)
        return EST_ERR_CAPACITY;   /* não deveria acontecer: a capacidade é conferida antes */
    size_t i = g->next++;
    if (!g->shuffled) {
        *channel = g->base + i;
        return EST_OK;
    }
    /* Passo i do Fisher-Yates: sorteia j em [i, n), entrega a[j] e põe a[i] no lugar. */
    size_t j = i + (size_t)uniform(&g->rng, (uint64_t)(g->n - i));
    size_t ai = map_get(g, i), aj = map_get(g, j);
    *channel = g->base + aj;
    return map_set(g, j, ai);
}

/* ------------------------------------------------- bits nos canais */

typedef struct {
    const bmp_image *img;
    position_gen *gen;
    int bits;
} carrier;

/* Escreve os bytes nos LSBs, bit mais significativo primeiro. */
static est_status carrier_write(carrier *c, const uint8_t *data, size_t n)
{
    uint8_t mask = (uint8_t)((1u << c->bits) - 1u);
    for (size_t i = 0; i < n; i++) {
        for (int shift = 8 - c->bits; shift >= 0; shift -= c->bits) {
            size_t ch;
            est_status st = posgen_next(c->gen, &ch);
            if (st != EST_OK)
                return st;
            uint8_t *p = bmp_channel(c->img, ch);
            *p = (uint8_t)((*p & ~mask) | ((data[i] >> shift) & mask));
        }
    }
    return EST_OK;
}

static est_status carrier_read(carrier *c, uint8_t *data, size_t n)
{
    uint8_t mask = (uint8_t)((1u << c->bits) - 1u);
    for (size_t i = 0; i < n; i++) {
        uint8_t v = 0;
        for (int shift = 8 - c->bits; shift >= 0; shift -= c->bits) {
            size_t ch;
            est_status st = posgen_next(c->gen, &ch);
            if (st != EST_OK)
                return st;
            v = (uint8_t)(v | ((*bmp_channel(c->img, ch) & mask) << shift));
        }
        data[i] = v;
    }
    return EST_OK;
}

/* --------------------------------------------------------- capacidade */

static size_t fixed_size(int with_password)
{
    return with_password ? FIXED_PASSWORD : FIXED_PLAIN;
}

static uint64_t record_overhead(int encrypted)
{
    return RECORD_HEADER + (encrypted ? HEADER_TAG + FULL_TAG : 0);
}

/* Bytes que cabem na área de dados. */
static uint64_t data_area_bytes(const bmp_image *img, int bits, int with_password)
{
    size_t channels = bmp_channels(img), fixed = fixed_size(with_password) * 8;
    if (channels <= fixed)
        return 0;
    return (uint64_t)(channels - fixed) * (uint64_t)bits / 8u;
}

uint64_t est_capacity(const bmp_image *img, int bits, int with_password, int encrypt,
                      size_t name_len)
{
    if (bits != 1 && bits != 2)
        return 0;
    uint64_t room = data_area_bytes(img, bits, with_password);
    uint64_t need = record_overhead(with_password && encrypt) + name_len;
    return room > need ? room - need : 0;
}

/* --------------------------------------------------------------- chaves */

typedef struct {
    uint8_t perm[32];     /* ordem dos canais */
    uint8_t enc[32];      /* ChaCha20 */
    uint8_t mac[32];      /* HMAC-SHA256 */
} key_set;

/* Senha -> PBKDF2 -> chave mestra -> HKDF-Expand -> três chaves independentes. */
static void derive_keys(const char *password, const uint8_t *salt, uint32_t iterations,
                        key_set *k)
{
    uint8_t master[32];
    pbkdf2_hmac_sha256((const uint8_t *)password, strlen(password), salt, ESTEG_SALT_SIZE,
                       iterations, master, sizeof master);
    hkdf_expand32(master, "esteg: posicoes", k->perm);
    hkdf_expand32(master, "esteg: cifra", k->enc);
    hkdf_expand32(master, "esteg: mac", k->mac);
    secure_zero(master, sizeof master);
}

static const uint8_t ZERO_NONCE[12] = {0};

/* --------------------------------------------------------------- esconder */

est_status est_hide(bmp_image *img, const uint8_t *data, size_t len, const char *name,
                    const est_options *opt, est_info *info)
{
    est_options def = est_default_options();
    if (opt == NULL)
        opt = &def;
    if (name == NULL)
        name = "";
    size_t name_len = strlen(name);
    int with_password = opt->password != NULL && opt->password[0] != '\0';
    int encrypted = with_password && opt->encrypt;
    uint32_t iterations = opt->iterations ? opt->iterations : ESTEG_DEFAULT_ITERATIONS;
    if ((opt->bits != 1 && opt->bits != 2) || name_len > ESTEG_MAX_NAME ||
        iterations > MAX_ITERATIONS || (data == NULL && len > 0))
        return EST_ERR_ARGUMENT;
    if ((uint64_t)len > est_capacity(img, opt->bits, with_password, encrypted, name_len))
        return EST_ERR_CAPACITY;

    /* Área fixa. */
    uint8_t fixed[FIXED_PASSWORD];
    memcpy(fixed, MAGIC, 4);
    fixed[4] = FORMAT_VERSION;
    fixed[5] = (uint8_t)((with_password ? FLAG_PASSWORD : 0u) | (encrypted ? FLAG_ENCRYPTED : 0u) |
                         (opt->bits == 2 ? FLAG_TWO_BITS : 0u));
    key_set keys;
    if (with_password) {
        put_le32(fixed + 6, iterations);
        if (opt->salt != NULL)
            memcpy(fixed + 10, opt->salt, ESTEG_SALT_SIZE);
        else if (est_random_bytes(fixed + 10, ESTEG_SALT_SIZE) != EST_OK)
            return EST_ERR_RANDOM;
        derive_keys(opt->password, fixed + 10, iterations, &keys);
    }
    size_t fixed_len = fixed_size(with_password);

    /* Registro: cabeçalho, nome e conteúdo (e as etiquetas, se cifrado). */
    uint64_t total = record_overhead(encrypted) + name_len + len;
    uint8_t *rec = malloc((size_t)total);
    if (rec == NULL)
        return EST_ERR_MEMORY;
    uint32_t crc = est_crc32(0, data, len);
    memset(rec, 0, RECORD_HEADER);
    put_le64(rec, (uint64_t)len);
    rec[8] = (uint8_t)name_len;
    put_le32(rec + 12, crc);
    size_t body = RECORD_HEADER + (encrypted ? HEADER_TAG : 0);
    memcpy(rec + body, name, name_len);
    if (len > 0)
        memcpy(rec + body + name_len, data, len);

    if (encrypted) {
        chacha20_ctx cc;
        hmac_sha256_ctx mac;
        uint8_t tag[32];
        chacha20_init(&cc, keys.enc, ZERO_NONCE, 1);
        chacha20_xor(&cc, rec, RECORD_HEADER);                    /* cabeçalho */
        chacha20_xor(&cc, rec + body, name_len + len);            /* nome e conteúdo */
        hmac_sha256_init(&mac, keys.mac, sizeof keys.mac);        /* etiqueta curta */
        hmac_sha256_update(&mac, fixed, fixed_len);
        hmac_sha256_update(&mac, rec, RECORD_HEADER);
        hmac_sha256_final(&mac, tag);
        memcpy(rec + RECORD_HEADER, tag, HEADER_TAG);
        hmac_sha256_init(&mac, keys.mac, sizeof keys.mac);        /* etiqueta completa */
        hmac_sha256_update(&mac, fixed, fixed_len);
        hmac_sha256_update(&mac, rec, (size_t)total - FULL_TAG);
        hmac_sha256_final(&mac, rec + total - FULL_TAG);
        secure_zero(&cc, sizeof cc);
    }

    /* Grava: área fixa (1 bit, em ordem) e área de dados. */
    position_gen fixed_gen, data_gen;
    posgen_init(&fixed_gen, 0, fixed_len * 8, NULL);
    posgen_init(&data_gen, fixed_len * 8, bmp_channels(img) - fixed_len * 8,
                with_password ? keys.perm : NULL);
    carrier cf = {img, &fixed_gen, 1}, cd = {img, &data_gen, opt->bits};
    est_status st = carrier_write(&cf, fixed, fixed_len);
    if (st == EST_OK)
        st = carrier_write(&cd, rec, (size_t)total);

    if (st == EST_OK && info != NULL) {
        memset(info, 0, sizeof *info);
        info->bits = opt->bits;
        info->has_password = with_password;
        info->encrypted = encrypted;
        info->iterations = with_password ? iterations : 0;
        info->size = len;
        info->crc32 = crc;
        memcpy(info->name, name, name_len + 1);
        info->channels_used = fixed_len * 8 + data_gen.next;
    }
    posgen_free(&fixed_gen);
    posgen_free(&data_gen);
    secure_zero(rec, (size_t)total);
    free(rec);
    if (with_password)
        secure_zero(&keys, sizeof keys);
    return st;
}

/* ---------------------------------------------------------------- revelar */

est_status est_reveal(const bmp_image *img, const char *password, uint8_t **data, size_t *len,
                      est_info *info)
{
    uint8_t fixed[FIXED_PASSWORD];
    est_info local;
    est_status st;

    *data = NULL;
    *len = 0;
    if (info == NULL)
        info = &local;
    memset(info, 0, sizeof *info);
    if (bmp_channels(img) < FIXED_PLAIN * 8)
        return EST_ERR_NOT_FOUND;

    /* Área fixa: assinatura, versão e flags. */
    position_gen fixed_gen;
    posgen_init(&fixed_gen, 0, FIXED_PASSWORD * 8, NULL);
    carrier cf = {img, &fixed_gen, 1};
    if ((st = carrier_read(&cf, fixed, FIXED_PLAIN)) != EST_OK)
        return st;
    if (memcmp(fixed, MAGIC, 4) != 0)
        return EST_ERR_NOT_FOUND;
    uint8_t flags = fixed[5];
    if (fixed[4] != FORMAT_VERSION || (flags & ~FLAG_KNOWN) != 0 ||
        ((flags & FLAG_ENCRYPTED) && !(flags & FLAG_PASSWORD)))
        return EST_ERR_BAD_HEADER;
    int with_password = (flags & FLAG_PASSWORD) != 0;
    int encrypted = (flags & FLAG_ENCRYPTED) != 0;
    int bits = (flags & FLAG_TWO_BITS) ? 2 : 1;
    size_t fixed_len = fixed_size(with_password);
    if (bmp_channels(img) < fixed_len * 8)
        return EST_ERR_BAD_HEADER;
    info->bits = bits;
    info->has_password = with_password;
    info->encrypted = encrypted;

    key_set keys;
    if (with_password) {
        if ((st = carrier_read(&cf, fixed + FIXED_PLAIN, fixed_len - FIXED_PLAIN)) != EST_OK)
            return st;
        uint32_t iterations = get_le32(fixed + 6);
        info->iterations = iterations;
        if (iterations == 0 || iterations > MAX_ITERATIONS)
            return EST_ERR_BAD_HEADER;
        if (password == NULL || password[0] == '\0')
            return EST_ERR_NEEDS_PASSWORD;
        derive_keys(password, fixed + 10, iterations, &keys);
    }
    posgen_free(&fixed_gen);

    position_gen gen;
    posgen_init(&gen, fixed_len * 8, bmp_channels(img) - fixed_len * 8,
                with_password ? keys.perm : NULL);
    carrier cd = {img, &gen, bits};
    uint64_t room = data_area_bytes(img, bits, with_password);
    uint8_t head[RECORD_HEADER + HEADER_TAG];
    uint8_t *rec = NULL;
    uint64_t total = 0;
    chacha20_ctx cc;
    hmac_sha256_ctx mac;
    uint8_t tag[32];

    size_t head_len = RECORD_HEADER + (encrypted ? HEADER_TAG : 0);
    st = room < record_overhead(encrypted) ? EST_ERR_BAD_HEADER : carrier_read(&cd, head, head_len);
    if (st == EST_OK && encrypted) {
        /* A etiqueta curta cobre a área fixa e o cabeçalho cifrado: com a
           senha errada, ela falha aqui, antes de usar qualquer tamanho. */
        hmac_sha256_init(&mac, keys.mac, sizeof keys.mac);
        hmac_sha256_update(&mac, fixed, fixed_len);
        hmac_sha256_update(&mac, head, RECORD_HEADER);
        hmac_sha256_final(&mac, tag);
        if (!ct_equal(tag, head + RECORD_HEADER, HEADER_TAG))
            st = EST_ERR_AUTH;
        else {
            chacha20_init(&cc, keys.enc, ZERO_NONCE, 1);
            chacha20_xor(&cc, head, RECORD_HEADER);   /* só o cabeçalho, por enquanto */
        }
    }
    uint64_t size = 0;
    size_t name_len = 0;
    if (st == EST_OK) {
        size = get_le64(head);
        name_len = head[8];
        uint64_t space = room - record_overhead(encrypted);
        if (head[9] != 0 || head[10] != 0 || head[11] != 0 || name_len > space ||
            size > space - name_len || size > SIZE_MAX / 2)
            st = EST_ERR_BAD_HEADER;
    }
    if (st == EST_OK) {
        total = record_overhead(encrypted) + name_len + size;
        rec = malloc((size_t)total);
        if (rec == NULL)
            st = EST_ERR_MEMORY;
    }
    if (st == EST_OK) {
        memcpy(rec, head, head_len);
        st = carrier_read(&cd, rec + head_len, (size_t)(total - head_len));
    }
    if (st == EST_OK && encrypted) {
        /* Cabeçalho cifrado de volta para conferir a etiqueta completa. */
        uint8_t cipher_head[RECORD_HEADER];
        chacha20_ctx again;
        chacha20_init(&again, keys.enc, ZERO_NONCE, 1);
        memcpy(cipher_head, rec, RECORD_HEADER);
        chacha20_xor(&again, cipher_head, RECORD_HEADER);
        hmac_sha256_init(&mac, keys.mac, sizeof keys.mac);
        hmac_sha256_update(&mac, fixed, fixed_len);
        hmac_sha256_update(&mac, cipher_head, RECORD_HEADER);
        hmac_sha256_update(&mac, rec + RECORD_HEADER, (size_t)total - FULL_TAG - RECORD_HEADER);
        hmac_sha256_final(&mac, tag);
        if (!ct_equal(tag, rec + total - FULL_TAG, FULL_TAG))
            st = EST_ERR_AUTH;
        else
            chacha20_xor(&cc, rec + head_len, name_len + (size_t)size);
        secure_zero(&again, sizeof again);
    }
    if (st == EST_OK) {
        const uint8_t *name = rec + head_len;
        const uint8_t *content = name + name_len;
        if (memchr(name, 0, name_len) != NULL) {
            st = EST_ERR_BAD_HEADER;
        } else if (est_crc32(0, content, (size_t)size) != get_le32(rec + 12)) {
            st = EST_ERR_CRC;
        } else {
            info->size = size;
            info->crc32 = get_le32(rec + 12);
            memcpy(info->name, name, name_len);
            info->name[name_len] = '\0';
            info->channels_used = fixed_len * 8 + gen.next;
            *data = malloc(size ? (size_t)size : 1);
            if (*data == NULL)
                st = EST_ERR_MEMORY;
            else {
                if (size > 0)
                    memcpy(*data, content, (size_t)size);
                *len = (size_t)size;
            }
        }
    }
    posgen_free(&gen);
    if (rec != NULL) {
        secure_zero(rec, (size_t)total);
        free(rec);
    }
    if (with_password)
        secure_zero(&keys, sizeof keys);
    secure_zero(&cc, sizeof cc);
    return st;
}
