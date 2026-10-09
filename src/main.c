/* main.c: esteg, a interface de linha de comando. */
#include "esteg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *PROGRAM = "esteg";

enum { EXIT_OK = 0, EXIT_ERROR = 1, EXIT_USAGE = 2 };

static void usage(FILE *f)
{
    fprintf(f,
            "uso:\n"
            "  esteg esconder <imagem.bmp> <arquivo> <saida.bmp> [opções]\n"
            "  esteg revelar <imagem.bmp> [-o arquivo] [opções]\n"
            "  esteg capacidade <imagem.bmp>\n"
            "  esteg analisar <imagem.bmp>\n"
            "\n"
            "Esconde um arquivo nos bits menos significativos das cores de um BMP\n"
            "de 24 ou 32 bits (o canal alfa nunca é tocado).\n"
            "\n"
            "opções:\n"
            "  --senha SENHA      embaralha as posições e cifra o conteúdo (ChaCha20 e\n"
            "                     HMAC-SHA256, chaves derivadas com PBKDF2)\n"
            "  --senha-stdin      lê a senha da primeira linha da entrada padrão\n"
            "  --bits 1|2         bits usados em cada canal de cor (padrão: 1)\n"
            "  --sem-cifra        com senha, só embaralha as posições, sem cifrar\n"
            "  --iteracoes N      iterações do PBKDF2 (padrão: %u)\n"
            "  -o ARQUIVO         onde gravar o arquivo revelado (padrão: o nome original)\n"
            "  -f, --forcar       sobrescreve a saída se ela já existir\n"
            "  -h, --help         mostra esta ajuda\n"
            "  -V, --version      mostra a versão\n"
            "\n"
            "Projeto educacional: a criptografia foi escrita do zero e não foi auditada.\n",
            ESTEG_DEFAULT_ITERATIONS);
}

static void fail(const char *what, const char *msg)
{
    if (what != NULL)
        fprintf(stderr, "%s: %s: %s\n", PROGRAM, what, msg);
    else
        fprintf(stderr, "%s: %s\n", PROGRAM, msg);
}

/* 1234567 -> "1.234.567" */
static const char *grouped(uint64_t v, char *buf, size_t cap)
{
    char digits[32];
    int n = snprintf(digits, sizeof digits, "%llu", (unsigned long long)v);
    size_t out = 0;
    for (int i = 0; i < n && out + 2 < cap; i++) {
        if (i > 0 && (n - i) % 3 == 0)
            buf[out++] = '.';
        buf[out++] = digits[i];
    }
    buf[out] = '\0';
    return buf;
}

/* Porcentagem com uma casa decimal e vírgula. */
static const char *percent(uint64_t part, uint64_t whole, char *buf, size_t cap)
{
    uint64_t tenths = whole ? (part * 1000 + whole / 2) / whole : 0;
    snprintf(buf, cap, "%llu,%llu%%", (unsigned long long)(tenths / 10),
             (unsigned long long)(tenths % 10));
    return buf;
}

/* Probabilidade com três casas e vírgula: 0,973. */
static const char *probability(double p, char *buf, size_t cap)
{
    long t = (long)(p * 1000.0 + 0.5);
    if (t < 0)
        t = 0;
    if (t > 1000)
        t = 1000;
    snprintf(buf, cap, "%ld,%03ld", t / 1000, t % 1000);
    return buf;
}

static int file_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f != NULL)
        fclose(f);
    return f != NULL;
}

static int read_file(const char *path, uint8_t **data, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return 0;
    size_t cap = 1 << 16, n = 0;
    uint8_t *buf = malloc(cap);
    int ok = buf != NULL;
    while (ok) {
        if (n == cap) {
            uint8_t *p = cap < ((size_t)1 << 30) ? realloc(buf, cap * 2) : NULL;
            if (p == NULL) {
                ok = 0;
                break;
            }
            buf = p;
            cap *= 2;
        }
        size_t got = fread(buf + n, 1, cap - n, f);
        n += got;
        if (got == 0) {
            ok = !ferror(f);
            break;
        }
    }
    fclose(f);
    if (!ok) {
        free(buf);
        return 0;
    }
    *data = buf;
    *len = n;
    return 1;
}

static int write_file(const char *path, const uint8_t *data, size_t len, int force)
{
    FILE *f = fopen(path, force ? "wb" : "wbx");
    if (f == NULL)
        return 0;
    size_t n = len ? fwrite(data, 1, len, f) : 0;
    int closed = fclose(f);
    return n == len && closed == 0;
}

static const char *base_name(const char *path)
{
    const char *p = path, *last = path;
    for (; *p; p++)
        if (*p == '/' || *p == '\\')
            last = p + 1;
    return last;
}

static char *read_password_line(void)
{
    char buf[1024];
    if (fgets(buf, sizeof buf, stdin) == NULL)
        return NULL;
    size_t n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    char *p = malloc(n + 1);
    if (p != NULL)
        memcpy(p, buf, n + 1);
    return p;
}

typedef struct {
    const char *positional[3];
    int npositional;
    const char *password;
    char *password_owned;
    int bits;
    int encrypt;
    uint32_t iterations;
    const char *output;
    int force;
} args;

/* Lê as opções comuns. Devolve 0 se ok. */
static int parse_args(int argc, char **argv, args *a)
{
    memset(a, 0, sizeof *a);
    a->bits = 1;
    a->encrypt = 1;
    for (int i = 2; i < argc; i++) {
        const char *s = argv[i];
        const char *next = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(s, "--senha") == 0) {
            if (next == NULL)
                return fail(NULL, "--senha precisa de um valor"), 1;
            a->password = argv[++i];
        } else if (strcmp(s, "--senha-stdin") == 0) {
            a->password_owned = read_password_line();
            if (a->password_owned == NULL)
                return fail(NULL, "não foi possível ler a senha da entrada padrão"), 1;
            a->password = a->password_owned;
        } else if (strcmp(s, "--bits") == 0) {
            if (next == NULL || (strcmp(next, "1") != 0 && strcmp(next, "2") != 0))
                return fail(NULL, "--bits aceita 1 ou 2"), 1;
            a->bits = next[0] - '0';
            i++;
        } else if (strcmp(s, "--sem-cifra") == 0) {
            a->encrypt = 0;
        } else if (strcmp(s, "--iteracoes") == 0) {
            char *end = NULL;
            unsigned long v = next ? strtoul(next, &end, 10) : 0;
            if (next == NULL || *end != '\0' || v < 1000 || v > 10000000ul)
                return fail(NULL, "--iteracoes aceita de 1000 a 10000000"), 1;
            a->iterations = (uint32_t)v;
            i++;
        } else if (strcmp(s, "-o") == 0) {
            if (next == NULL)
                return fail(NULL, "-o precisa de um nome de arquivo"), 1;
            a->output = argv[++i];
        } else if (strcmp(s, "-f") == 0 || strcmp(s, "--forcar") == 0) {
            a->force = 1;
        } else if (s[0] == '-' && s[1] != '\0') {
            fprintf(stderr, "%s: opção inválida: %s\n", PROGRAM, s);
            return 1;
        } else if (a->npositional < 3) {
            a->positional[a->npositional++] = s;
        } else {
            return fail(NULL, "argumentos demais"), 1;
        }
    }
    return 0;
}

static int load_image(const char *path, bmp_image *img)
{
    est_status st = bmp_load(img, path);
    if (st != EST_OK) {
        fail(path, st == EST_ERR_IO ? "não foi possível ler a imagem" : est_strerror(st));
        return 0;
    }
    return 1;
}

static int cmd_hide(const args *a)
{
    if (a->npositional != 3) {
        fail(NULL, "uso: esteg esconder <imagem.bmp> <arquivo> <saida.bmp> [opções]");
        return EXIT_USAGE;
    }
    const char *image_path = a->positional[0], *secret_path = a->positional[1],
               *out_path = a->positional[2];
    if (strcmp(image_path, out_path) == 0) {
        fail(out_path, "a saída precisa ser diferente da imagem original");
        return EXIT_USAGE;
    }
    if (!a->force && file_exists(out_path)) {
        fail(out_path, "já existe; use -f para sobrescrever");
        return EXIT_ERROR;
    }
    bmp_image img;
    if (!load_image(image_path, &img))
        return EXIT_ERROR;
    uint8_t *secret = NULL;
    size_t secret_len = 0;
    if (!read_file(secret_path, &secret, &secret_len)) {
        fail(secret_path, "não foi possível ler o arquivo");
        bmp_free(&img);
        return EXIT_ERROR;
    }

    /* Só o nome do arquivo, cortado em 255 bytes sem partir um caractere UTF-8. */
    char name[ESTEG_MAX_NAME + 1];
    const char *b = base_name(secret_path);
    size_t nl = strlen(b);
    if (nl > ESTEG_MAX_NAME) {
        nl = ESTEG_MAX_NAME;
        while (nl > 0 && ((unsigned char)b[nl] & 0xC0u) == 0x80u)
            nl--;
    }
    memcpy(name, b, nl);
    name[nl] = '\0';

    est_options opt = est_default_options();
    opt.password = a->password;
    opt.encrypt = a->encrypt;
    opt.bits = a->bits;
    opt.iterations = a->iterations;
    int with_password = a->password != NULL && a->password[0] != '\0';
    int encrypted = with_password && a->encrypt;

    est_info info;
    est_status st = est_hide(&img, secret, secret_len, name, &opt, &info);
    int rc = EXIT_OK;
    char s1[32], s2[32], s3[32];
    if (st == EST_ERR_CAPACITY) {
        uint64_t cap = est_capacity(&img, a->bits, with_password, encrypted, nl);
        fprintf(stderr, "%s: %s não cabe em %s: tem %s bytes e cabem %s com %d bit%s por canal",
                PROGRAM, secret_path, image_path, grouped(secret_len, s1, sizeof s1),
                grouped(cap, s2, sizeof s2), a->bits, a->bits == 1 ? "" : "s");
        if (a->bits == 1)
            fprintf(stderr, " (com --bits 2 cabem %s)",
                    grouped(est_capacity(&img, 2, with_password, encrypted, nl), s3, sizeof s3));
        fprintf(stderr, "\n");
        rc = EXIT_ERROR;
    } else if (st != EST_OK) {
        fail(image_path, est_strerror(st));
        rc = EXIT_ERROR;
    } else if (bmp_save(&img, out_path) != EST_OK) {
        fail(out_path, "não foi possível gravar a imagem");
        rc = EXIT_ERROR;
    } else {
        uint64_t cap = est_capacity(&img, a->bits, with_password, encrypted, nl);
        printf("Escondi %s (%s bytes) em %s, usando %s da capacidade com %d bit%s por canal.\n",
               name, grouped(secret_len, s1, sizeof s1), out_path,
               percent(secret_len, cap, s2, sizeof s2), a->bits, a->bits == 1 ? "" : "s");
        if (!with_password)
            printf("Sem senha: os dados ficam em ordem e qualquer um com o esteg consegue lê-los.\n");
        else if (encrypted)
            printf("Com senha: posições embaralhadas, conteúdo cifrado com ChaCha20 e autenticado com "
                   "HMAC-SHA256 (PBKDF2 com %s iterações).\n",
                   grouped(info.iterations, s3, sizeof s3));
        else
            printf("Com senha, sem cifra: as posições estão embaralhadas, mas o conteúdo não foi "
                   "cifrado.\n");
    }
    free(secret);
    bmp_free(&img);
    return rc;
}

static int cmd_reveal(const args *a)
{
    if (a->npositional != 1) {
        fail(NULL, "uso: esteg revelar <imagem.bmp> [-o arquivo] [opções]");
        return EXIT_USAGE;
    }
    bmp_image img;
    if (!load_image(a->positional[0], &img))
        return EXIT_ERROR;
    uint8_t *data = NULL;
    size_t len = 0;
    est_info info;
    est_status st = est_reveal(&img, a->password, &data, &len, &info);
    bmp_free(&img);
    if (st != EST_OK) {
        fail(a->positional[0], est_strerror(st));
        return EXIT_ERROR;
    }
    char name[ESTEG_MAX_NAME + 1];
    est_safe_name(info.name, name, sizeof name);
    const char *out = a->output ? a->output : name;
    int rc = EXIT_OK;
    char s1[32];
    if (!a->force && file_exists(out)) {
        fail(out, "já existe; use -f para sobrescrever ou -o para escolher outro nome");
        rc = EXIT_ERROR;
    } else if (!write_file(out, data, len, a->force)) {
        fail(out, "não foi possível gravar o arquivo");
        rc = EXIT_ERROR;
    } else {
        printf("Revelei %s (%s bytes, CRC-32 %08lx conferido) em %s.\n", info.name,
               grouped(len, s1, sizeof s1), (unsigned long)info.crc32, out);
        printf("%d bit%s por canal, %s.\n", info.bits, info.bits == 1 ? "" : "s",
               info.encrypted ? "cifrado e autenticado (HMAC-SHA256 conferido)"
               : info.has_password ? "com senha, sem cifra" : "sem senha");
    }
    free(data);
    return rc;
}

static int cmd_capacity(const args *a)
{
    if (a->npositional != 1) {
        fail(NULL, "uso: esteg capacidade <imagem.bmp>");
        return EXIT_USAGE;
    }
    bmp_image img;
    if (!load_image(a->positional[0], &img))
        return EXIT_ERROR;
    char s1[32], s2[32];
    printf("%s: %d x %d pixels, %d bits por pixel, linhas %s\n", a->positional[0], (int)img.width,
           (int)img.height, img.bits_per_pixel,
           img.top_down ? "de cima para baixo" : "de baixo para cima");
    printf("canais de cor: %s (3 por pixel; o alfa nunca é usado)\n\n",
           grouped(bmp_channels(&img), s1, sizeof s1));
    printf("%-26s %18s %18s\n", "", "1 bit por canal", "2 bits por canal");
    printf("%-26s %12s bytes %12s bytes\n", "sem senha", grouped(est_capacity(&img, 1, 0, 0, 0), s1, sizeof s1),
           grouped(est_capacity(&img, 2, 0, 0, 0), s2, sizeof s2));
    printf("%-26s %12s bytes %12s bytes\n", "com senha e cifra", grouped(est_capacity(&img, 1, 1, 1, 0), s1, sizeof s1),
           grouped(est_capacity(&img, 2, 1, 1, 0), s2, sizeof s2));
    printf("\n(já descontados os cabeçalhos; o nome do arquivo escondido também ocupa espaço)\n");
    bmp_free(&img);
    return EXIT_OK;
}

static int cmd_analyze(const args *a)
{
    if (a->npositional != 1) {
        fail(NULL, "uso: esteg analisar <imagem.bmp>");
        return EXIT_USAGE;
    }
    bmp_image img;
    if (!load_image(a->positional[0], &img))
        return EXIT_ERROR;
    size_t total = bmp_channels(&img);
    char s1[32];
    printf("%s: %s canais de cor, ataque do qui-quadrado em 10 trechos\n", a->positional[0],
           grouped(total, s1, sizeof s1));
    printf("(perto de 1: pares de valores equalizados, sinal de dados escondidos com LSB)\n\n");
    printf("  trecho da imagem   probabilidade\n");
    int suspicious = 0;
    for (int part = 0; part < 10; part++) {
        size_t first = total * (size_t)part / 10, last = total * (size_t)(part + 1) / 10;
        double p = est_chi_square(&img, first, last - first);
        int bar = (int)(p * 20 + 0.5);
        printf("  %3d%% a %3d%%       %s  ", part * 10, part * 10 + 10,
               probability(p, s1, sizeof s1));
        for (int k = 0; k < bar; k++)
            putchar('#');
        putchar('\n');
        suspicious += p > 0.9;
    }
    double whole = est_chi_square(&img, 0, total);
    printf("\nimagem inteira: %s\n", probability(whole, s1, sizeof s1));
    if (suspicious > 0)
        printf("Há %d trecho%s suspeito%s (acima de 0,9). Imagens com muito ruído também podem dar "
               "esse sinal.\n", suspicious, suspicious == 1 ? "" : "s", suspicious == 1 ? "" : "s");
    else
        printf("Nenhum trecho suspeito pelo qui-quadrado (o que não prova que a imagem esteja limpa).\n");
    bmp_free(&img);
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return EXIT_USAGE;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "ajuda") == 0) {
        usage(stdout);
        return EXIT_OK;
    }
    if (strcmp(cmd, "-V") == 0 || strcmp(cmd, "--version") == 0) {
        printf("esteg %s\n", ESTEG_VERSION);
        return EXIT_OK;
    }
    args a;
    if (parse_args(argc, argv, &a) != 0) {
        free(a.password_owned);
        return EXIT_USAGE;
    }
    int rc;
    if (strcmp(cmd, "esconder") == 0)
        rc = cmd_hide(&a);
    else if (strcmp(cmd, "revelar") == 0)
        rc = cmd_reveal(&a);
    else if (strcmp(cmd, "capacidade") == 0)
        rc = cmd_capacity(&a);
    else if (strcmp(cmd, "analisar") == 0)
        rc = cmd_analyze(&a);
    else {
        fprintf(stderr, "%s: comando desconhecido: %s\n", PROGRAM, cmd);
        fprintf(stderr, "use \"esteg --help\" para ver os comandos\n");
        rc = EXIT_USAGE;
    }
    if (a.password_owned != NULL) {
        memset(a.password_owned, 0, strlen(a.password_owned));
        free(a.password_owned);
    }
    return rc;
}
