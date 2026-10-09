/*
 * esteg.h: esteganografia LSB em imagens BMP.
 *
 * Código educacional e não auditado. A cifra (ChaCha20 + HMAC-SHA256 com
 * chaves do PBKDF2) foi implementada do zero para estudo; não confie nela
 * para proteger dados reais.
 */
#ifndef ESTEG_H
#define ESTEG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ESTEG_VERSION "1.0.0"
#define ESTEG_DEFAULT_ITERATIONS 200000u
#define ESTEG_SALT_SIZE 16
#define ESTEG_MAX_NAME 255

typedef enum {
    EST_OK = 0,
    EST_ERR_MEMORY,           /* falta de memória */
    EST_ERR_IO,               /* erro de leitura ou escrita de arquivo */
    EST_ERR_NOT_BMP,          /* não começa com "BM" */
    EST_ERR_UNSUPPORTED,      /* BMP válido, mas em formato não suportado */
    EST_ERR_CORRUPT_BMP,      /* tamanhos inconsistentes no BMP */
    EST_ERR_CAPACITY,         /* o arquivo não cabe na imagem */
    EST_ERR_NOT_FOUND,        /* nenhuma assinatura EST1 na imagem */
    EST_ERR_NEEDS_PASSWORD,   /* a imagem foi protegida com senha */
    EST_ERR_AUTH,             /* senha errada ou dados adulterados (HMAC) */
    EST_ERR_CRC,              /* CRC-32 do conteúdo não confere */
    EST_ERR_BAD_HEADER,       /* cabeçalho escondido inválido */
    EST_ERR_RANDOM,           /* não deu para ler /dev/urandom */
    EST_ERR_ARGUMENT          /* parâmetro inválido */
} est_status;

const char *est_strerror(est_status st);

/* ---------------------------------------------------------------- BMP */

typedef struct {
    uint8_t *file;           /* o arquivo inteiro (os cabeçalhos são preservados) */
    size_t file_size;
    int32_t width;
    int32_t height;          /* sempre positivo */
    int bits_per_pixel;      /* 24 ou 32 */
    int top_down;            /* 1 se as linhas vêm de cima para baixo */
    uint32_t header_size;    /* 40 (BITMAPINFOHEADER), 108 (V4) ou 124 (V5) */
    size_t pixel_offset;     /* início dos pixels no arquivo */
    size_t stride;           /* bytes por linha, múltiplo de 4 */
    int offset[3];           /* posição de azul, verde e vermelho dentro do pixel */
    int alpha_offset;        /* posição do quarto byte (alfa ou livre), -1 em 24 bits */
} bmp_image;

/* Interpreta um BMP já carregado. Em caso de sucesso, img fica dona de data. */
est_status bmp_parse(bmp_image *img, uint8_t *data, size_t size);
est_status bmp_load(bmp_image *img, const char *path);
est_status bmp_save(const bmp_image *img, const char *path);
void bmp_free(bmp_image *img);

/* Canais de cor utilizáveis: 3 por pixel (o alfa nunca é usado). */
size_t bmp_channels(const bmp_image *img);

/* Ponteiro para o canal i, na ordem da imagem: de cima para baixo, da
   esquerda para a direita, e azul, verde, vermelho em cada pixel. */
uint8_t *bmp_channel(const bmp_image *img, size_t i);

/* ------------------------------------------------------ esconder e revelar */

typedef struct {
    const char *password;    /* NULL ou "" = sem senha */
    int encrypt;             /* com senha: 1 cifra (padrão), 0 só embaralha as posições */
    int bits;                /* bits por canal: 1 ou 2 */
    uint32_t iterations;     /* PBKDF2; 0 = ESTEG_DEFAULT_ITERATIONS */
    const uint8_t *salt;     /* NULL = sal aleatório de /dev/urandom */
} est_options;

/* Opções padrão: sem senha, 1 bit por canal. */
est_options est_default_options(void);

typedef struct {
    int bits;                /* bits por canal usados */
    int has_password;        /* posições embaralhadas pela senha */
    int encrypted;           /* conteúdo cifrado com ChaCha20 + HMAC-SHA256 */
    uint32_t iterations;     /* PBKDF2 (com senha) */
    uint64_t size;           /* tamanho do arquivo escondido */
    uint32_t crc32;          /* CRC-32 do arquivo escondido */
    char name[ESTEG_MAX_NAME + 1];   /* nome original (sem caminho) */
    size_t channels_used;    /* canais modificáveis efetivamente usados */
} est_info;

/* Maior arquivo (em bytes) que cabe, dado o tamanho do nome. */
uint64_t est_capacity(const bmp_image *img, int bits, int with_password, int encrypt,
                      size_t name_len);

/* Esconde data na imagem (que é modificada em memória). */
est_status est_hide(bmp_image *img, const uint8_t *data, size_t len, const char *name,
                    const est_options *opt, est_info *info);

/* Recupera o arquivo escondido; *data é alocado com malloc. */
est_status est_reveal(const bmp_image *img, const char *password, uint8_t **data, size_t *len,
                      est_info *info);

/*
 * Nome seguro para gravar o arquivo revelado: só a parte depois da última
 * barra, sem caracteres de controle e nunca "." ou "..". Uma imagem
 * maliciosa poderia esconder um nome como "../../.bashrc".
 */
void est_safe_name(const char *stored, char *out, size_t cap);

/* CRC-32 (o mesmo do gzip e do zip). */
uint32_t est_crc32(uint32_t crc, const void *data, size_t len);

/* ------------------------------------------------------- esteganálise */

/*
 * Ataque do qui-quadrado (Westfeld e Pfitzmann, 1999) sobre os primeiros
 * count canais da imagem. Devolve a probabilidade de os pares de valores
 * (2k, 2k+1) estarem equalizados, o sinal típico de LSB com dados
 * aleatórios: perto de 1 indica dados escondidos, perto de 0 indica uma
 * imagem natural.
 */
double est_chi_square(const bmp_image *img, size_t first, size_t count);

/* Probabilidade de cauda da distribuição qui-quadrado (para os testes). */
double est_chi2_tail(double x, double degrees);

#ifdef __cplusplus
}
#endif

#endif /* ESTEG_H */
