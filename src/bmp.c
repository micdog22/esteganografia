/*
 * bmp.c: leitura e escrita de BMP sem compressão (24 e 32 bits).
 *
 *   BITMAPFILEHEADER (14 bytes)
 *     0  "BM"
 *     2  tamanho do arquivo
 *     10 deslocamento dos pixels
 *   cabeçalho DIB (40, 108 ou 124 bytes)
 *     14 tamanho deste cabeçalho
 *     18 largura (com sinal)
 *     22 altura (negativa = linhas de cima para baixo)
 *     26 planos (1)
 *     28 bits por pixel (24 ou 32)
 *     30 compressão (0 = BI_RGB, 3 = BI_BITFIELDS)
 *     54 máscaras de vermelho, verde, azul e alfa (V4 e V5, ou logo depois
 *        do BITMAPINFOHEADER quando a compressão é BI_BITFIELDS)
 *
 * Cada linha ocupa um múltiplo de 4 bytes; o que sobra é preenchimento.
 * O arquivo inteiro fica em memória e só os bytes de cor mudam, então
 * perfis de cor e outros campos dos cabeçalhos V4/V5 são preservados.
 */
#include "esteg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE_SIZE ((size_t)1 << 30)   /* 1 GiB */

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Máscara de um byte inteiro (0xFF << 8k): devolve k, ou -1. */
static int mask_byte(uint32_t mask)
{
    for (int k = 0; k < 4; k++)
        if (mask == (uint32_t)0xFFu << (8 * k))
            return k;
    return -1;
}

est_status bmp_parse(bmp_image *img, uint8_t *data, size_t size)
{
    memset(img, 0, sizeof *img);
    if (size < 2 || data[0] != 'B' || data[1] != 'M')
        return EST_ERR_NOT_BMP;
    if (size < 14 + 40)
        return EST_ERR_CORRUPT_BMP;

    uint32_t off_bits = le32(data + 10);
    uint32_t hsize = le32(data + 14);
    if (hsize == 12)
        return EST_ERR_UNSUPPORTED;   /* BITMAPCOREHEADER, do OS/2 */
    if (hsize < 40 || hsize > 124 || 14 + (size_t)hsize > size)
        return EST_ERR_CORRUPT_BMP;

    int32_t width = (int32_t)le32(data + 18);
    int32_t height = (int32_t)le32(data + 22);
    uint16_t planes = le16(data + 26);
    uint16_t bpp = le16(data + 28);
    uint32_t compression = le32(data + 30);

    if (planes != 1 || width <= 0 || height == 0 || height == INT32_MIN)
        return EST_ERR_CORRUPT_BMP;
    if (bpp != 24 && bpp != 32)
        return EST_ERR_UNSUPPORTED;

    /* Ordem padrão dos bytes de um pixel: azul, verde, vermelho (e alfa). */
    int off_b = 0, off_g = 1, off_r = 2, off_a = bpp == 32 ? 3 : -1;
    if (compression == 3 && bpp == 32) {
        /* BI_BITFIELDS: as máscaras dizem onde está cada cor. */
        size_t at = 14 + 40;
        if (at + 12 > size)
            return EST_ERR_CORRUPT_BMP;
        int r = mask_byte(le32(data + at)), g = mask_byte(le32(data + at + 4)),
            b = mask_byte(le32(data + at + 8));
        if (r < 0 || g < 0 || b < 0 || r == g || r == b || g == b)
            return EST_ERR_UNSUPPORTED;   /* cores que não ocupam bytes inteiros */
        off_r = r;
        off_g = g;
        off_b = b;
        off_a = 6 - r - g - b;            /* o byte que sobrou: alfa ou livre */
    } else if (compression != 0) {
        return EST_ERR_UNSUPPORTED;       /* RLE, JPEG, PNG ou bitfields em 24 bits */
    }

    uint64_t rows = height < 0 ? (uint64_t)(-(int64_t)height) : (uint64_t)height;
    uint64_t stride = ((uint64_t)width * bpp + 31) / 32 * 4;
    if (off_bits < 14 + hsize || off_bits > size || stride * rows > size - off_bits)
        return EST_ERR_CORRUPT_BMP;

    img->file = data;
    img->file_size = size;
    img->width = width;
    img->height = (int32_t)rows;
    img->bits_per_pixel = bpp;
    img->top_down = height < 0;
    img->header_size = hsize;
    img->pixel_offset = off_bits;
    img->stride = (size_t)stride;
    img->offset[0] = off_b;
    img->offset[1] = off_g;
    img->offset[2] = off_r;
    img->alpha_offset = off_a;
    return EST_OK;
}

est_status bmp_load(bmp_image *img, const char *path)
{
    memset(img, 0, sizeof *img);
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return EST_ERR_IO;
    size_t cap = 1 << 16, len = 0;
    uint8_t *buf = malloc(cap);
    est_status st = buf ? EST_OK : EST_ERR_MEMORY;
    while (st == EST_OK) {
        if (len == cap) {
            if (cap >= MAX_FILE_SIZE) {
                st = EST_ERR_UNSUPPORTED;
                break;
            }
            uint8_t *p = realloc(buf, cap * 2);
            if (p == NULL) {
                st = EST_ERR_MEMORY;
                break;
            }
            buf = p;
            cap *= 2;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) {
            if (ferror(f))
                st = EST_ERR_IO;
            break;
        }
    }
    fclose(f);
    if (st == EST_OK)
        st = bmp_parse(img, buf, len);
    if (st != EST_OK)
        free(buf);
    return st;
}

est_status bmp_save(const bmp_image *img, const char *path)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL)
        return EST_ERR_IO;
    size_t n = fwrite(img->file, 1, img->file_size, f);
    int closed = fclose(f);
    return (n == img->file_size && closed == 0) ? EST_OK : EST_ERR_IO;
}

void bmp_free(bmp_image *img)
{
    free(img->file);
    memset(img, 0, sizeof *img);
}

size_t bmp_channels(const bmp_image *img)
{
    return (size_t)img->width * (size_t)img->height * 3u;
}

uint8_t *bmp_channel(const bmp_image *img, size_t i)
{
    size_t pixel = i / 3, c = i % 3;
    size_t y = pixel / (size_t)img->width, x = pixel % (size_t)img->width;
    /* Nas imagens de baixo para cima, a primeira linha do arquivo é a de baixo. */
    size_t row = img->top_down ? y : (size_t)img->height - 1 - y;
    return img->file + img->pixel_offset + row * img->stride +
           x * (size_t)(img->bits_per_pixel / 8) + (size_t)img->offset[c];
}
