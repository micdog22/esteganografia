/* bmp_sintetico.h: cria BMPs em memória para os testes. */
#ifndef BMP_SINTETICO_H
#define BMP_SINTETICO_H

#include <stddef.h>
#include <stdint.h>

enum { PATTERN_NOISE = 0, PATTERN_LANDSCAPE = 1 };

typedef struct {
    int width, height;
    int bpp;              /* 24 ou 32 */
    int top_down;         /* altura negativa no arquivo */
    int header;           /* 40, 108 (V4) ou 124 (V5) */
    int rgba;             /* 32 bits com BI_BITFIELDS na ordem R, G, B, A */
    int pattern;          /* PATTERN_NOISE ou PATTERN_LANDSCAPE */
    uint64_t seed;
} synth_params;

/* Cor (r, g, b) que o gerador pôs no pixel (x, y), com y = 0 no topo. */
void synth_color(const synth_params *p, int x, int y, uint8_t rgb[3]);
/* Valor do quarto byte (alfa) do pixel (x, y) em 32 bits. */
uint8_t synth_alpha(int x, int y);

/* Monta o arquivo BMP inteiro (alocado com malloc). */
uint8_t *synth_bmp(const synth_params *p, size_t *size);

#endif
