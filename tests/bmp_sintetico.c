/*
 * bmp_sintetico.c: cria BMPs em memória para os testes.
 *
 * Dois desenhos: ruído (cores aleatórias, determinísticas pela semente) e
 * uma paisagem com 6 bits por cor (RGB666), cujos bits menos significativos
 * são todos zero: ótima para ver o ataque do qui-quadrado.
 */
#include "bmp_sintetico.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

static uint64_t mix(uint64_t z)
{
    z += UINT64_C(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static uint8_t clamp(double v)
{
    return v < 0 ? 0 : v > 255 ? 255 : (uint8_t)v;
}

void synth_color(const synth_params *p, int x, int y, uint8_t rgb[3])
{
    if (p->pattern == PATTERN_NOISE) {
        uint64_t r = mix(p->seed ^ ((uint64_t)y << 32) ^ (uint64_t)x);
        rgb[0] = (uint8_t)r;
        rgb[1] = (uint8_t)(r >> 8);
        rgb[2] = (uint8_t)(r >> 16);
        return;
    }
    /* Paisagem: céu em degradê, sol, morros e chão. */
    double fx = (double)x / p->width, fy = (double)y / p->height;
    double hill = 0.62 + 0.08 * sin(fx * 9.0) + 0.04 * sin(fx * 23.0 + 1.0);
    double r, g, b;
    double dx = fx - 0.75, dy = fy - 0.25;
    if (dx * dx + dy * dy < 0.008) {
        r = 255; g = 214; b = 90;                                   /* sol */
    } else if (fy < hill) {
        r = 70 + 120 * fy; g = 130 + 90 * fy; b = 235 - 20 * fy;   /* céu */
    } else if (fy < 0.85) {
        r = 40 + 30 * fy; g = 140 - 60 * (fy - hill); b = 50;       /* morro */
    } else {
        r = 120 - 30 * fy; g = 85; b = 50;                          /* chão */
    }
    /* Textura (como o grão de uma foto) e uma leve variação na horizontal,
       depois quantizadas para 6 bits por cor (RGB666, como em telas de 18 bits). */
    uint64_t n = mix(p->seed ^ ((uint64_t)y << 32) ^ (uint64_t)x);
    r += (double)(n & 63u) - 32.0 + 40.0 * fx;
    g += (double)((n >> 8) & 63u) - 32.0 - 30.0 * fx;
    b += (double)((n >> 16) & 63u) - 32.0;
    rgb[0] = (uint8_t)(clamp(r) & 0xFC);
    rgb[1] = (uint8_t)(clamp(g) & 0xFC);
    rgb[2] = (uint8_t)(clamp(b) & 0xFC);
}

uint8_t synth_alpha(int x, int y)
{
    return (uint8_t)(0x80 + ((x * 7 + y * 13) & 0x7F));
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

uint8_t *synth_bmp(const synth_params *p, size_t *size)
{
    int bitfields = p->bpp == 32 && p->header >= 108;
    size_t stride = ((size_t)p->width * (size_t)p->bpp + 31) / 32 * 4;
    size_t offset = 14 + (size_t)p->header;
    size_t total = offset + stride * (size_t)p->height;
    uint8_t *f = calloc(1, total);
    if (f == NULL)
        return NULL;

    f[0] = 'B';
    f[1] = 'M';
    put32(f + 2, (uint32_t)total);
    put32(f + 10, (uint32_t)offset);
    put32(f + 14, (uint32_t)p->header);
    put32(f + 18, (uint32_t)p->width);
    put32(f + 22, (uint32_t)(p->top_down ? -p->height : p->height));
    put16(f + 26, 1);
    put16(f + 28, (uint16_t)p->bpp);
    put32(f + 30, bitfields ? 3u : 0u);
    put32(f + 34, (uint32_t)(stride * (size_t)p->height));
    put32(f + 38, 2835);   /* 72 dpi */
    put32(f + 42, 2835);

    /* Posição de cada cor dentro do pixel. */
    int ob = 0, og = 1, orr = 2, oa = 3;
    if (bitfields) {
        if (p->rgba) {
            orr = 0;
            og = 1;
            ob = 2;
            oa = 3;
        }
        put32(f + 54, 0xFFu << (8 * orr));
        put32(f + 58, 0xFFu << (8 * og));
        put32(f + 62, 0xFFu << (8 * ob));
        put32(f + 66, 0xFFu << (8 * oa));
        /* Espaço de cor: "sRGB" no V5; no V4, LCS_CALIBRATED_RGB (0), porque o
           ImageIO do macOS recusa V4 com "sRGB". */
        put32(f + 70, p->header == 124 ? 0x73524742u : 0u);
        if (p->header == 124)
            put32(f + 14 + 108, 4u); /* intenção de renderização */
    }

    size_t bytes = (size_t)p->bpp / 8;
    for (int y = 0; y < p->height; y++) {
        size_t row = p->top_down ? (size_t)y : (size_t)(p->height - 1 - y);
        uint8_t *line = f + offset + row * stride;
        for (int x = 0; x < p->width; x++) {
            uint8_t rgb[3];
            synth_color(p, x, y, rgb);
            uint8_t *px = line + (size_t)x * bytes;
            px[orr] = rgb[0];
            px[og] = rgb[1];
            px[ob] = rgb[2];
            if (p->bpp == 32)
                px[oa] = synth_alpha(x, y);
        }
        /* O preenchimento da linha fica com um valor conhecido. */
        for (size_t k = (size_t)p->width * bytes; k < stride; k++)
            line[k] = 0xAB;
    }
    *size = total;
    return f;
}
