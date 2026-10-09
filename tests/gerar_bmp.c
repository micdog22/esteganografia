/*
 * gerar_bmp.c: gera imagens BMP de teste.
 *
 *   gerar_bmp <largura> <altura> <24|32> <saída.bmp> [--topo] [--v4|--v5] [--rgba]
 *             [--paisagem] [--semente N]
 */
#include "bmp_sintetico.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "uso: gerar_bmp <largura> <altura> <24|32> <saída.bmp> [--topo] "
                        "[--v4|--v5] [--rgba] [--paisagem] [--semente N]\n");
        return 2;
    }
    synth_params p;
    memset(&p, 0, sizeof p);
    p.width = atoi(argv[1]);
    p.height = atoi(argv[2]);
    p.bpp = atoi(argv[3]);
    p.header = 40;
    p.seed = 2026;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--topo") == 0)
            p.top_down = 1;
        else if (strcmp(argv[i], "--v4") == 0)
            p.header = 108;
        else if (strcmp(argv[i], "--v5") == 0)
            p.header = 124;
        else if (strcmp(argv[i], "--rgba") == 0)
            p.rgba = 1;
        else if (strcmp(argv[i], "--paisagem") == 0)
            p.pattern = PATTERN_LANDSCAPE;
        else if (strcmp(argv[i], "--semente") == 0 && i + 1 < argc)
            p.seed = strtoull(argv[++i], NULL, 10);
        else {
            fprintf(stderr, "gerar_bmp: opção desconhecida: %s\n", argv[i]);
            return 2;
        }
    }
    if (p.width <= 0 || p.height <= 0 || p.width > 20000 || p.height > 20000 ||
        (p.bpp != 24 && p.bpp != 32)) {
        fprintf(stderr, "gerar_bmp: tamanho ou bits por pixel inválidos\n");
        return 2;
    }
    size_t size;
    uint8_t *bmp = synth_bmp(&p, &size);
    if (bmp == NULL)
        return 1;
    FILE *f = fopen(argv[4], "wb");
    int ok = f != NULL && fwrite(bmp, 1, size, f) == size;
    if (f != NULL && fclose(f) != 0)
        ok = 0;
    free(bmp);
    if (!ok) {
        fprintf(stderr, "gerar_bmp: não foi possível gravar %s\n", argv[4]);
        return 1;
    }
    return 0;
}
