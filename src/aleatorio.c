/*
 * aleatorio.c: bytes aleatórios do sistema operacional.
 *
 * Único ponto que depende do sistema: lê /dev/urandom, que existe no Linux e
 * no macOS. O sal do PBKDF2 precisa ser imprevisível; rand() não serve.
 */
#include "esteg.h"

#include <stdio.h>

est_status est_random_bytes(uint8_t *out, size_t n);

est_status est_random_bytes(uint8_t *out, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL)
        return EST_ERR_RANDOM;
    size_t got = fread(out, 1, n, f);
    fclose(f);
    return got == n ? EST_OK : EST_ERR_RANDOM;
}
