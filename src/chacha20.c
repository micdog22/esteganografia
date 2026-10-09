/*
 * chacha20.c: a cifra de fluxo ChaCha20 (RFC 8439).
 *
 * O estado são 16 palavras de 32 bits:
 *
 *     constantes   "expa"   "nd 3"   "2-by"   "te k"
 *     chave        k0       k1       k2       k3
 *     chave        k4       k5       k6       k7
 *     contador     n0       n1       n2              (n = nonce)
 *
 * Vinte rodadas de "quarter rounds" (soma, xor e rotação) embaralham o
 * estado; somar o estado original ao resultado dá 64 bytes de fluxo, que
 * são combinados com xor aos dados. Cifrar e decifrar é a mesma operação.
 */
#include "cripto.h"

#include <string.h>

static uint32_t rotl(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define QUARTER(a, b, c, d)                 \
    do {                                    \
        a += b; d ^= a; d = rotl(d, 16);    \
        c += d; b ^= c; b = rotl(b, 12);    \
        a += b; d ^= a; d = rotl(d, 8);     \
        c += d; b ^= c; b = rotl(b, 7);     \
    } while (0)

void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                    uint8_t out[64])
{
    uint32_t s[16], x[16];
    s[0] = 0x61707865;   /* "expand 32-byte k" em little-endian */
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++)
        s[4 + i] = load_le32(key + 4 * i);
    s[12] = counter;
    for (int i = 0; i < 3; i++)
        s[13 + i] = load_le32(nonce + 4 * i);
    memcpy(x, s, sizeof x);
    for (int round = 0; round < 10; round++) {
        /* Rodada de colunas... */
        QUARTER(x[0], x[4], x[8], x[12]);
        QUARTER(x[1], x[5], x[9], x[13]);
        QUARTER(x[2], x[6], x[10], x[14]);
        QUARTER(x[3], x[7], x[11], x[15]);
        /* ...e rodada de diagonais. */
        QUARTER(x[0], x[5], x[10], x[15]);
        QUARTER(x[1], x[6], x[11], x[12]);
        QUARTER(x[2], x[7], x[8], x[13]);
        QUARTER(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++)
        store_le32(out + 4 * i, x[i] + s[i]);
    secure_zero(x, sizeof x);
    secure_zero(s, sizeof s);
}

void chacha20_init(chacha20_ctx *c, const uint8_t key[32], const uint8_t nonce[12],
                   uint32_t counter)
{
    memcpy(c->key, key, 32);
    memcpy(c->nonce, nonce, 12);
    c->counter = counter;
    c->used = 64;   /* nenhum bloco gerado ainda */
}

void chacha20_keystream(chacha20_ctx *c, uint8_t *out, size_t n)
{
    while (n > 0) {
        if (c->used == 64) {
            chacha20_block(c->key, c->counter++, c->nonce, c->block);
            c->used = 0;
        }
        size_t take = 64 - c->used < n ? 64 - c->used : n;
        memcpy(out, c->block + c->used, take);
        c->used += take;
        out += take;
        n -= take;
    }
}

void chacha20_xor(chacha20_ctx *c, uint8_t *data, size_t n)
{
    uint8_t ks[64];
    while (n > 0) {
        size_t take = n < sizeof ks ? n : sizeof ks;
        chacha20_keystream(c, ks, take);
        for (size_t i = 0; i < take; i++)
            data[i] ^= ks[i];
        data += take;
        n -= take;
    }
    secure_zero(ks, sizeof ks);
}

uint64_t chacha20_u64(chacha20_ctx *c)
{
    uint8_t b[8];
    chacha20_keystream(c, b, 8);
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | b[i];
    return v;
}
