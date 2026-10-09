/*
 * sha256.c: SHA-256 (FIPS 180-4), HMAC (RFC 2104), PBKDF2 (RFC 8018) e
 * HKDF-Expand (RFC 5869).
 */
#include "cripto.h"

#include <string.h>

/* Primeiros 32 bits das partes fracionárias das raízes cúbicas dos 64 primeiros primos. */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* A função de compressão: mistura um bloco de 64 bytes no estado. */
static void compress(uint32_t h[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int t = 0; t < 16; t++)
        w[t] = load_be32(block + 4 * t);
    for (int t = 16; t < 64; t++) {
        uint32_t s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
        uint32_t s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int t = 0; t < 64; t++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + K[t] + w[t];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

void sha256_init(sha256_ctx *c)
{
    /* Primeiros 32 bits das partes fracionárias das raízes quadradas dos 8 primeiros primos. */
    static const uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, H0, sizeof H0);
    c->length = 0;
    c->buf_len = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    c->length += n;
    if (c->buf_len > 0) {
        size_t take = 64 - c->buf_len < n ? 64 - c->buf_len : n;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p += take;
        n -= take;
        if (c->buf_len == 64) {
            compress(c->h, c->buf);
            c->buf_len = 0;
        }
    }
    while (n >= 64) {
        compress(c->h, p);
        p += 64;
        n -= 64;
    }
    if (n > 0) {
        memcpy(c->buf, p, n);
        c->buf_len = n;
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST])
{
    /* Preenchimento: um bit 1, zeros até sobrarem 8 bytes no bloco, e o
       tamanho da mensagem em bits (64 bits, big-endian). */
    uint64_t bits = c->length * 8u;
    uint8_t pad[72];
    size_t pad_len = (c->buf_len < 56 ? 56 : 120) - c->buf_len;
    memset(pad, 0, sizeof pad);
    pad[0] = 0x80;
    for (int i = 0; i < 8; i++)
        pad[pad_len + (size_t)i] = (uint8_t)(bits >> (56 - 8 * i));
    uint64_t saved = c->length;
    sha256_update(c, pad, pad_len + 8);
    c->length = saved;
    for (int i = 0; i < 8; i++)
        store_be32(out + 4 * i, c->h[i]);
    secure_zero(c, sizeof *c);
}

void sha256(const void *data, size_t n, uint8_t out[SHA256_DIGEST])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, n);
    sha256_final(&c, out);
}

/* ------------------------------------------------------------------ HMAC */

void hmac_sha256_init(hmac_sha256_ctx *c, const uint8_t *key, size_t key_len)
{
    uint8_t k[SHA256_BLOCK] = {0}, pad[SHA256_BLOCK];
    /* Chaves maiores que o bloco viram o seu hash. */
    if (key_len > SHA256_BLOCK)
        sha256(key, key_len, k);
    else if (key_len > 0)
        memcpy(k, key, key_len);
    for (int i = 0; i < SHA256_BLOCK; i++)
        pad[i] = k[i] ^ 0x36;
    sha256_init(&c->inner);
    sha256_update(&c->inner, pad, sizeof pad);
    for (int i = 0; i < SHA256_BLOCK; i++)
        pad[i] = k[i] ^ 0x5c;
    sha256_init(&c->outer);
    sha256_update(&c->outer, pad, sizeof pad);
    secure_zero(k, sizeof k);
    secure_zero(pad, sizeof pad);
}

void hmac_sha256_update(hmac_sha256_ctx *c, const void *data, size_t n)
{
    sha256_update(&c->inner, data, n);
}

void hmac_sha256_final(hmac_sha256_ctx *c, uint8_t out[SHA256_DIGEST])
{
    /* HMAC(k, m) = H((k ^ opad) || H((k ^ ipad) || m)) */
    uint8_t inner[SHA256_DIGEST];
    sha256_final(&c->inner, inner);
    sha256_update(&c->outer, inner, sizeof inner);
    sha256_final(&c->outer, out);
    secure_zero(inner, sizeof inner);
}

void hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t n,
                 uint8_t out[SHA256_DIGEST])
{
    hmac_sha256_ctx c;
    hmac_sha256_init(&c, key, key_len);
    hmac_sha256_update(&c, data, n);
    hmac_sha256_final(&c, out);
}

/* ---------------------------------------------------------------- PBKDF2 */

void pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
                        size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len)
{
    hmac_sha256_ctx base, c;
    uint8_t u[SHA256_DIGEST], t[SHA256_DIGEST];

    /* O HMAC com a senha como chave é preparado uma vez só: cada iteração
       copia os estados prontos e custa duas compressões do SHA-256. */
    hmac_sha256_init(&base, password, password_len);
    for (uint32_t block = 1; out_len > 0; block++) {
        uint8_t be[4] = {(uint8_t)(block >> 24), (uint8_t)(block >> 16), (uint8_t)(block >> 8),
                         (uint8_t)block};
        /* U1 = HMAC(senha, sal || bloco), Ui = HMAC(senha, Ui-1); T = U1 ^ ... ^ Uc. */
        c = base;
        hmac_sha256_update(&c, salt, salt_len);
        hmac_sha256_update(&c, be, 4);
        hmac_sha256_final(&c, u);
        memcpy(t, u, sizeof t);
        for (uint32_t i = 1; i < iterations; i++) {
            c = base;
            hmac_sha256_update(&c, u, sizeof u);
            hmac_sha256_final(&c, u);
            for (int k = 0; k < SHA256_DIGEST; k++)
                t[k] ^= u[k];
        }
        size_t take = out_len < SHA256_DIGEST ? out_len : SHA256_DIGEST;
        memcpy(out, t, take);
        out += take;
        out_len -= take;
    }
    secure_zero(&base, sizeof base);
    secure_zero(&c, sizeof c);
    secure_zero(u, sizeof u);
    secure_zero(t, sizeof t);
}

void hkdf_expand32(const uint8_t prk[32], const char *info, uint8_t out[32])
{
    hmac_sha256_ctx c;
    const uint8_t one = 1;
    hmac_sha256_init(&c, prk, 32);
    hmac_sha256_update(&c, info, strlen(info));
    hmac_sha256_update(&c, &one, 1);
    hmac_sha256_final(&c, out);
}

/* ----------------------------------------------------------- utilidades */

int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--)
        *v++ = 0;
}
