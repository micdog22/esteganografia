/*
 * cripto.h: primitivas criptográficas implementadas do zero.
 *
 *   SHA-256       FIPS 180-4
 *   HMAC-SHA256   RFC 2104
 *   PBKDF2        RFC 8018 (com HMAC-SHA256)
 *   HKDF-Expand   RFC 5869 (um bloco)
 *   ChaCha20      RFC 8439
 *
 * Código educacional e não auditado: não use para proteger nada importante.
 */
#ifndef ESTEG_CRIPTO_H
#define ESTEG_CRIPTO_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST 32
#define SHA256_BLOCK 64

typedef struct {
    uint32_t h[8];        /* estado (os 8 registradores de 32 bits) */
    uint64_t length;      /* bytes processados até agora */
    uint8_t buf[64];      /* bloco parcial */
    size_t buf_len;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t n);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST]);
void sha256(const void *data, size_t n, uint8_t out[SHA256_DIGEST]);

/* HMAC com os estados interno e externo já preparados (ipad e opad). */
typedef struct {
    sha256_ctx inner;
    sha256_ctx outer;
} hmac_sha256_ctx;

void hmac_sha256_init(hmac_sha256_ctx *c, const uint8_t *key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx *c, const void *data, size_t n);
void hmac_sha256_final(hmac_sha256_ctx *c, uint8_t out[SHA256_DIGEST]);
void hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t n,
                 uint8_t out[SHA256_DIGEST]);

void pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
                        size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len);

/* HKDF-Expand com saída de 32 bytes: HMAC(prk, info || 0x01). */
void hkdf_expand32(const uint8_t prk[32], const char *info, uint8_t out[32]);

/* ChaCha20: chave de 256 bits, nonce de 96 bits e contador de blocos de 32 bits. */
void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                    uint8_t out[64]);

typedef struct {
    uint8_t key[32];
    uint8_t nonce[12];
    uint32_t counter;
    uint8_t block[64];
    size_t used;          /* bytes do bloco atual já consumidos */
} chacha20_ctx;

void chacha20_init(chacha20_ctx *c, const uint8_t key[32], const uint8_t nonce[12],
                   uint32_t counter);
void chacha20_xor(chacha20_ctx *c, uint8_t *data, size_t n);   /* cifra e decifra */
void chacha20_keystream(chacha20_ctx *c, uint8_t *out, size_t n);
uint64_t chacha20_u64(chacha20_ctx *c);

/* Compara em tempo constante (não para no primeiro byte diferente). */
int ct_equal(const uint8_t *a, const uint8_t *b, size_t n);
/* Zera memória sensível sem o compilador poder remover a escrita. */
void secure_zero(void *p, size_t n);

#endif /* ESTEG_CRIPTO_H */
