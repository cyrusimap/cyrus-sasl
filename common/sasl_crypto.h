/* Cryptographic helpers for SASL mechanisms.
 * Copyright (c) 2026 Sergei Ilinykh.
 * Distributed under the terms in COPYING.
 */
#ifndef SASL_CRYPTO_H
#define SASL_CRYPTO_H

#include <sasl.h>
#include <saslplug.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SASL_MAX_HASH_SIZE 64

typedef struct sasl_crypto_context {
    const sasl_utils_t *utils;
    const sasl_crypto_t *operations;
    void *context;
    unsigned hash_size;
} sasl_crypto_context_t;

int _sasl_crypto_init(const sasl_utils_t *utils, const char *algorithm,
                      sasl_crypto_context_t *crypto);
int _sasl_crypto_hash(const sasl_crypto_context_t *crypto,
                      const struct iovec *input, unsigned count,
                      unsigned char *output);
int _sasl_crypto_digest(const sasl_crypto_context_t *crypto,
                        const unsigned char *input, size_t inputlen,
                        unsigned char *output);
int _sasl_crypto_default(void *context, const char *algorithm,
                         const sasl_crypto_t **operations,
                         void **crypto_context);
int _sasl_crypto_hmac(const sasl_crypto_context_t *crypto,
                      const unsigned char *key, size_t keylen,
                      const unsigned char *input, size_t inputlen,
                      unsigned char *output);
int _sasl_crypto_pbkdf2(const sasl_crypto_context_t *crypto,
                        const unsigned char *password, size_t passwordlen,
                        const unsigned char *salt, size_t saltlen,
                        unsigned iterations, unsigned char *output);
#ifdef __cplusplus
}
#endif
#endif
