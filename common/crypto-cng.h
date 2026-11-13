/* Windows CNG implementation of the public crypto callback contract.
 * Copyright (c) 2026 Sergei Ilinykh.
 * Distributed under the terms in COPYING.
 */
#ifndef SASL_CRYPTO_CNG_H
#define SASL_CRYPTO_CNG_H

#include <sasl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This adapter is private, not an exported libsasl API. Applications may
 * compile crypto-cng.c into their own executable to demonstrate callbacks.
 */
int _sasl_cng_getcrypto(void *context, const char *algorithm,
                        const sasl_crypto_t **operations,
                        void **crypto_context);

#ifdef __cplusplus
}
#endif
#endif
