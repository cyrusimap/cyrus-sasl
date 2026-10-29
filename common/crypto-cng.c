/* Windows CNG implementation of the public crypto callback contract.
 * Copyright (c) 2026 Sergei Ilinykh.
 * Distributed under the terms in COPYING.
 */
#ifndef _WIN32
#error The CNG backend requires a native Windows target.
#endif
#include <limits.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>
#include "crypto-cng.h"

#ifndef BCRYPT_SHA256_ALG_HANDLE
#error The CNG backend requires the Windows 10 SDK or later.
#endif

typedef struct cng_algorithm {
    const char *name;
    BCRYPT_ALG_HANDLE hash, hmac;
    unsigned size;
} cng_algorithm_t;

/* Pseudo-handles need no initialization or cleanup and can be shared across
 * threads. Each operation owns its hash object; no passwords or keys are
 * retained in the shared context. This backend requires Windows 10 or later.
 */
static const cng_algorithm_t algorithms[] = {
    {"MD5", BCRYPT_MD5_ALG_HANDLE, BCRYPT_HMAC_MD5_ALG_HANDLE, 16},
    {"SHA1", BCRYPT_SHA1_ALG_HANDLE, BCRYPT_HMAC_SHA1_ALG_HANDLE, 20},
    {"SHA256", BCRYPT_SHA256_ALG_HANDLE, BCRYPT_HMAC_SHA256_ALG_HANDLE, 32},
    {"SHA384", BCRYPT_SHA384_ALG_HANDLE, BCRYPT_HMAC_SHA384_ALG_HANDLE, 48},
    {"SHA512", BCRYPT_SHA512_ALG_HANDLE, BCRYPT_HMAC_SHA512_ALG_HANDLE, 64}
};

static int cng_result(NTSTATUS status, unsigned char *output, unsigned length)
{
    if (status >= 0)
        return SASL_OK;
    SecureZeroMemory(output, length);
    /* STATUS_NO_MEMORY */
    return (ULONG)status == 0xc0000017UL ? SASL_NOMEM : SASL_FAIL;
}

static int cng_output(const cng_algorithm_t *algorithm,
                       unsigned char *output, unsigned length)
{
    return algorithm != NULL && output != NULL && length == algorithm->size;
}

static NTSTATUS cng_update(BCRYPT_HASH_HANDLE hash,
                            const unsigned char *input, size_t length)
{
    NTSTATUS status;
    while (length) {
        ULONG chunk = length > ULONG_MAX ? ULONG_MAX : (ULONG)length;
        status = BCryptHashData(hash, (PUCHAR)input, chunk, 0);
        if (status < 0)
            return status;
        input += chunk;
        length -= chunk;
    }
    return 0;
}

static int cng_hash(void *context, const struct iovec *input, unsigned count,
                     unsigned char *output, unsigned length)
{
    const cng_algorithm_t *algorithm = context;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;
    unsigned i;

    if (!cng_output(algorithm, output, length))
        return SASL_BADPARAM;
    if (count && input == NULL)
        goto badparam;
    for (i = 0; i < count; i++) {
        if (input[i].iov_len < 0 ||
            (input[i].iov_len && input[i].iov_base == NULL))
            goto badparam;
    }
    status = BCryptCreateHash(algorithm->hash, &hash, NULL, 0, NULL, 0, 0);
    if (status < 0)
        return cng_result(status, output, length);
    for (i = 0; i < count; i++) {
        status = cng_update(hash, (const unsigned char *)input[i].iov_base,
                            (size_t)input[i].iov_len);
        if (status < 0)
            break;
    }
    if (status >= 0)
        status = BCryptFinishHash(hash, output, length, 0);
    BCryptDestroyHash(hash);
    return cng_result(status, output, length);

badparam:
    SecureZeroMemory(output, length);
    return SASL_BADPARAM;
}

static int cng_hmac(void *context, const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t inputlen,
                     unsigned char *output, unsigned length)
{
    const cng_algorithm_t *algorithm = context;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;
    static const unsigned char empty = 0;

    if (!cng_output(algorithm, output, length))
        return SASL_BADPARAM;
    if (keylen > ULONG_MAX || (keylen && key == NULL) ||
        (inputlen && input == NULL)) {
        SecureZeroMemory(output, length);
        return SASL_BADPARAM;
    }
    /* An empty HMAC key must not be mistaken for an unkeyed hash. */
    if (key == NULL)
        key = &empty;
    status = BCryptCreateHash(algorithm->hmac, &hash, NULL, 0, (PUCHAR)key,
                              (ULONG)keylen, 0);
    if (status < 0)
        return cng_result(status, output, length);
    status = cng_update(hash, input, inputlen);
    if (status >= 0)
        status = BCryptFinishHash(hash, output, length, 0);
    BCryptDestroyHash(hash);
    return cng_result(status, output, length);
}

static int cng_pbkdf2(void *context, const unsigned char *password,
                       size_t passwordlen, const unsigned char *salt,
                       size_t saltlen, unsigned iterations,
                       unsigned char *output, unsigned length)
{
    const cng_algorithm_t *algorithm = context;
    NTSTATUS status;

    if (!cng_output(algorithm, output, length))
        return SASL_BADPARAM;
    if (passwordlen > ULONG_MAX || saltlen > ULONG_MAX || iterations == 0 ||
        (passwordlen && password == NULL) || (saltlen && salt == NULL)) {
        SecureZeroMemory(output, length);
        return SASL_BADPARAM;
    }
    status = BCryptDeriveKeyPBKDF2(algorithm->hmac, (PUCHAR)password,
                                   (ULONG)passwordlen, (PUCHAR)salt,
                                   (ULONG)saltlen, iterations, output, length,
                                   0);
    return cng_result(status, output, length);
}

int _sasl_cng_getcrypto(void *context, const char *name,
                        const sasl_crypto_t **operations,
                        void **crypto_context)
{
    static const sasl_crypto_t table = {
        SASL_CRYPTO_VERSION, cng_hash, cng_hmac, cng_pbkdf2};
    unsigned i;
    (void)context;

    if (operations == NULL || crypto_context == NULL)
        return SASL_BADPARAM;
    *operations = NULL;
    *crypto_context = NULL;
    if (name == NULL)
        return SASL_BADPARAM;
    for (i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
        if (!strcmp(name, algorithms[i].name)) {
            *operations = &table;
            *crypto_context = (void *)&algorithms[i];
            return SASL_OK;
        }
    }
    /* CNG does not supply SHA224; do not substitute or truncate SHA256. */
    return SASL_NOMECH;
}
