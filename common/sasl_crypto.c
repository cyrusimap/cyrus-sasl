/* Cryptographic helpers for SASL mechanisms.
 * Copyright (c) 2026 Sergei Ilinykh.
 * Distributed under the terms in COPYING.
 */
#include <config.h>
#include <limits.h>
#include <string.h>
#ifndef _WIN32
#include <sys/uio.h>
#endif
#include "sasl_crypto.h"
#include "crypto-validate.h"
#ifdef HAVE_CNG
#include "crypto-cng.h"
#endif

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>

static int openssl_output(const EVP_MD *md, unsigned char *output,
                          unsigned outputlen)
{
    return md != NULL &&
           crypto_valid_output(output, outputlen, (unsigned)EVP_MD_size(md));
}

static int openssl_hash(void *context, const struct iovec *input,
                        unsigned count, unsigned char *output,
                        unsigned outputlen)
{
    const EVP_MD *md = context;
    EVP_MD_CTX *ctx;
    unsigned i, length = 0;
    int result = SASL_FAIL;

    if (!openssl_output(md, output, outputlen))
        return SASL_BADPARAM;
    if (!crypto_valid_hash_input(input, count)) {
        OPENSSL_cleanse(output, outputlen);
        return SASL_BADPARAM;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        OPENSSL_cleanse(output, outputlen);
        return SASL_NOMEM;
    }
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
        goto done;
    for (i = 0; i < count; i++) {
        if (EVP_DigestUpdate(ctx, input[i].iov_base, input[i].iov_len) != 1)
            goto done;
    }
    if (EVP_DigestFinal_ex(ctx, output, &length) == 1 && length == outputlen)
        result = SASL_OK;
done:
    EVP_MD_CTX_free(ctx);
    if (result != SASL_OK)
        OPENSSL_cleanse(output, outputlen);
    return result;
}

static int openssl_hmac(void *context, const unsigned char *key, size_t keylen,
                        const unsigned char *input, size_t inputlen,
                        unsigned char *output, unsigned outputlen)
{
    unsigned length = 0;

    static const unsigned char empty = 0;

    if (!openssl_output(context, output, outputlen))
        return SASL_BADPARAM;
    if (keylen > INT_MAX ||
        !crypto_valid_hmac_input(key, keylen, input, inputlen)) {
        OPENSSL_cleanse(output, outputlen);
        return SASL_BADPARAM;
    }
    if (key == NULL && keylen == 0)
        key = &empty;
    if (HMAC(context, key, (int)keylen, input, inputlen, output, &length) ==
            NULL ||
        length != outputlen) {
        OPENSSL_cleanse(output, outputlen);
        return SASL_FAIL;
    }
    return SASL_OK;
}

static int openssl_pbkdf2(void *context, const unsigned char *password,
                          size_t passwordlen, const unsigned char *salt,
                          size_t saltlen, unsigned iterations,
                          unsigned char *output, unsigned outputlen)
{
    if (!openssl_output(context, output, outputlen))
        return SASL_BADPARAM;
    if (passwordlen > INT_MAX || saltlen > INT_MAX || iterations > INT_MAX ||
        !crypto_valid_pbkdf2_input(password, passwordlen, salt, saltlen,
                                   iterations)) {
        OPENSSL_cleanse(output, outputlen);
        return SASL_BADPARAM;
    }
    if (PKCS5_PBKDF2_HMAC((const char *)password, (int)passwordlen, salt,
                          (int)saltlen, (int)iterations, context,
                          (int)outputlen, output) != 1) {
        OPENSSL_cleanse(output, outputlen);
        return SASL_FAIL;
    }
    return SASL_OK;
}

static const sasl_crypto_t openssl_operations = {
    SASL_CRYPTO_VERSION, openssl_hash, openssl_hmac, openssl_pbkdf2};
#endif

int _sasl_crypto_init(const sasl_utils_t *utils, const char *algorithm,
                      sasl_crypto_context_t *crypto)
{
    sasl_getcrypto_t *callback = NULL;
    void *context = NULL;
    int result;
    unsigned i;
    static const struct {
        const char *name;
        unsigned size;
    } hashes[] = {{"MD5", 16},    {"SHA1", 20},   {"SHA224", 28},
                  {"SHA256", 32}, {"SHA384", 48}, {"SHA512", 64}};

    if (utils == NULL || algorithm == NULL || crypto == NULL)
        return SASL_BADPARAM;
    memset(crypto, 0, sizeof(*crypto));
    crypto->utils = utils;
    for (i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
        if (!strcmp(algorithm, hashes[i].name)) {
            crypto->hash_size = hashes[i].size;
            break;
        }
    }
    if (crypto->hash_size == 0)
        return SASL_NOMECH;
    result = utils->getcallback(utils->conn, SASL_CB_CRYPTO,
                                (sasl_callback_ft *)&callback, &context);
    if (result == SASL_OK) {
        if (callback == NULL)
            return SASL_BADPARAM;
        result =
            callback(context, algorithm, &crypto->operations, &crypto->context);
        if (result == SASL_INTERACT)
            return SASL_BADPARAM;
        if (result != SASL_OK)
            return result > 0 ? SASL_FAIL : result;
        if (crypto->operations == NULL)
            return SASL_BADPARAM;
        if (crypto->operations->version != SASL_CRYPTO_VERSION)
            return SASL_BADVERS;
        if (crypto->operations->hash == NULL)
            return SASL_BADPARAM;
        return SASL_OK;
    }
    if (result == SASL_INTERACT)
        return SASL_BADPARAM;
    if (result != SASL_FAIL)
        return result > 0 ? SASL_FAIL : result;
    return _sasl_crypto_default(NULL, algorithm, &crypto->operations,
                                &crypto->context);
}

int _sasl_crypto_default(void *context __attribute__((unused)),
                         const char *algorithm,
                         const sasl_crypto_t **operations,
                         void **crypto_context)
{
    if (operations == NULL || crypto_context == NULL)
        return SASL_BADPARAM;
    *operations = NULL;
    *crypto_context = NULL;
    if (algorithm == NULL)
        return SASL_BADPARAM;
#ifdef HAVE_OPENSSL
    *crypto_context = (void *)EVP_get_digestbyname(algorithm);
    if (*crypto_context == NULL)
        return SASL_NOMECH;
    *operations = &openssl_operations;
    return SASL_OK;
#elif defined(HAVE_CNG)
    return _sasl_cng_getcrypto(NULL, algorithm, operations, crypto_context);
#else
    (void)algorithm;
    return SASL_NOMECH;
#endif
}

static int crypto_result(const sasl_crypto_context_t *crypto, int result,
                         unsigned char *output)
{
    if (result != SASL_OK) {
        crypto->utils->erasebuffer((char *)output, crypto->hash_size);
        return result > 0 ? SASL_FAIL : result;
    }
    return SASL_OK;
}

int _sasl_crypto_hash(const sasl_crypto_context_t *crypto,
                      const struct iovec *input, unsigned count,
                      unsigned char *output)
{
    if (output == NULL)
        return SASL_BADPARAM;
    if (!crypto_valid_hash_input(input, count))
        return crypto_result(crypto, SASL_BADPARAM, output);
    return crypto_result(crypto,
                         crypto->operations->hash(crypto->context, input, count,
                                                  output, crypto->hash_size),
                         output);
}

int _sasl_crypto_digest(const sasl_crypto_context_t *crypto,
                        const unsigned char *input, size_t inputlen,
                        unsigned char *output)
{
    struct iovec vector;
#ifdef _WIN32
    if (inputlen > LONG_MAX)
        return SASL_BADPARAM;
    vector.iov_len = (long)inputlen;
#else
    vector.iov_len = inputlen;
#endif
    vector.iov_base = (char *)input;
    return _sasl_crypto_hash(crypto, &vector, 1, output);
}

int _sasl_crypto_hmac(const sasl_crypto_context_t *crypto,
                      const unsigned char *key, size_t keylen,
                      const unsigned char *input, size_t inputlen,
                      unsigned char *output)
{
    if (output == NULL)
        return SASL_BADPARAM;
    if (!crypto_valid_hmac_input(key, keylen, input, inputlen))
        return crypto_result(crypto, SASL_BADPARAM, output);
    if (crypto->operations->hmac == NULL)
        return crypto_result(crypto, SASL_NOMECH, output);
    return crypto_result(crypto,
                         crypto->operations->hmac(crypto->context, key, keylen,
                                                  input, inputlen, output,
                                                  crypto->hash_size),
                         output);
}

int _sasl_crypto_pbkdf2(const sasl_crypto_context_t *crypto,
                        const unsigned char *password, size_t passwordlen,
                        const unsigned char *salt, size_t saltlen,
                        unsigned iterations, unsigned char *output)
{
    if (output == NULL)
        return SASL_BADPARAM;
    if (!crypto_valid_pbkdf2_input(password, passwordlen, salt, saltlen,
                                   iterations))
        return crypto_result(crypto, SASL_BADPARAM, output);
    if (crypto->operations->pbkdf2 == NULL)
        return crypto_result(crypto, SASL_NOMECH, output);
    return crypto_result(crypto,
                         crypto->operations->pbkdf2(
                             crypto->context, password, passwordlen, salt,
                             saltlen, iterations, output, crypto->hash_size),
                         output);
}
