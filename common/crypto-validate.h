/* Shared input validation for the library and standalone crypto adapters.
 * Copyright (c) 2026 Sergei Ilinykh.
 * Distributed under the terms in COPYING.
 */
#ifndef SASL_CRYPTO_VALIDATE_H
#define SASL_CRYPTO_VALIDATE_H

#ifndef _WIN32
#include <sys/uio.h>
#endif
#include <sasl.h>

static int crypto_valid_output(unsigned char *output, unsigned length,
                               unsigned hash_size)
{
    return output != NULL && length == hash_size;
}

static int crypto_valid_hash_input(const struct iovec *input, unsigned count)
{
    unsigned i;
    if (count && input == NULL)
        return 0;
    for (i = 0; i < count; i++) {
#ifdef _WIN32
        if (input[i].iov_len < 0)
            return 0;
#endif
        if (input[i].iov_len && input[i].iov_base == NULL)
            return 0;
    }
    return 1;
}

static int crypto_valid_hmac_input(const unsigned char *key, size_t keylen,
                                   const unsigned char *input, size_t inputlen)
{
    return !(keylen && key == NULL) && !(inputlen && input == NULL);
}

static int crypto_valid_pbkdf2_input(const unsigned char *password,
                                     size_t passwordlen,
                                     const unsigned char *salt, size_t saltlen,
                                     unsigned iterations)
{
    return iterations != 0 &&
           crypto_valid_hmac_input(password, passwordlen, salt, saltlen);
}
#endif
