/* Copyright (c) 2026 Sergei Ilinykh.
 * Distributed under the terms in COPYING.
 */
#include <config.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#ifndef _WIN32
#include <sys/uio.h>
#endif
#include "sasl_crypto.h"

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);    \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct mock {
    sasl_crypto_t operations;
    int lookup_result, select_result, operation_result;
    unsigned selected, calls, marker;
    const void *input;
    size_t inputlen;
    unsigned iterations;
} mock_t;

static int mock_hash(void *context, const struct iovec *input, unsigned count,
                     unsigned char *output, unsigned outputlen)
{
    mock_t *mock = context;
    mock->calls++;
    mock->input = count ? input[0].iov_base : NULL;
    mock->inputlen = count ? input[0].iov_len : 0;
    memset(output, mock->marker, outputlen);
    return mock->operation_result;
}

static int mock_hmac(void *context, const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t inputlen,
                     unsigned char *output, unsigned outputlen)
{
    mock_t *mock = context;
    (void)key;
    (void)keylen;
    mock->calls++;
    mock->input = input;
    mock->inputlen = inputlen;
    memset(output, mock->marker, outputlen);
    return mock->operation_result;
}

static int mock_pbkdf2(void *context, const unsigned char *password,
                       size_t passwordlen, const unsigned char *salt,
                       size_t saltlen, unsigned iterations,
                       unsigned char *output, unsigned outputlen)
{
    mock_t *mock = context;
    (void)salt;
    (void)saltlen;
    mock->calls++;
    mock->input = password;
    mock->inputlen = passwordlen;
    mock->iterations = iterations;
    memset(output, mock->marker, outputlen);
    return mock->operation_result;
}

static int mock_select(void *context, const char *algorithm,
                       const sasl_crypto_t **operations, void **crypto_context)
{
    mock_t *mock = context;
    (void)algorithm;
    mock->selected++;
    *operations = &mock->operations;
    *crypto_context = mock;
    return mock->select_result;
}

static int mock_lookup(sasl_conn_t *conn, unsigned long id,
                       sasl_callback_ft *callback, void **context)
{
    mock_t *mock = (mock_t *)conn;
    if (id != SASL_CB_CRYPTO)
        return SASL_FAIL;
    *callback = (sasl_callback_ft)mock_select;
    *context = mock;
    return mock->lookup_result;
}

static void erase(char *buffer, unsigned length)
{
    volatile char *p = buffer;
    while (length--)
        *p++ = 0;
}

static void init_mock(mock_t *mock, sasl_utils_t *utils, unsigned marker)
{
    memset(mock, 0, sizeof(*mock));
    memset(utils, 0, sizeof(*utils));
    mock->marker = marker;
    mock->operations.version = SASL_CRYPTO_VERSION;
    mock->operations.hash = mock_hash;
    mock->operations.hmac = mock_hmac;
    mock->operations.pbkdf2 = mock_pbkdf2;
    utils->conn = (sasl_conn_t *)mock;
    utils->getcallback = mock_lookup;
    utils->erasebuffer = erase;
}

static int all_bytes(const unsigned char *buffer, unsigned length,
                     unsigned byte)
{
    unsigned i;
    for (i = 0; i < length; i++)
        if (buffer[i] != byte)
            return 0;
    return 1;
}

int main(void)
{
    static const char *names[] = {"MD5",    "SHA1",   "SHA224",
                                  "SHA256", "SHA384", "SHA512"};
    static const unsigned sizes[] = {16, 20, 28, 32, 48, 64};
    mock_t a, b;
    sasl_utils_t au, bu;
    sasl_crypto_context_t ac, bc;
    struct iovec input[2];
    unsigned char output[SASL_MAX_HASH_SIZE + 2];
    const unsigned char message[] = "message";
    unsigned i, before;

    init_mock(&a, &au, 0x12);
    init_mock(&b, &bu, 0x34);
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        CHECK(_sasl_crypto_init(&au, names[i], &ac) == SASL_OK);
        CHECK(ac.hash_size == sizes[i]);
    }
    CHECK(_sasl_crypto_init(&au, "unknown", &ac) == SASL_NOMECH);
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_OK);
    CHECK(_sasl_crypto_init(&bu, "SHA512", &bc) == SASL_OK);
    input[0].iov_base = (char *)message;
    input[0].iov_len = sizeof(message) - 1;
    input[1].iov_base = NULL;
    input[1].iov_len = 0;
    memset(output, 0x55, sizeof(output));
    CHECK(_sasl_crypto_hash(&ac, input, 2, output + 1) == SASL_OK);
    CHECK(a.input == message && a.inputlen == sizeof(message) - 1);
    CHECK(all_bytes(output + 1, 32, 0x12));
    CHECK(output[0] == 0x55 && output[33] == 0x55);
    CHECK(_sasl_crypto_digest(&bc, message, sizeof(message) - 1, output) ==
          SASL_OK);
    CHECK(all_bytes(output, 64, 0x34));
    CHECK(a.calls == 1 && b.calls == 1);
    CHECK(_sasl_crypto_hash(&ac, NULL, 0, output) == SASL_OK);
    CHECK(_sasl_crypto_hmac(&ac, NULL, 0, NULL, 0, output) == SASL_OK);
    before = a.calls;
    CHECK(_sasl_crypto_pbkdf2(&ac, message, 7, message, 7, 4096, output) ==
          SASL_OK);
    CHECK(a.calls == before + 1 && a.iterations == 4096);
    CHECK(a.input == message && a.inputlen == 7);

    before = a.calls;
    CHECK(_sasl_crypto_hmac(&ac, NULL, 1, message, 7, output) == SASL_BADPARAM);
    CHECK(_sasl_crypto_digest(&ac, NULL, 1, output) == SASL_BADPARAM);
    CHECK(_sasl_crypto_hash(&ac, NULL, 1, output) == SASL_BADPARAM);
    CHECK(_sasl_crypto_hash(&ac, input, 2, NULL) == SASL_BADPARAM);
    CHECK(_sasl_crypto_pbkdf2(&ac, message, 7, message, 7, 0, output) ==
          SASL_BADPARAM);
#ifdef _WIN32
    input[0].iov_len = -1;
    CHECK(_sasl_crypto_hash(&ac, input, 1, output) == SASL_BADPARAM);
#endif
    CHECK(a.calls == before);

    a.operation_result = SASL_NOMEM;
    memset(output, 0x55, sizeof(output));
    CHECK(_sasl_crypto_digest(&ac, message, 7, output + 1) == SASL_NOMEM);
    CHECK(all_bytes(output + 1, 32, 0));
    CHECK(output[0] == 0x55 && output[33] == 0x55);
    memset(output, 0x55, sizeof(output));
    CHECK(_sasl_crypto_hmac(&ac, message, 7, message, 7, output) == SASL_NOMEM);
    CHECK(all_bytes(output, 32, 0));
    memset(output, 0x55, sizeof(output));
    CHECK(_sasl_crypto_pbkdf2(&ac, message, 7, message, 7, 1, output) ==
          SASL_NOMEM);
    CHECK(all_bytes(output, 32, 0));
    a.operation_result = SASL_CONTINUE;
    CHECK(_sasl_crypto_digest(&ac, message, 7, output) == SASL_FAIL);
    CHECK(all_bytes(output, 32, 0));
    a.operations.hmac = NULL;
    CHECK(_sasl_crypto_hmac(&ac, NULL, 0, NULL, 0, output) == SASL_NOMECH);
    a.operations.pbkdf2 = NULL;
    CHECK(_sasl_crypto_pbkdf2(&ac, NULL, 0, NULL, 0, 1, output) == SASL_NOMECH);

    a.select_result = SASL_NOMECH;
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_NOMECH);
    a.select_result = SASL_NOMEM;
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_NOMEM);
    a.select_result = SASL_INTERACT;
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_BADPARAM);
    a.select_result = SASL_OK;
    a.operations.version++;
    a.operations.hash = NULL;
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_BADVERS);
    a.operations.version = SASL_CRYPTO_VERSION;
    a.operations.hash = NULL;
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_BADPARAM);
    a.lookup_result = SASL_INTERACT;
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_BADPARAM);
    a.lookup_result = SASL_NOMEM;
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_NOMEM);
    a.lookup_result = SASL_FAIL;
#ifdef HAVE_OPENSSL
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_OK);
    {
        static const unsigned char hash[] = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
            0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
            0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
        static const unsigned char mac[] = {
            0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec, 0x77, 0x2f, 0x95,
            0xd7, 0x78, 0xc3, 0x5f, 0xc5, 0xff, 0x16, 0x97, 0xc4, 0x93, 0x71,
            0x56, 0x53, 0xc6, 0xc7, 0x12, 0x14, 0x42, 0x92, 0xc5, 0xad};
        static const unsigned char derived[] = {
            0xf7, 0xce, 0x0b, 0x65, 0x3d, 0x2d, 0x72, 0xa4, 0x10, 0x8c, 0xf5,
            0xab, 0xe9, 0x12, 0xff, 0xdd, 0x77, 0x76, 0x16, 0xdb, 0xbb, 0x27,
            0xa7, 0x0e, 0x82, 0x04, 0xf3, 0xae, 0x2d, 0x0f, 0x6f, 0xad};
        input[0].iov_base = "a";
        input[0].iov_len = 1;
        input[1].iov_base = "bc";
        input[1].iov_len = 2;
        CHECK(_sasl_crypto_hash(&ac, input, 2, output) == SASL_OK);
        CHECK(!memcmp(output, hash, sizeof(hash)));
        CHECK(_sasl_crypto_hmac(&ac, NULL, 0, NULL, 0, output) == SASL_OK);
        CHECK(!memcmp(output, mac, sizeof(mac)));
        CHECK(_sasl_crypto_pbkdf2(&ac, NULL, 0, NULL, 0, 1, output) == SASL_OK);
        CHECK(!memcmp(output, derived, sizeof(derived)));
        CHECK(_sasl_crypto_hmac(&ac, message, (size_t)INT_MAX + 1, NULL, 0,
                                output) == SASL_BADPARAM);
        CHECK(all_bytes(output, 32, 0));
        CHECK(_sasl_crypto_pbkdf2(&ac, message, (size_t)INT_MAX + 1, NULL, 0, 1,
                                  output) == SASL_BADPARAM);
        CHECK(all_bytes(output, 32, 0));
    }
#else
    CHECK(_sasl_crypto_init(&au, "SHA256", &ac) == SASL_NOMECH);
#endif
    puts("crypto callback tests passed");
    return 0;
}
