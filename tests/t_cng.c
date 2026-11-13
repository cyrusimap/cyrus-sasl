/* Windows CNG known-answer, input validation and concurrency tests.
 * Copyright (c) 2026 Sergei Ilinykh.
 * Distributed under the terms in COPYING.
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "crypto-cng.h"

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
            return 1; \
        } \
    } while (0)

typedef struct vector {
    const char *name;
    unsigned size;
    const char *hash, *empty_hash, *mac, *empty_mac, *derived, *empty_derived;
} vector_t;

/* Fixed answers cover binary, length-delimited passwords, keys and salts.
 * They were generated independently using Python's hashlib and hmac modules.
 */
static const vector_t vectors[] = {
    {"MD5", 16,
     "900150983cd24fb0d6963f7d28e17f72",
     "d41d8cd98f00b204e9800998ecf8427e",
     "e382b8d5f6d69e819c13d76dea61cf58",
     "74e6f7298a9c2d168935f58c001bad88",
     "d1ee95373653c9b212aa52feb209b4dd",
     "9c627ef8f3723c914c7bf25e2344a8ed"},
    {"SHA1", 20,
     "a9993e364706816aba3e25717850c26c9cd0d89d",
     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "7a203b6fb9e0bc42cd8d09ce8b8832c05765df44",
     "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
     "a7a082557353f038493626104a228fd3698fd815",
     "1e437a1c79d75be61e91141dae20affc4892cc99"},
    {"SHA256", 32,
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "bd7678cc9e2aa580ccbb75d0c4d29d286e1af0b6789fe779052c4014e322ed99",
     "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
     "3055afee1cf5b5deda6926d97aba0988a51be8e327ba9cf646d2281ed4306ce0",
     "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad"},
    {"SHA384", 48,
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
     "3a883ab7983ba572751b9de0aa4f5cdf97f6c652c3dcb02fb435afc890178eca6f565d2f6655eef7a671b4921fbfb90f",
     "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc",
     "41e4cd23507f1d619292455d03112e9d68de8c641dcba5ff9965744cbba3f8c442d2150f39ebc2d6979f76b4fe26dbdc",
     "4bb042a5c28cee6f66f991c717fd770267787e2bb3031eae270d87d63ad99534f70873bfc8f78b914c7134975cfecb24"},
    {"SHA512", 64,
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
     "1212480792289a3fb27a1578c400a17937a752662ca80932421424bc4a9c7d2f2c4e293ac3d851eeab65367a5cd009121b81660eae0610e776fd988d784f172f",
     "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
     "bef9659390a058ad5f16f9f4f6013b5896a59c44337118fd7af068968b5c2ea880b66d9c1bee17fd173e608d64136f4926178449f7c6180cd0e86045125eddc0",
     "6d2ecbbbfb2e6dcd7056faf9af6aa06eae594391db983279a6bf27e0eb2286143ab0c996f33ca4b667e945829ea693340f2831797324e5f31df18ed171d18c97"}
};

static int equal_hex(const unsigned char *output, const char *expected)
{
    static const char digits[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; expected[2 * i]; i++) {
        if (digits[output[i] >> 4] != expected[2 * i] ||
            digits[output[i] & 15] != expected[2 * i + 1])
            return 0;
    }
    return 1;
}

static int zero(const unsigned char *output, unsigned length)
{
    unsigned i;
    for (i = 0; i < length; i++) {
        if (output[i])
            return 0;
    }
    return 1;
}

static int answers(const vector_t *v)
{
    const sasl_crypto_t *ops = NULL;
    void *context = NULL;
    unsigned char output[66];
    const unsigned char key[] = "k\0ey\xff";
    const unsigned char message[] = "m\0essage\x80";
    const unsigned char password[] = "p\0assword\xff";
    const unsigned char salt[] = "s\0alt\x80";
    struct iovec input[3];

    CHECK(_sasl_cng_getcrypto(NULL, v->name, &ops, &context) == SASL_OK);
    CHECK(ops && context && ops->version == SASL_CRYPTO_VERSION);
    memset(output, 0xa5, sizeof(output));
    input[0].iov_base = "a";
    input[0].iov_len = 1;
    input[1].iov_base = NULL;
    input[1].iov_len = 0;
    input[2].iov_base = "bc";
    input[2].iov_len = 2;
    CHECK(ops->hash(context, input, 3, output + 1, v->size) == SASL_OK);
    CHECK(equal_hex(output + 1, v->hash));
    CHECK(output[0] == 0xa5 && output[v->size + 1] == 0xa5);
    CHECK(ops->hash(context, NULL, 0, output + 1, v->size) == SASL_OK);
    CHECK(equal_hex(output + 1, v->empty_hash));
    CHECK(ops->hmac(context, key, sizeof(key) - 1, message,
                    sizeof(message) - 1, output + 1, v->size) == SASL_OK);
    CHECK(equal_hex(output + 1, v->mac));
    CHECK(ops->hmac(context, NULL, 0, NULL, 0, output + 1, v->size) == SASL_OK);
    CHECK(equal_hex(output + 1, v->empty_mac));
    CHECK(ops->pbkdf2(context, password, sizeof(password) - 1, salt,
                      sizeof(salt) - 1, 4096, output + 1, v->size) == SASL_OK);
    CHECK(equal_hex(output + 1, v->derived));
    CHECK(ops->pbkdf2(context, NULL, 0, NULL, 0, 1, output + 1, v->size) == SASL_OK);
    CHECK(equal_hex(output + 1, v->empty_derived));
    CHECK(output[0] == 0xa5 && output[v->size + 1] == 0xa5);
    CHECK(ops->hash(context, NULL, 1, output + 1, v->size) == SASL_BADPARAM);
    CHECK(zero(output + 1, v->size));
    input[0].iov_len = -1;
    CHECK(ops->hash(context, input, 1, output + 1, v->size) == SASL_BADPARAM);
    input[0].iov_len = 1;
    input[0].iov_base = NULL;
    CHECK(ops->hash(context, input, 1, output + 1, v->size) == SASL_BADPARAM);
    CHECK(ops->hmac(context, NULL, 1, message, sizeof(message) - 1,
                    output + 1, v->size) == SASL_BADPARAM);
    CHECK(ops->hmac(context, key, sizeof(key) - 1, NULL, 1,
                    output + 1, v->size) == SASL_BADPARAM);
    CHECK(ops->pbkdf2(context, NULL, 1, NULL, 0, 1,
                      output + 1, v->size) == SASL_BADPARAM);
    CHECK(ops->pbkdf2(context, NULL, 0, NULL, 1, 1,
                      output + 1, v->size) == SASL_BADPARAM);
    CHECK(ops->pbkdf2(context, NULL, 0, NULL, 0, 0,
                      output + 1, v->size) == SASL_BADPARAM);
#if defined(_WIN64)
    CHECK(ops->hmac(context, key, (size_t)ULONG_MAX + 1, NULL, 0,
                    output + 1, v->size) == SASL_BADPARAM);
    CHECK(ops->pbkdf2(context, password, (size_t)ULONG_MAX + 1, NULL, 0, 1,
                      output + 1, v->size) == SASL_BADPARAM);
    CHECK(ops->pbkdf2(context, NULL, 0, salt, (size_t)ULONG_MAX + 1, 1,
                      output + 1, v->size) == SASL_BADPARAM);
#endif
    CHECK(ops->hash(context, NULL, 0, NULL, v->size) == SASL_BADPARAM);
    CHECK(ops->hmac(context, NULL, 0, NULL, 0, NULL, v->size) == SASL_BADPARAM);
    CHECK(ops->pbkdf2(context, NULL, 0, NULL, 0, 1, NULL, v->size) == SASL_BADPARAM);
    memset(output, 0xa5, sizeof(output));
    CHECK(ops->hash(context, NULL, 0, output + 1, v->size - 1) == SASL_BADPARAM);
    CHECK(ops->hmac(context, NULL, 0, NULL, 0, output + 1, v->size + 1) == SASL_BADPARAM);
    CHECK(ops->pbkdf2(context, NULL, 0, NULL, 0, 1, output + 1, v->size + 1) == SASL_BADPARAM);
    CHECK(output[0] == 0xa5 && output[1] == 0xa5 && output[v->size + 1] == 0xa5);
    return 0;
}

static int large_message(void)
{
    const sasl_crypto_t *ops;
    void *context;
    struct iovec input[64];
    unsigned char output[32], key[257];
    char *chunk = malloc(1024 * 1024);
    unsigned i;
    CHECK(chunk != NULL);
    memset(chunk, 0xa5, 1024 * 1024);
    for (i = 0; i < 64; i++) {
        input[i].iov_base = chunk;
        input[i].iov_len = 1024 * 1024;
    }
    CHECK(_sasl_cng_getcrypto(NULL, "SHA256", &ops, &context) == SASL_OK);
    CHECK(ops->hash(context, input, 64, output, sizeof(output)) == SASL_OK);
    free(chunk);
    CHECK(equal_hex(output,
        "1c5386005b9cc63833a7cac9ee928040d05d4128b81715d893f2e2fb2a3391b7"));
    memset(key, 0xa5, sizeof(key));
    CHECK(ops->hmac(context, key, sizeof(key), (const unsigned char *)"abc",
                    3, output, sizeof(output)) == SASL_OK);
    CHECK(equal_hex(output,
        "f8b99dbc1df2f48f34b43c1553c049ed209ff092486476c52a855ed9249f512a"));
    return 0;
}

static DWORD WINAPI concurrent_answers(void *unused)
{
    unsigned i;
    (void)unused;
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        if (answers(&vectors[i]))
            return 1;
    }
    return 0;
}

int main(void)
{
    const sasl_crypto_t *ops = NULL;
    void *context = NULL;
    HANDLE threads[4];
    DWORD result;
    unsigned i;
    CHECK(_sasl_cng_getcrypto(NULL, NULL, &ops, &context) == SASL_BADPARAM);
    CHECK(_sasl_cng_getcrypto(NULL, "SHA256", NULL, &context) == SASL_BADPARAM);
    CHECK(_sasl_cng_getcrypto(NULL, "SHA256", &ops, NULL) == SASL_BADPARAM);
    CHECK(_sasl_cng_getcrypto(NULL, "SHA224", &ops, &context) == SASL_NOMECH);
    CHECK(ops == NULL && context == NULL);
    CHECK(_sasl_cng_getcrypto(NULL, "unknown", &ops, &context) == SASL_NOMECH);
    CHECK(_sasl_cng_getcrypto(NULL, "sha256", &ops, &context) == SASL_NOMECH);
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++)
        CHECK(answers(&vectors[i]) == 0);
    CHECK(large_message() == 0);
    for (i = 0; i < 4; i++) {
        threads[i] = CreateThread(NULL, 0, concurrent_answers, NULL, 0, NULL);
        CHECK(threads[i] != NULL);
    }
    CHECK(WaitForMultipleObjects(4, threads, TRUE, 30000) == WAIT_OBJECT_0);
    for (i = 0; i < 4; i++) {
        CHECK(GetExitCodeThread(threads[i], &result));
        CloseHandle(threads[i]);
        CHECK(result == 0);
    }
    puts("CNG known-answer, boundary, streaming and concurrency tests passed");
    return 0;
}
