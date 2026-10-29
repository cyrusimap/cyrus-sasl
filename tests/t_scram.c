/* Copyright (c) 2026 Sergei Ilinykh.
 * Distributed under the terms in COPYING.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/uio.h>
#endif
#include "sasl_crypto.h"
#include <saslutil.h>
#include <prop.h>

#if defined(HAVE_OPENSSL) || defined(TEST_EXTERNAL_CRYPTO)

extern sasl_client_plug_init_t scram_client_plug_init;
extern sasl_server_plug_init_t scram_server_plug_init;
#ifdef TEST_EXTERNAL_CRYPTO
extern sasl_getcrypto_t test_external_crypto;
#endif

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);    \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

typedef struct backend backend_t;
typedef struct binding {
    backend_t *backend;
    const sasl_crypto_t *operations;
    void *context;
} binding_t;

struct backend {
    binding_t bindings[6];
    const char *only_algorithm;
    const char *password;
    unsigned hash_calls, hmac_calls, pbkdf2_calls;
    int fail_operation;
    struct {
        unsigned long len;
        unsigned char data[32];
    } secret;
};

static int test_hash(void *context, const struct iovec *input, unsigned count,
                     unsigned char *output, unsigned outputlen)
{
    int result;
    binding_t *binding = context;
    backend_t *backend = binding->backend;
    backend->hash_calls++;
    if (backend->fail_operation == 1)
        return SASL_NOMEM;
    result = binding->operations->hash(binding->context, input, count, output,
                                       outputlen);
    return result;
}

static int test_hmac(void *context, const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t inputlen,
                     unsigned char *output, unsigned outputlen)
{
    int result;
    binding_t *binding = context;
    backend_t *backend = binding->backend;
    backend->hmac_calls++;
    if (backend->fail_operation == 2)
        return SASL_NOMEM;
    result = binding->operations->hmac(binding->context, key, keylen, input,
                                       inputlen, output, outputlen);
    return result;
}

static int test_pbkdf2(void *context, const unsigned char *password,
                       size_t passwordlen, const unsigned char *salt,
                       size_t saltlen, unsigned iterations,
                       unsigned char *output, unsigned outputlen)
{
    int result;
    binding_t *binding = context;
    backend_t *backend = binding->backend;
    backend->pbkdf2_calls++;
    if (backend->fail_operation == 3)
        return SASL_NOMEM;
    result = binding->operations->pbkdf2(binding->context, password,
                                         passwordlen, salt, saltlen, iterations,
                                         output, outputlen);
    return result;
}

static const sasl_crypto_t test_operations = {SASL_CRYPTO_VERSION, test_hash,
                                              test_hmac, test_pbkdf2};

static int test_select(void *context, const char *algorithm,
                       const sasl_crypto_t **operations, void **crypto_context)
{
    backend_t *backend = context;
    static const char *names[] = {"MD5",    "SHA1",   "SHA224",
                                  "SHA256", "SHA384", "SHA512"};
    unsigned i;
    binding_t *binding = NULL;
    int result;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (!strcmp(algorithm, names[i]))
            binding = &backend->bindings[i];
    }
    if (binding == NULL)
        return SASL_NOMECH;
    binding->backend = backend;
    if (backend->only_algorithm && strcmp(backend->only_algorithm, algorithm))
        return SASL_NOMECH;
#ifdef TEST_EXTERNAL_CRYPTO
    result = test_external_crypto(NULL, algorithm, &binding->operations,
                                  &binding->context);
#else
    result = _sasl_crypto_default(NULL, algorithm, &binding->operations,
                                  &binding->context);
#endif
    if (result != SASL_OK)
        return result;
    *operations = &test_operations;
    *crypto_context = binding;
    return SASL_OK;
}

static int test_simple(void *context, int id, const char **result,
                       unsigned *len)
{
    backend_t *backend = context;
    (void)backend;
    *result = id == SASL_CB_AUTHNAME ? "user" : "";
    if (*result == NULL)
        return SASL_FAIL;
    if (len)
        *len = (unsigned)strlen(*result);
    return SASL_OK;
}

static int test_password(sasl_conn_t *conn, void *context, int id,
                         sasl_secret_t **secret)
{
    backend_t *backend = context;
    (void)conn;
    (void)id;
    backend->secret.len = (unsigned long)strlen(backend->password);
    memcpy(backend->secret.data, backend->password, backend->secret.len + 1);
    *secret = (sasl_secret_t *)&backend->secret;
    return SASL_OK;
}

static int test_path(void *context, const char **path)
{
    (void)context;
    *path = "";
    return SASL_OK;
}

static int test_confpath(void *context, char **path)
{
    (void)context;
    *path = malloc(1);
    if (*path == NULL)
        return SASL_NOMEM;
    **path = '\0';
    return SASL_OK;
}

static int test_verify(void *context, const char *file, sasl_verify_type_t type)
{
    (void)context;
    (void)file;
    (void)type;
    return SASL_CONTINUE;
}

static int test_option(void *context, const char *plugin, const char *option,
                       const char **result, unsigned *len)
{
    (void)context;
    (void)plugin;
    if (!strcmp(option, "auxprop_plugin"))
        *result = "scram-test";
    else if (!strcmp(option, "pwcheck_method"))
        *result = "auxprop";
    else if (!strcmp(option, "scram_iteration_counter"))
        *result = "4096";
    else if (!strcmp(option, "scram_secret_generate"))
        *result = "yes";
    else
        return SASL_FAIL;
    if (len)
        *len = (unsigned)strlen(*result);
    return SASL_OK;
}

static void callbacks(sasl_callback_t *cb, backend_t *backend, int custom)
{
    static const unsigned long ids[] = {
        SASL_CB_GETPATH,     SASL_CB_VERIFYFILE, SASL_CB_GETOPT,
        SASL_CB_AUTHNAME,    SASL_CB_USER,       SASL_CB_PASS,
        SASL_CB_GETCONFPATH, SASL_CB_CRYPTO,     SASL_CB_LIST_END};
    unsigned i;
    for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        cb[i].id = ids[i];
        cb[i].context = backend;
        cb[i].proc = NULL;
    }
    cb[0].proc = (sasl_callback_ft)test_path;
    cb[1].proc = (sasl_callback_ft)test_verify;
    cb[2].proc = (sasl_callback_ft)test_option;
    cb[3].proc = cb[4].proc = (sasl_callback_ft)test_simple;
    cb[5].proc = (sasl_callback_ft)test_password;
    cb[6].proc = (sasl_callback_ft)test_confpath;
    cb[7].proc = (sasl_callback_ft)test_select;
    if (!custom)
        cb[7].id = SASL_CB_LIST_END;
}

/* Salt, NUL, then MD5(salt || "sasldb" || "pencil"). */
static const char legacy_secret[] =
    "0123456789abcdef\0"
    "\xe1\xdd\x2c\xc2\xab\x71\x5d\x8d\x21\xa1\xa0\x62\xe5\x29\xc1\xd4";
static int use_legacy_secret;
static char stored_secret[512];
static unsigned stored_count;
static int use_stored_secret, create_stored_secret, store_failure;

static int test_lookup(void *context, sasl_server_params_t *params,
                       unsigned flags, const char *user, unsigned ulen)
{
    (void)context;
    if (flags & SASL_AUXPROP_AUTHZID)
        return SASL_OK;
    if (ulen < 4 || memcmp(user, "user", 4))
        return SASL_NOUSER;
    if (use_stored_secret)
        return params->utils->prop_set(params->propctx, "*authPassword",
                                       stored_secret,
                                       (int)strlen(stored_secret));
    if (use_legacy_secret)
        return params->utils->prop_set(params->propctx, "*cmusaslsecretPLAIN",
                                       legacy_secret,
                                       sizeof(legacy_secret) - 1);
    return params->utils->prop_set(params->propctx, SASL_AUX_PASSWORD, "pencil",
                                   6);
}

static int test_store(void *context, sasl_server_params_t *params,
                      struct propctx *properties, const char *user,
                      unsigned ulen)
{
    const char *requested[] = {"authPassword", NULL};
    struct propval values[2];
    (void)context;
    (void)params;
    (void)user;
    (void)ulen;
    if (properties == NULL)
        return SASL_OK;
    if (prop_getnames(properties, requested, values) < 0)
        return SASL_FAIL;
    if (values[0].values == NULL)
        return SASL_BADPARAM;
    CHECK(strlen(values[0].values[0]) < sizeof(stored_secret));
    strcpy(stored_secret, values[0].values[0]);
    stored_count++;
    return SASL_OK;
}

static sasl_auxprop_plug_t test_auxprop = {
    0, 0, NULL, NULL, test_lookup, "scram-test", test_store};

static int test_auxprop_init(const sasl_utils_t *utils, int max_version,
                             int *version, sasl_auxprop_plug_t **plug,
                             const char *name)
{
    (void)utils;
    (void)name;
    if (max_version < SASL_AUXPROP_PLUG_VERSION)
        return SASL_BADVERS;
    *version = SASL_AUXPROP_PLUG_VERSION;
    *plug = &test_auxprop;
    return SASL_OK;
}

static void init_backend(backend_t *backend)
{
    memset(backend, 0, sizeof(*backend));
    backend->password = "pencil";
}

/* The calculations from RFC 5802 section 5 and RFC 7677 section 3. */
static void rfc_vector(const char *algorithm, unsigned size, const char *nonce,
                       const char *challenge, const char *proof,
                       const char *signature)
{
    backend_t backend;
    const sasl_crypto_t *ops;
    void *context;
    unsigned char salt[64], salted[64], client_key[64], stored_key[64];
    unsigned char client_signature[64], server_key[64], server_signature[64];
    char auth_message[1024], encoded[128];
    const char *s = strstr(challenge, ",s=") + 3;
    const char *end = strchr(s, ',');
    unsigned saltlen, i;
    int length;

    init_backend(&backend);
    CHECK(test_select(&backend, algorithm, &ops, &context) == SASL_OK);
    CHECK(sasl_decode64(s, (unsigned)(end - s), (char *)salt, sizeof(salt),
                        &saltlen) == SASL_OK);
    length =
        sprintf(auth_message, "n=user,r=%s,%s,c=biws,%.*s", nonce, challenge,
                (int)(strstr(challenge, ",s=") - challenge), challenge);
    CHECK(ops->pbkdf2(context, (const unsigned char *)"pencil", 6, salt,
                      saltlen, 4096, salted, size) == SASL_OK);
    CHECK(ops->hmac(context, salted, size, (const unsigned char *)"Client Key",
                    10, client_key, size) == SASL_OK);
    {
        struct iovec input;
        input.iov_base = (char *)client_key;
        input.iov_len = size;
        CHECK(ops->hash(context, &input, 1, stored_key, size) == SASL_OK);
    }
    CHECK(ops->hmac(context, stored_key, size,
                    (const unsigned char *)auth_message, length,
                    client_signature, size) == SASL_OK);
    for (i = 0; i < size; i++)
        client_signature[i] ^= client_key[i];
    CHECK(sasl_encode64((const char *)client_signature, size, encoded,
                        sizeof(encoded), NULL) == SASL_OK);
    CHECK(!strcmp(encoded, proof));
    CHECK(ops->hmac(context, salted, size, (const unsigned char *)"Server Key",
                    10, server_key, size) == SASL_OK);
    CHECK(ops->hmac(context, server_key, size,
                    (const unsigned char *)auth_message, length,
                    server_signature, size) == SASL_OK);
    CHECK(sasl_encode64((const char *)server_signature, size, encoded,
                        sizeof(encoded), NULL) == SASL_OK);
    CHECK(!strcmp(encoded, signature));
    CHECK(backend.pbkdf2_calls == 1);
}

static void round_trip(const char *mechanism, int custom_client,
                       int custom_server, int bad_password, int bad_binding,
                       int server_failure, int client_failure,
                       int corrupt_signature)
{
    backend_t client_backend, server_backend;
    sasl_callback_t cc[9], sc[9];
    sasl_conn_t *client = NULL, *server = NULL;
    sasl_interact_t *interact = NULL;
    sasl_channel_binding_t client_binding, server_binding;
    const unsigned char binding[] = "test channel binding data";
    const unsigned char different[] = "other channel binding data";
    const char *out, *chosen, *reply;
    unsigned len, replylen;
    int result, plus = strstr(mechanism, "-PLUS") != NULL;

    init_backend(&client_backend);
    init_backend(&server_backend);
    if (bad_password)
        client_backend.password = "wrong password";
    server_backend.fail_operation = server_failure;
    client_backend.fail_operation = client_failure;
    callbacks(cc, &client_backend, custom_client);
    callbacks(sc, &server_backend, custom_server);
    CHECK(sasl_client_new("test", "localhost", NULL, NULL, cc,
                          SASL_SUCCESS_DATA, &client) == SASL_OK);
    CHECK(sasl_server_new("test", "localhost", NULL, NULL, NULL, sc,
                          SASL_SUCCESS_DATA, &server) == SASL_OK);
    if (plus) {
        memset(&client_binding, 0, sizeof(client_binding));
        client_binding.name = "tls-exporter";
        client_binding.critical = 1;
        client_binding.data = binding;
        client_binding.len = sizeof(binding) - 1;
        server_binding = client_binding;
        if (bad_binding) {
            server_binding.data = different;
            server_binding.len = sizeof(different) - 1;
        }
        CHECK(sasl_setprop(client, SASL_CHANNEL_BINDING, &client_binding) ==
              SASL_OK);
        CHECK(sasl_setprop(server, SASL_CHANNEL_BINDING, &server_binding) ==
              SASL_OK);
    }
    CHECK(sasl_client_start(client, mechanism, &interact, &out, &len,
                            &chosen) == SASL_CONTINUE);
    CHECK(strlen(chosen) == strlen(mechanism) - (plus ? 5 : 0));
    CHECK(!strncmp(chosen, mechanism, strlen(chosen)));
    if (plus)
        CHECK(len >= 16 && !memcmp(out, "p=tls-exporter,,", 16));
    result = sasl_server_start(server, mechanism, out, len, &reply, &replylen);
    if (server_failure) {
        CHECK(result == SASL_NOMEM);
        goto done;
    }
    if (result != SASL_CONTINUE)
        fprintf(stderr, "server start: %d %s\n", result,
                sasl_errdetail(server));
    CHECK(result == SASL_CONTINUE);
    result = sasl_client_step(client, reply, replylen, &interact, &out, &len);
    if (client_failure) {
        CHECK(result == SASL_NOMEM);
        goto done;
    }
    CHECK(result == SASL_CONTINUE);
    result = sasl_server_step(server, out, len, &reply, &replylen);
    if (bad_password || bad_binding) {
        CHECK(result == (bad_binding ? SASL_BADPROT : SASL_BADAUTH));
    } else {
        if (result != SASL_OK)
            fprintf(stderr, "server step: %d %s\n", result,
                    sasl_errdetail(server));
        CHECK(result == SASL_OK);
        if (corrupt_signature) {
            char corrupted[128];
            CHECK(replylen < sizeof(corrupted));
            memcpy(corrupted, reply, replylen);
            corrupted[2] = corrupted[2] == 'a' ? 'b' : 'a';
            CHECK(sasl_client_step(client, corrupted, replylen, &interact, &out,
                                   &len) == SASL_BADAUTH);
        } else {
            CHECK(sasl_client_step(client, reply, replylen, &interact, &out,
                                   &len) == SASL_OK);
        }
    }
    if (create_stored_secret) {
        server_backend.fail_operation = store_failure;
        result = sasl_setpass(server, "user", "pencil", 6, NULL, 0,
                              SASL_SET_NOPLAIN | SASL_SET_CURMECH_ONLY);
        CHECK(result == (store_failure ? SASL_NOMEM : SASL_OK));
    }
done:
    sasl_dispose(&client);
    sasl_dispose(&server);
}

static void interleaved_exchanges(void)
{
    backend_t client_backend, server_backend;
    sasl_callback_t cc[9], sc[9];
    sasl_conn_t *clients[2] = {NULL, NULL}, *servers[2] = {NULL, NULL};
    const char *mechanisms[2] = {"SCRAM-SHA-1", "SCRAM-SHA-256"};
    const char *output[2], *reply[2], *chosen;
    unsigned length[2], replylen[2], i;
    sasl_interact_t *interact = NULL;
    init_backend(&client_backend);
    init_backend(&server_backend);
    callbacks(cc, &client_backend, 1);
    callbacks(sc, &server_backend, 1);
    for (i = 0; i < 2; i++) {
        CHECK(sasl_client_new("test", "localhost", NULL, NULL, cc,
                              SASL_SUCCESS_DATA, &clients[i]) == SASL_OK);
        CHECK(sasl_server_new("test", "localhost", NULL, NULL, NULL, sc,
                              SASL_SUCCESS_DATA, &servers[i]) == SASL_OK);
        CHECK(sasl_client_start(clients[i], mechanisms[i], &interact,
                                &output[i], &length[i],
                                &chosen) == SASL_CONTINUE);
        CHECK(sasl_server_start(servers[i], mechanisms[i], output[i], length[i],
                                &reply[i], &replylen[i]) == SASL_CONTINUE);
    }
    for (i = 0; i < 2; i++)
        CHECK(sasl_client_step(clients[i], reply[i], replylen[i], &interact,
                               &output[i], &length[i]) == SASL_CONTINUE);
    for (i = 0; i < 2; i++) {
        CHECK(sasl_server_step(servers[i], output[i], length[i], &reply[i],
                               &replylen[i]) == SASL_OK);
        CHECK(sasl_client_step(clients[i], reply[i], replylen[i], &interact,
                               &output[i], &length[i]) == SASL_OK);
        sasl_dispose(&clients[i]);
        sasl_dispose(&servers[i]);
    }
}

static void check_passwords(void)
{
    backend_t backend;
    sasl_callback_t cb[9];
    sasl_conn_t *server = NULL;
    init_backend(&backend);
    callbacks(cb, &backend, 1);
    use_legacy_secret = 1;
    CHECK(sasl_server_new("test", "localhost", NULL, NULL, NULL, cb, 0,
                          &server) == SASL_OK);
    {
        int result = sasl_checkpass(server, "user", 4, "pencil", 6);
        if (result != SASL_OK)
            fprintf(stderr, "legacy checkpass: %d %s\n", result,
                    sasl_errdetail(server));
        CHECK(result == SASL_OK);
    }
    CHECK(backend.hash_calls > 0);
    CHECK(sasl_checkpass(server, "user", 4, "wrong", 5) == SASL_BADAUTH);
    backend.fail_operation = 1;
    CHECK(sasl_checkpass(server, "user", 4, "pencil", 6) != SASL_OK);
    sasl_dispose(&server);
    use_legacy_secret = 0;
#ifdef DO_SASL_CHECKAPOP
    {
        const char challenge[] = "<test-challenge@localhost>";
        const char response[] = "user 9c9dd79643abe2f804878fa6cf92760a";
        const char *requested[] = {SASL_AUX_PASSWORD, NULL};
        struct propval values[2];
        unsigned i;
        for (i = 0; i < 3; i++) {
            init_backend(&backend);
            callbacks(cb, &backend, 1);
            if (i == 2)
                backend.fail_operation = 1;
            CHECK(sasl_server_new("test", "localhost", NULL, NULL, NULL, cb, 0,
                                  &server) == SASL_OK);
            CHECK(
                sasl_checkapop(
                    server, challenge, sizeof(challenge) - 1,
                    i == 1 ? "user 00000000000000000000000000000000" : response,
                    sizeof(response) - 1) == (i == 0   ? SASL_OK
                                              : i == 1 ? SASL_BADAUTH
                                                       : SASL_NOMEM));
            CHECK(prop_getnames(sasl_auxprop_getctx(server), requested,
                                values) >= 0);
            CHECK(values[0].values == NULL);
            sasl_dispose(&server);
        }
    }
#endif
}

static void saved_credentials(void)
{
    unsigned i, previous;
    static const char *mechanisms[] = {"SCRAM-SHA-1", "SCRAM-SHA-256",
                                       "SCRAM-SHA-384", "SCRAM-SHA-512"};
    for (i = 0; i < sizeof(mechanisms) / sizeof(mechanisms[0]); i++) {
        create_stored_secret = 1;
        round_trip(mechanisms[i], 1, 1, 0, 0, 0, 0, 0);
        CHECK(stored_count > 0);
        create_stored_secret = 0;
        use_stored_secret = 1;
#ifdef HAVE_OPENSSL
        round_trip(mechanisms[i], 1, 0, 0, 0, 0, 0, 0);
#else
        round_trip(mechanisms[i], 1, 1, 0, 0, 0, 0, 0);
#endif
        use_stored_secret = 0;
#ifdef HAVE_OPENSSL
        create_stored_secret = 1;
        round_trip(mechanisms[i], 1, 0, 0, 0, 0, 0, 0);
        create_stored_secret = 0;
        use_stored_secret = 1;
        round_trip(mechanisms[i], 0, 1, 0, 0, 0, 0, 0);
        use_stored_secret = 0;
#endif
    }
    previous = stored_count;
    create_stored_secret = 1;
    for (i = 1; i <= 3; i++) {
        store_failure = i;
        round_trip("SCRAM-SHA-256", 1, 1, 0, 0, 0, 0, 0);
        CHECK(stored_count == previous);
    }
    create_stored_secret = store_failure = 0;
    sasl_erasebuffer(stored_secret, sizeof(stored_secret));
}

static void mechanism_filter(void)
{
    backend_t a, b;
    sasl_callback_t ac[9], bc[9];
    sasl_conn_t *as = NULL, *bs = NULL;
    const char *list;
    unsigned len;
    int count;
    init_backend(&a);
    init_backend(&b);
    a.only_algorithm = "SHA1";
    b.only_algorithm = "SHA256";
    callbacks(ac, &a, 1);
    callbacks(bc, &b, 1);
    CHECK(sasl_server_new("test", "localhost", NULL, NULL, NULL, ac, 0, &as) ==
          SASL_OK);
    CHECK(sasl_server_new("test", "localhost", NULL, NULL, NULL, bc, 0, &bs) ==
          SASL_OK);
    CHECK(sasl_listmech(as, NULL, "", " ", "", &list, &len, &count) == SASL_OK);
    CHECK(strstr(list, "SCRAM-SHA-1") && !strstr(list, "SCRAM-SHA-256"));
    CHECK(sasl_listmech(bs, NULL, "", " ", "", &list, &len, &count) == SASL_OK);
    CHECK(strstr(list, "SCRAM-SHA-256") && !strstr(list, "SCRAM-SHA-1"));
    CHECK(sasl_listmech(as, NULL, "", " ", "", &list, &len, &count) == SASL_OK);
    CHECK(strstr(list, "SCRAM-SHA-1") && !strstr(list, "SCRAM-SHA-256"));
    sasl_dispose(&as);
    sasl_dispose(&bs);
}

int main(int argc, char **argv)
{
    backend_t global;
    sasl_callback_t cb[9];
    unsigned i;
    int global_mode = argc == 2 && !strcmp(argv[1], "--global-callbacks");
    static const char *mechanisms[] = {
        "SCRAM-SHA-1",        "SCRAM-SHA-256",     "SCRAM-SHA-384",
        "SCRAM-SHA-512",      "SCRAM-SHA-1-PLUS",  "SCRAM-SHA-256-PLUS",
        "SCRAM-SHA-384-PLUS", "SCRAM-SHA-512-PLUS"};
    init_backend(&global);
    callbacks(cb, &global, global_mode);
    CHECK(sasl_client_init(cb) == SASL_OK);
    CHECK(sasl_server_init(cb, "scram-test") == SASL_OK);
#ifndef STATIC_SCRAM
    CHECK(sasl_client_add_plugin("scram", scram_client_plug_init) == SASL_OK);
    CHECK(sasl_server_add_plugin("scram", scram_server_plug_init) == SASL_OK);
#endif
    CHECK(sasl_auxprop_add_plugin("scram-test", test_auxprop_init) == SASL_OK);
    if (global_mode) {
        round_trip("SCRAM-SHA-256-PLUS", 0, 0, 0, 0, 0, 0, 0);
        CHECK(global.pbkdf2_calls > 0);
        sasl_done();
        puts("global crypto callback tests passed");
        return 0;
    }
    rfc_vector("SHA1", 20, "fyko+d2lbbFgONRv9qkxdawL",
               "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+"
               "Q6sek8bf92,i=4096",
               "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", "rmF9pqV8S7suAoZWja4dJRkFsKQ=");
    rfc_vector("SHA256", 32, "rOprNGfwEbeRWgbNEkqO",
               "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s="
               "W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
               "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
               "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
    for (i = 0; i < sizeof(mechanisms) / sizeof(mechanisms[0]); i++) {
        round_trip(mechanisms[i], 1, 1, 0, 0, 0, 0, 0);
#ifdef HAVE_OPENSSL
        round_trip(mechanisms[i], 1, 0, 0, 0, 0, 0, 0);
        round_trip(mechanisms[i], 0, 1, 0, 0, 0, 0, 0);
#endif
    }
    round_trip("SCRAM-SHA-1", 1, 1, 1, 0, 0, 0, 0);
    round_trip("SCRAM-SHA-256-PLUS", 1, 1, 0, 1, 0, 0, 0);
    round_trip("SCRAM-SHA-256-PLUS", 1, 1, 0, 0, 0, 0, 1);
    for (i = 1; i <= 3; i++) {
        round_trip("SCRAM-SHA-256", 1, 1, 0, 0, i, 0, 0);
        round_trip("SCRAM-SHA-256", 1, 1, 0, 0, 0, i, 0);
    }
#ifdef HAVE_OPENSSL
#ifndef TEST_EXTERNAL_CRYPTO
    round_trip("SCRAM-SHA-224", 1, 0, 0, 0, 0, 0, 0);
    round_trip("SCRAM-SHA-224-PLUS", 0, 1, 0, 0, 0, 0, 0);
#endif
#endif
    mechanism_filter();
    interleaved_exchanges();
    check_passwords();
    saved_credentials();
    sasl_done();
    puts("SCRAM callback tests passed");
    return 0;
}
#else
int main(void)
{
    puts("SKIP: no cryptographic test backend available");
    return 77;
}
#endif
