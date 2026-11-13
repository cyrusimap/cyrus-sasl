/* Copyright (c) 2026 Sergei Ilinykh.
 * Distributed under the terms in COPYING.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sasl.h>
#include <saslplug.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);    \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

#ifdef WIN32
#define MULTIPLE_PATHS "first;second;third"
#else
#define MULTIPLE_PATHS "first:second:third"
#endif

static size_t live_allocations;
static char *returned_path;
static unsigned path_frees, config_files, callback_calls;
static const char *source_path;
static int callback_result, verify_result;
static int fail_filename_allocation, fail_next_allocation;

static void *test_malloc(size_t size)
{
    void *pointer;
    if (fail_next_allocation) {
        fail_next_allocation = 0;
        return NULL;
    }
    pointer = malloc(size);
    if (pointer != NULL)
        live_allocations++;
    return pointer;
}

static void *test_calloc(size_t count, size_t size)
{
    void *pointer;
    if (size && count > (size_t)-1 / size)
        return NULL;
    pointer = test_malloc(count * size);
    if (pointer != NULL)
        memset(pointer, 0, count * size);
    return pointer;
}

static void *test_realloc(void *pointer, size_t size)
{
    if (pointer == NULL)
        return test_malloc(size);
    CHECK(size != 0);
    if (fail_next_allocation) {
        fail_next_allocation = 0;
        return NULL;
    }
    return realloc(pointer, size);
}

static void test_free(void *pointer)
{
    if (pointer == NULL)
        return;
    if (pointer == returned_path) {
        path_frees++;
        returned_path = NULL;
    }
    CHECK(live_allocations > 0);
    live_allocations--;
    free(pointer);
}

static int get_path(void *context, const char **path)
{
    (void)context;
    *path = "";
    return SASL_OK;
}

static int get_confpath(void *context, char **path)
{
    size_t size;
    (void)context;
    callback_calls++;
    *path = NULL;
    if (callback_result != SASL_OK)
        return callback_result;
    if (source_path == NULL)
        return SASL_OK;
    size = strlen(source_path) + 1;
    returned_path = test_malloc(size);
    CHECK(returned_path != NULL);
    memcpy(returned_path, source_path, size);
    *path = returned_path;
    fail_next_allocation = fail_filename_allocation;
    return SASL_OK;
}

static int verify_file(void *context, const char *file, sasl_verify_type_t type)
{
    (void)context;
    (void)file;
    if (type == SASL_VRFY_CONF) {
        config_files++;
        return verify_result;
    }
    return SASL_CONTINUE;
}

static sasl_callback_t callbacks[] = {
    {SASL_CB_GETPATH, (sasl_callback_ft)get_path, NULL},
    {SASL_CB_VERIFYFILE, (sasl_callback_ft)verify_file, NULL},
    {SASL_CB_GETCONFPATH, (sasl_callback_ft)get_confpath, NULL},
    {SASL_CB_LIST_END, NULL, NULL}};

static void custom_path(const char *path, int expected, unsigned files)
{
    unsigned expected_frees = path != NULL && callback_result == SASL_OK;
    source_path = path;
    returned_path = NULL;
    path_frees = config_files = callback_calls = 0;
    CHECK(sasl_server_init(callbacks, "confpath-test") == expected);
    CHECK(callback_calls == 1);
    CHECK(config_files == files);
    CHECK(path_frees == expected_frees);
    CHECK(returned_path == NULL);
    CHECK(!fail_next_allocation);
    if (expected == SASL_OK)
        CHECK(sasl_server_done() == SASL_OK);
}

static void default_path(void)
{
    unsigned i;
    callbacks[2].id = SASL_CB_LIST_END;
    /* Keep the client active: server shutdown must not invalidate the shared
     * default path cache between these repeated server initializations. */
    for (i = 0; i < 3; i++) {
        config_files = 0;
        CHECK(sasl_server_init(callbacks, "confpath-test") == SASL_OK);
        CHECK(config_files > 0);
        CHECK(sasl_server_done() == SASL_OK);
    }
    callbacks[2].id = SASL_CB_GETCONFPATH;
}

int main(void)
{
    char *long_path;
    sasl_set_alloc(test_malloc, test_calloc, test_realloc, test_free);
    verify_result = SASL_CONTINUE;
    CHECK(sasl_client_init(callbacks) == SASL_OK);

    custom_path("", SASL_OK, 1);
    custom_path(MULTIPLE_PATHS, SASL_OK, 3);
    custom_path(NULL, SASL_OK, 1);

    callback_result = SASL_FAIL;
    custom_path("", SASL_FAIL, 0);
    callback_result = SASL_OK;

    verify_result = SASL_FAIL;
    custom_path("", SASL_FAIL, 1);
    verify_result = SASL_CONTINUE;

    fail_filename_allocation = 1;
    custom_path("", SASL_NOMEM, 0);
    fail_filename_allocation = 0;

    long_path = malloc(65537);
    CHECK(long_path != NULL);
    memset(long_path, 'x', 65536);
    long_path[65536] = '\0';
    custom_path(long_path, SASL_FAIL, 0);
    free(long_path);

    /* Cover both lazy default lookup and sasl_set_path's cached override. */
    default_path();
    CHECK(sasl_set_path(SASL_PATH_TYPE_CONFIG, MULTIPLE_PATHS) == SASL_OK);
    default_path();
    CHECK(sasl_client_done() == SASL_OK);
    CHECK(live_allocations == 0);
    puts("configuration path ownership tests passed");
    return 0;
}
