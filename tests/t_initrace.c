/* Concurrent sasl_server_init() / sasl_client_init() regression test.
 *
 * Several threads initialize the library at the same time, as happens when
 * an application and the libraries it uses (for example an LDAP library)
 * each call sasl_*_init() from different threads.  Every caller must get a
 * fully initialized library: if one thread returns from sasl_*_init()
 * while another is still loading plugins, it finds no mechanisms.
 *
 * Exit status: 0 on success, 1 on failure, 77 if built without threads.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sasl.h>
#include <saslplug.h>

#ifndef HAVE_PTHREAD

int main(void)
{
    printf("SKIP: built without thread support\n");
    return 77;
}

#else

#include <pthread.h>

#define NTHREADS 16
#define ROUNDS   20

static const char *plugindir;
static int failures;
static pthread_mutex_t fail_lock = PTHREAD_MUTEX_INITIALIZER;

/* A reusable barrier; pthread_barrier_t isn't available everywhere. */
static struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int waiting;
    unsigned generation;
} barrier = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0 };

static void barrier_wait(void)
{
    unsigned gen;

    pthread_mutex_lock(&barrier.lock);
    gen = barrier.generation;
    if (++barrier.waiting == NTHREADS) {
        barrier.waiting = 0;
        barrier.generation++;
        pthread_cond_broadcast(&barrier.cond);
    } else {
        while (gen == barrier.generation)
            pthread_cond_wait(&barrier.cond, &barrier.lock);
    }
    pthread_mutex_unlock(&barrier.lock);
}

static void fail(int round, const char *what, int rc)
{
    pthread_mutex_lock(&fail_lock);
    if (failures++ < 10)
        fprintf(stderr, "round %d: %s: %s\n", round, what,
                sasl_errstring(rc, NULL, NULL));
    pthread_mutex_unlock(&fail_lock);
}

static int getpath(void *context, const char **path)
{
    (void)context;
    if (!path) return SASL_BADPARAM;
    *path = plugindir;
    return SASL_OK;
}

static const sasl_callback_t callbacks[] = {
    { SASL_CB_GETPATH, (sasl_callback_ft)&getpath, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static void *worker(void *arg)
{
    int round, rc;
    (void)arg;

    for (round = 0; round < ROUNDS; round++) {
        sasl_conn_t *conn = NULL;
        const char *list = NULL, *mech = NULL, *out = NULL;
        unsigned len = 0;
        int count = 0;

        barrier_wait();

        /* server: every caller must see the loaded plugins */
        rc = sasl_server_init(callbacks, "t_initrace");
        if (rc != SASL_OK) {
            fail(round, "sasl_server_init", rc);
        } else {
            rc = sasl_server_new("test", "localhost", NULL, NULL, NULL,
                                 NULL, 0, &conn);
            if (rc != SASL_OK) {
                fail(round, "sasl_server_new", rc);
            } else {
                rc = sasl_listmech(conn, NULL, "", " ", "", &list, NULL,
                                   &count);
                if (rc != SASL_OK)
                    fail(round, "sasl_listmech", rc);
                else if (!strstr(list, "PLAIN"))
                    fail(round, "sasl_listmech: PLAIN missing", SASL_NOMECH);
                sasl_dispose(&conn);
            }
        }

        /* client: likewise */
        rc = sasl_client_init(callbacks);
        if (rc != SASL_OK) {
            fail(round, "sasl_client_init", rc);
        } else {
            rc = sasl_client_new("test", "localhost", NULL, NULL, NULL, 0,
                                 &conn);
            if (rc != SASL_OK) {
                fail(round, "sasl_client_new", rc);
            } else {
                rc = sasl_client_start(conn, "ANONYMOUS", NULL, &out, &len,
                                       &mech);
                if (rc != SASL_OK && rc != SASL_CONTINUE &&
                    rc != SASL_INTERACT)
                    fail(round, "sasl_client_start(ANONYMOUS)", rc);
                sasl_dispose(&conn);
            }
        }

        barrier_wait();

        /* tear down concurrently; the last caller frees everything */
        rc = sasl_client_done();
        if (rc != SASL_OK && rc != SASL_CONTINUE)
            fail(round, "sasl_client_done", rc);
        rc = sasl_server_done();
        if (rc != SASL_OK && rc != SASL_CONTINUE)
            fail(round, "sasl_server_done", rc);
    }

    return NULL;
}

int main(void)
{
    pthread_t threads[NTHREADS];
    const sasl_callback_t bad[] = {
        { SASL_CB_LOG, NULL, NULL },
        { SASL_CB_LIST_END, NULL, NULL }
    };
    int i, rc;

    plugindir = getenv("T_PLUGINDIR");
    if (!plugindir || !*plugindir)
        plugindir = PLUGINDIR;

    /* A callback without a procedure is rejected, not dereferenced. */
    rc = sasl_server_init(bad, "t_initrace");
    if (rc != SASL_FAIL) {
        fprintf(stderr, "sasl_server_init with a NULL callback: %s\n",
                sasl_errstring(rc, NULL, NULL));
        return 1;
    }

    for (i = 0; i < NTHREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker, NULL) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    for (i = 0; i < NTHREADS; i++)
        pthread_join(threads[i], NULL);

    if (failures) {
        fprintf(stderr, "FAIL: %d failures in %d rounds of %d threads\n",
                failures, ROUNDS, NTHREADS);
        return 1;
    }

    printf("PASS: %d rounds of %d concurrent init/done\n", ROUNDS, NTHREADS);
    return 0;
}

#endif /* HAVE_PTHREAD */
