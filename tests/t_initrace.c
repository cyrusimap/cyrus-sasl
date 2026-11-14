/* Concurrent sasl_server_init() / sasl_client_init() regression test.
 *
 * Several threads initialize the library at the same time, as happens when
 * an application and the libraries it uses (for example an LDAP library)
 * each call sasl_*_init() from different threads.  Every caller must get a
 * fully initialized library: if one thread returns from sasl_*_init()
 * while another is still loading plugins, it finds no mechanisms.
 *
 * Exit status: 0 on success, 1 on failure, 77 if built without threads.
 * The test uses the same thread API as the library: pthreads or Windows.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sasl.h>
#include <saslplug.h>

#if !defined(HAVE_PTHREAD) && !defined(HAVE_NT_THREADS)

int main(void)
{
    printf("SKIP: built without thread support\n");
    return 77;
}

#else

#if defined(HAVE_PTHREAD)

#include <pthread.h>

typedef pthread_mutex_t lock_t;
typedef pthread_cond_t cond_t;
typedef pthread_t thread_t;
#define LOCK_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define COND_INITIALIZER PTHREAD_COND_INITIALIZER
#define lock(l)          pthread_mutex_lock(l)
#define unlock(l)        pthread_mutex_unlock(l)
#define cond_wait(c, l)  pthread_cond_wait(c, l)
#define cond_wakeall(c)  pthread_cond_broadcast(c)
#define THREAD_FUNC(f)   static void *f(void *arg)
#define THREAD_RETURN    return NULL

static int thread_start(thread_t *t, void *(*f)(void *))
{
    return pthread_create(t, NULL, f, NULL) == 0 ? 0 : -1;
}

static void thread_join(thread_t t)
{
    pthread_join(t, NULL);
}

#else /* HAVE_NT_THREADS */

#include <windows.h>
#include <process.h>

typedef SRWLOCK lock_t;
typedef CONDITION_VARIABLE cond_t;
typedef HANDLE thread_t;
#define LOCK_INITIALIZER SRWLOCK_INIT
#define COND_INITIALIZER CONDITION_VARIABLE_INIT
#define lock(l)          AcquireSRWLockExclusive(l)
#define unlock(l)        ReleaseSRWLockExclusive(l)
#define cond_wait(c, l)  SleepConditionVariableSRW(c, l, INFINITE, 0)
#define cond_wakeall(c)  WakeAllConditionVariable(c)
#define THREAD_FUNC(f)   static unsigned __stdcall f(void *arg)
#define THREAD_RETURN    return 0

static int thread_start(thread_t *t, unsigned (__stdcall *f)(void *))
{
    *t = (HANDLE)_beginthreadex(NULL, 0, f, NULL, 0, NULL);
    return *t ? 0 : -1;
}

static void thread_join(thread_t t)
{
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}

#endif

#define NTHREADS 16
#define ROUNDS   20

static const char *plugindir;
static int failures;
static lock_t fail_lock = LOCK_INITIALIZER;

/* A reusable barrier; pthread_barrier_t isn't available everywhere. */
static struct {
    lock_t lock;
    cond_t cond;
    int waiting;
    unsigned generation;
} barrier = { LOCK_INITIALIZER, COND_INITIALIZER, 0, 0 };

static void barrier_wait(void)
{
    unsigned gen;

    lock(&barrier.lock);
    gen = barrier.generation;
    if (++barrier.waiting == NTHREADS) {
        barrier.waiting = 0;
        barrier.generation++;
        cond_wakeall(&barrier.cond);
    } else {
        while (gen == barrier.generation)
            cond_wait(&barrier.cond, &barrier.lock);
    }
    unlock(&barrier.lock);
}

static void fail(int round, const char *what, int rc)
{
    lock(&fail_lock);
    if (failures++ < 10)
        fprintf(stderr, "round %d: %s: %s\n", round, what,
                sasl_errstring(rc, NULL, NULL));
    unlock(&fail_lock);
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

THREAD_FUNC(worker)
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

    THREAD_RETURN;
}

int main(void)
{
    thread_t threads[NTHREADS];
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
        if (thread_start(&threads[i], worker) != 0) {
            perror("thread_start");
            return 1;
        }
    }
    for (i = 0; i < NTHREADS; i++)
        thread_join(threads[i]);

    if (failures) {
        fprintf(stderr, "FAIL: %d failures in %d rounds of %d threads\n",
                failures, ROUNDS, NTHREADS);
        return 1;
    }

    printf("PASS: %d rounds of %d concurrent init/done\n", ROUNDS, NTHREADS);
    return 0;
}

#endif /* HAVE_PTHREAD || HAVE_NT_THREADS */
