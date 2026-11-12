/* Shared helpers for the wire-level conformance drivers (t_srv, t_cli).
 * See t_wire.h for the line protocol.
 *
 * See COPYING file for License */

#include "t_wire.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct t_kv t_opts[T_MAX_OPTS];
int t_nopts = 0;

static void die(const char *msg, const char *arg)
{
    fprintf(stderr, "%s: %s\n", msg, arg ? arg : "");
    exit(2);
}

void t_parse_kv(const char *arg, char sep, struct t_kv *kv)
{
    const char *p = strchr(arg, sep);
    char *key;

    if (!p) die("expected key/value pair", arg);

    key = strndup(arg, (size_t)(p - arg));
    if (!key) die("out of memory", NULL);

    kv->key = key;
    kv->value = p + 1;
}

void t_add_opt(const char *arg)
{
    if (t_nopts >= T_MAX_OPTS) die("too many -o options", arg);
    t_parse_kv(arg, '=', &t_opts[t_nopts++]);
}

int t_getopt(void *context __attribute__((unused)),
             const char *plugin_name __attribute__((unused)),
             const char *option,
             const char **result,
             unsigned *len)
{
    int i;

    for (i = 0; i < t_nopts; i++) {
        if (strcmp(t_opts[i].key, option) == 0) {
            *result = t_opts[i].value;
            if (len) *len = (unsigned) strlen(t_opts[i].value);
            return SASL_OK;
        }
    }
    return SASL_FAIL;
}

int t_getpath(void *context __attribute__((unused)), const char **path)
{
    const char *env;

    if (!path) return SASL_BADPARAM;

    env = getenv("T_PLUGINDIR");
    *path = (env && *env) ? env : PLUGINDIR;
    return SASL_OK;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

unsigned char *t_hex_decode(const char *hex, unsigned *len)
{
    size_t n = strlen(hex), i;
    unsigned char *buf;

    if (n % 2) die("odd-length hex string", hex);

    /* Always allocate at least one byte so empty input is non-NULL. */
    buf = malloc(n / 2 + 1);
    if (!buf) die("out of memory", NULL);

    for (i = 0; i < n; i += 2) {
        int hi = hexval((unsigned char) hex[i]);
        int lo = hexval((unsigned char) hex[i + 1]);
        if (hi < 0 || lo < 0) die("invalid hex string", hex);
        buf[i / 2] = (unsigned char) ((hi << 4) | lo);
    }
    *len = (unsigned) (n / 2);
    return buf;
}

void t_parse_cbinding(const char *arg, sasl_channel_binding_t *cb)
{
    struct t_kv kv;
    unsigned len;

    t_parse_kv(arg, ':', &kv);
    cb->name = kv.key;
    cb->data = t_hex_decode(kv.value, &len);
    cb->len = len;
}

int t_read_msg(unsigned char **data, unsigned *len)
{
    static char *line = NULL;
    static size_t cap = 0;
    ssize_t n;

    n = getline(&line, &cap, stdin);
    if (n < 0) return 0;

    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
        line[--n] = '\0';
    }

    if (strcmp(line, "-") == 0) {
        *data = NULL;
        *len = 0;
    } else {
        *data = t_hex_decode(line, len);
    }
    return 1;
}

/* ---- JSON output ---- */

static int json_first;

void t_json_begin(void)
{
    fputc('{', stdout);
    json_first = 1;
}

static void json_key(const char *key)
{
    if (!json_first) fputc(',', stdout);
    json_first = 0;
    fprintf(stdout, "\"%s\":", key);
}

void t_json_int(const char *key, long value)
{
    json_key(key);
    fprintf(stdout, "%ld", value);
}

void t_json_str(const char *key, const char *value)
{
    const unsigned char *p;

    json_key(key);
    if (!value) {
        fputs("null", stdout);
        return;
    }
    fputc('"', stdout);
    for (p = (const unsigned char *) value; *p; p++) {
        if (*p == '"' || *p == '\\') {
            fprintf(stdout, "\\%c", *p);
        } else if (*p < 0x20 || *p >= 0x7f) {
            /* Bytes outside printable ASCII are escaped individually; this
             * is lossless for diagnostics, which is all strings are used for. */
            fprintf(stdout, "\\u%04x", *p);
        } else {
            fputc(*p, stdout);
        }
    }
    fputc('"', stdout);
}

void t_json_hex(const char *key, const unsigned char *data, unsigned len,
                int present)
{
    unsigned i;

    json_key(key);
    if (!present) {
        fputs("null", stdout);
        return;
    }
    fputc('"', stdout);
    for (i = 0; i < len; i++) fprintf(stdout, "%02x", data[i]);
    fputc('"', stdout);
}

void t_json_end(void)
{
    fputs("}\n", stdout);
    fflush(stdout);
}

/* ---- result reporting ---- */

static const struct { int code; const char *name; } rc_names[] = {
    { SASL_CONTINUE, "SASL_CONTINUE" },
    { SASL_OK, "SASL_OK" },
    { SASL_FAIL, "SASL_FAIL" },
    { SASL_NOMEM, "SASL_NOMEM" },
    { SASL_BUFOVER, "SASL_BUFOVER" },
    { SASL_NOMECH, "SASL_NOMECH" },
    { SASL_BADPROT, "SASL_BADPROT" },
    { SASL_NOTDONE, "SASL_NOTDONE" },
    { SASL_BADPARAM, "SASL_BADPARAM" },
    { SASL_TRYAGAIN, "SASL_TRYAGAIN" },
    { SASL_BADMAC, "SASL_BADMAC" },
    { SASL_NOTINIT, "SASL_NOTINIT" },
    { SASL_INTERACT, "SASL_INTERACT" },
    { SASL_BADSERV, "SASL_BADSERV" },
    { SASL_WRONGMECH, "SASL_WRONGMECH" },
    { SASL_BADAUTH, "SASL_BADAUTH" },
    { SASL_NOAUTHZ, "SASL_NOAUTHZ" },
    { SASL_TOOWEAK, "SASL_TOOWEAK" },
    { SASL_ENCRYPT, "SASL_ENCRYPT" },
    { SASL_TRANS, "SASL_TRANS" },
    { SASL_EXPIRED, "SASL_EXPIRED" },
    { SASL_DISABLED, "SASL_DISABLED" },
    { SASL_NOUSER, "SASL_NOUSER" },
    { SASL_BADVERS, "SASL_BADVERS" },
    { SASL_UNAVAIL, "SASL_UNAVAIL" },
    { SASL_NOVERIFY, "SASL_NOVERIFY" },
#ifdef SASL_BADBINDING
    { SASL_BADBINDING, "SASL_BADBINDING" },
#endif
#ifdef SASL_CONFIGERR
    { SASL_CONFIGERR, "SASL_CONFIGERR" },
#endif
};

static const char *rc_name(int rc)
{
    size_t i;

    for (i = 0; i < sizeof(rc_names) / sizeof(rc_names[0]); i++) {
        if (rc_names[i].code == rc) return rc_names[i].name;
    }
    return "SASL_UNKNOWN";
}

static void json_prop_str(sasl_conn_t *conn, const char *key, int prop)
{
    const void *val = NULL;

    if (sasl_getprop(conn, prop, &val) == SASL_OK && val) {
        t_json_hex(key, val, (unsigned) strlen(val), 1);
    } else {
        t_json_hex(key, NULL, 0, 0);
    }
}

void t_report(sasl_conn_t *conn, int rc, const char *out, unsigned outlen,
              const char *mech)
{
    t_json_begin();
    t_json_int("rc", rc);
    t_json_str("name", rc_name(rc));
    t_json_hex("out", (const unsigned char *) out, outlen, out != NULL);
    if (mech) t_json_str("mech", mech);
    if (rc != SASL_OK && rc != SASL_CONTINUE) {
        t_json_str("detail", sasl_errdetail(conn));
    }
    if (rc == SASL_OK) {
        const void *ssf = NULL;

        json_prop_str(conn, "user", SASL_USERNAME);
        json_prop_str(conn, "authuser", SASL_AUTHUSER);
        if (sasl_getprop(conn, SASL_SSF, &ssf) == SASL_OK && ssf) {
            t_json_int("ssf", (long) *(const sasl_ssf_t *) ssf);
        }
    }
    t_json_end();
}
