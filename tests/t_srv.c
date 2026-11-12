/* t_srv: wire-level SASL server driver for the conformance tests.
 *
 * Runs one server-side authentication for the mechanism given with -m.
 * The first stdin line is the client's initial response, each later line
 * is a client response; each produces one JSON result line on stdout (see
 * t_wire.h).  E: and D: lines use the negotiated security layer.  Before reading any input it prints one line listing the
 * mechanisms the server advertises.
 *
 * Passwords come from an in-memory auxprop plugin ("memdb") filled with
 * -U user:password, so no sasldb backend is required.
 *
 * Options:
 *   -m MECH          mechanism to run (required)
 *   -U user:pass     add a user (repeatable)
 *   -A authid:authzid  allow authid to act as authzid (repeatable); when
 *                    given, replaces the library's default proxy policy
 *   -o key=value     SASL option served through SASL_CB_GETOPT (repeatable)
 *   -c name:hex      channel binding data; -C marks it critical
 *   -n N / -x N      min_ssf / max_ssf      -b N  maxbufsize
 *   -f N             security_flags
 *   -e ID            external authentication identity (SASL_AUTH_EXTERNAL)
 *   -E N             external SSF
 *   -r REALM         user realm             -s SERVICE   -h FQDN
 *   -S               the protocol carries additional data with success
 *                    (SASL_SUCCESS_DATA)
 *
 * See COPYING file for License */

#include "t_wire.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <saslplug.h>

static struct t_kv users[T_MAX_USERS];
static int nusers = 0;
static struct t_kv proxies[T_MAX_USERS];
static int nproxies = 0;

/* ---- in-memory auxprop plugin ---- */

static const char *find_password(const char *user, unsigned ulen)
{
    int i;

    for (i = 0; i < nusers; i++) {
        if (strlen(users[i].key) == ulen &&
            memcmp(users[i].key, user, ulen) == 0) {
            return users[i].value;
        }
    }
    return NULL;
}

static int memdb_lookup(void *glob_context __attribute__((unused)),
                        sasl_server_params_t *sparams,
                        unsigned flags,
                        const char *user, unsigned ulen)
{
    const struct propval *to_fetch, *cur;
    const char *password;

    if (!sparams || !user) return SASL_BADPARAM;

    to_fetch = sparams->utils->prop_get(sparams->propctx);
    if (!to_fetch) return SASL_NOMEM;

    password = find_password(user, ulen);

    for (cur = to_fetch; cur->name; cur++) {
        const char *realname = cur->name;

        /* Authid properties are prefixed with '*'; authzid ones are not. */
        if (cur->name[0] == '*' && (flags & SASL_AUXPROP_AUTHZID)) continue;
        if (!(flags & SASL_AUXPROP_AUTHZID)) {
            if (cur->name[0] != '*') continue;
            realname = cur->name + 1;
        }

        if (strcasecmp(realname, SASL_AUX_PASSWORD_PROP) != 0) continue;

        if (cur->values) {
            if (!(flags & SASL_AUXPROP_OVERRIDE)) continue;
            sparams->utils->prop_erase(sparams->propctx, cur->name);
        }

        if (password) {
            sparams->utils->prop_set(sparams->propctx, cur->name, password,
                                     (unsigned) strlen(password));
        }
    }

    if (!password && !(flags & SASL_AUXPROP_AUTHZID)) return SASL_NOUSER;
    return SASL_OK;
}

static sasl_auxprop_plug_t memdb_plugin = {
    0, 0, NULL, NULL, memdb_lookup, "memdb", NULL
};

static int memdb_init(const sasl_utils_t *utils __attribute__((unused)),
                      int max_version, int *out_version,
                      sasl_auxprop_plug_t **plug,
                      const char *plugname __attribute__((unused)))
{
    if (max_version < SASL_AUXPROP_PLUG_VERSION) return SASL_BADVERS;
    *out_version = SASL_AUXPROP_PLUG_VERSION;
    *plug = &memdb_plugin;
    return SASL_OK;
}

/* ---- proxy policy (only used with -A) ---- */

static int proxy_policy(sasl_conn_t *conn,
                        void *context __attribute__((unused)),
                        const char *requested_user, unsigned rlen,
                        const char *auth_identity, unsigned alen,
                        const char *def_realm __attribute__((unused)),
                        unsigned urlen __attribute__((unused)),
                        struct propctx *propctx __attribute__((unused)))
{
    int i;

    if (!requested_user || rlen == 0) return SASL_OK;
    if (rlen == alen && memcmp(requested_user, auth_identity, rlen) == 0) {
        return SASL_OK;
    }
    for (i = 0; i < nproxies; i++) {
        if (strlen(proxies[i].key) == alen &&
            memcmp(proxies[i].key, auth_identity, alen) == 0 &&
            strlen(proxies[i].value) == rlen &&
            memcmp(proxies[i].value, requested_user, rlen) == 0) {
            return SASL_OK;
        }
    }
    sasl_seterror(conn, 0, "proxy not permitted");
    return SASL_NOAUTHZ;
}

int main(int argc, char *argv[])
{
    sasl_callback_t callbacks[4];
    sasl_security_properties_t secprops;
    sasl_channel_binding_t cb;
    sasl_conn_t *conn;
    const char *mech = NULL, *service = "test", *fqdn = "host.test";
    const char *realm = NULL, *ext_id = NULL;
    const char *mechlist = NULL, *out = NULL;
    unsigned char *in;
    unsigned inlen, outlen = 0, mlen;
    sasl_ssf_t ext_ssf = 0;
    int have_cb = 0, have_ext_ssf = 0, ncb = 0, started = 0, cmd;
    unsigned conn_flags = 0;
    int c, rc;

    memset(&secprops, 0, sizeof(secprops));
    secprops.max_ssf = 256;
    secprops.maxbufsize = 65536;
    memset(&cb, 0, sizeof(cb));

    /* Defaults: use only the in-memory store, verify through auxprop.
     * Later -o options take precedence because t_getopt returns the first
     * match, so user options are inserted ahead of these below. */
    while ((c = getopt(argc, argv, "m:U:A:o:c:Cn:x:b:f:e:E:r:Ss:h:")) != EOF) {
        switch (c) {
        case 'm': mech = optarg; break;
        case 'U':
            if (nusers >= T_MAX_USERS) { fprintf(stderr, "too many -U\n"); exit(2); }
            t_parse_kv(optarg, ':', &users[nusers++]);
            break;
        case 'A':
            if (nproxies >= T_MAX_USERS) { fprintf(stderr, "too many -A\n"); exit(2); }
            t_parse_kv(optarg, ':', &proxies[nproxies++]);
            break;
        case 'o': t_add_opt(optarg); break;
        case 'c': t_parse_cbinding(optarg, &cb); have_cb = 1; break;
        case 'C': cb.critical = 1; break;
        case 'n': secprops.min_ssf = (sasl_ssf_t) atoi(optarg); break;
        case 'x': secprops.max_ssf = (sasl_ssf_t) atoi(optarg); break;
        case 'b': secprops.maxbufsize = (unsigned) atoi(optarg); break;
        case 'f': secprops.security_flags = (unsigned) strtoul(optarg, NULL, 0); break;
        case 'e': ext_id = optarg; break;
        case 'E': ext_ssf = (sasl_ssf_t) atoi(optarg); have_ext_ssf = 1; break;
        case 'r': realm = optarg; break;
        case 'S': conn_flags |= SASL_SUCCESS_DATA; break;
        case 's': service = optarg; break;
        case 'h': fqdn = optarg; break;
        default:
            fprintf(stderr, "usage: t_srv -m MECH [options]\n");
            exit(2);
        }
    }
    if (!mech) {
        fprintf(stderr, "t_srv: -m MECH is required\n");
        exit(2);
    }
    t_add_opt("auxprop_plugin=memdb");
    t_add_opt("pwcheck_method=auxprop");

    callbacks[ncb].id = SASL_CB_GETPATH;
    callbacks[ncb].proc = (sasl_callback_ft) &t_getpath;
    callbacks[ncb++].context = NULL;
    callbacks[ncb].id = SASL_CB_GETOPT;
    callbacks[ncb].proc = (sasl_callback_ft) &t_getopt;
    callbacks[ncb++].context = NULL;
    if (nproxies) {
        callbacks[ncb].id = SASL_CB_PROXY_POLICY;
        callbacks[ncb].proc = (sasl_callback_ft) &proxy_policy;
        callbacks[ncb++].context = NULL;
    }
    callbacks[ncb].id = SASL_CB_LIST_END;
    callbacks[ncb].proc = NULL;
    callbacks[ncb].context = NULL;

    rc = sasl_server_init(callbacks, "t_srv");
    if (rc != SASL_OK) {
        fprintf(stderr, "sasl_server_init: %s\n", sasl_errstring(rc, NULL, NULL));
        exit(2);
    }

    rc = sasl_auxprop_add_plugin("memdb", &memdb_init);
    if (rc != SASL_OK) {
        fprintf(stderr, "sasl_auxprop_add_plugin: %s\n", sasl_errstring(rc, NULL, NULL));
        exit(2);
    }

    rc = sasl_server_new(service, fqdn, realm, NULL, NULL, callbacks,
                         conn_flags, &conn);
    if (rc != SASL_OK) {
        fprintf(stderr, "sasl_server_new: %s\n", sasl_errstring(rc, NULL, NULL));
        exit(2);
    }

    sasl_setprop(conn, SASL_SEC_PROPS, &secprops);
    if (have_cb) sasl_setprop(conn, SASL_CHANNEL_BINDING, &cb);
    if (ext_id) sasl_setprop(conn, SASL_AUTH_EXTERNAL, ext_id);
    if (have_ext_ssf) sasl_setprop(conn, SASL_SSF_EXTERNAL, &ext_ssf);

    /* First line: what the server advertises. */
    rc = sasl_listmech(conn, NULL, "", " ", "", &mechlist, &mlen, NULL);
    t_json_begin();
    t_json_str("mechs", rc == SASL_OK ? mechlist : "");
    t_json_end();

    while (t_read_msg(&cmd, &in, &inlen)) {
        if (cmd) {
            t_security_layer(conn, cmd, in, inlen);
        } else if (!started) {
            started = 1;
            rc = sasl_server_start(conn, mech, (const char *) in, inlen,
                                   &out, &outlen);
            t_report(conn, rc, out, outlen, NULL);
        } else if (rc == SASL_CONTINUE) {
            out = NULL;
            outlen = 0;
            rc = sasl_server_step(conn, (const char *) in, inlen, &out, &outlen);
            t_report(conn, rc, out, outlen, NULL);
        } else {
            free(in);
            break;
        }
        free(in);
    }

    sasl_dispose(&conn);
    sasl_server_done();
    return 0;
}
