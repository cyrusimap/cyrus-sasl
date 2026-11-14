/* t_cli: wire-level SASL client driver for the conformance tests.
 *
 * Calls sasl_client_start() with the mechanism list given by -m and prints
 * one JSON result line (including the chosen mechanism and any initial
 * response).  Each stdin line after that is a server challenge passed to
 * sasl_client_step(), and each produces one JSON result line (see
 * t_wire.h).  A line of "-" passes no data, as an application does when
 * the server reports success without additional data.  E: and D: lines
 * use the negotiated security layer.
 *
 * Callbacks are registered only for the values given, so a missing value
 * shows up as SASL_INTERACT.
 *
 * Options:
 *   -m MECHLIST      mechanisms the server offers (required)
 *   -u NAME          authentication identity (SASL_CB_AUTHNAME)
 *   -a NAME          authorization identity (SASL_CB_USER)
 *   -w PASSWORD      password (SASL_CB_PASS)
 *   -o key=value     SASL option served through SASL_CB_GETOPT (repeatable)
 *   -c name:hex      channel binding data; -C marks it critical
 *   -n N / -x N      min_ssf / max_ssf      -b N  maxbufsize
 *   -f N             security_flags
 *   -e ID            external authentication identity (SASL_AUTH_EXTERNAL)
 *   -E N             external SSF
 *   -N               the protocol has no initial response (passes a NULL
 *                    clientout to sasl_client_start)
 *   -S               the protocol carries additional data with success
 *                    (SASL_SUCCESS_DATA)
 *   -s SERVICE       -h FQDN
 *
 * See COPYING file for License */

#include "t_wire.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static const char *authname = NULL, *authzid = NULL, *password = NULL;

static int get_simple(void *context __attribute__((unused)), int id,
                      const char **result, unsigned *len)
{
    const char *value = NULL;

    if (id == SASL_CB_AUTHNAME) value = authname;
    else if (id == SASL_CB_USER) value = authzid;

    if (!value) return SASL_FAIL;
    *result = value;
    if (len) *len = (unsigned) strlen(value);
    return SASL_OK;
}

static int get_secret(sasl_conn_t *conn __attribute__((unused)),
                      void *context __attribute__((unused)),
                      int id, sasl_secret_t **psecret)
{
    static sasl_secret_t *secret = NULL;
    size_t len;

    if (id != SASL_CB_PASS || !password) return SASL_FAIL;

    len = strlen(password);
    if (!secret) {
        secret = malloc(sizeof(sasl_secret_t) + len);
        if (!secret) return SASL_NOMEM;
        secret->len = len;
        memcpy(secret->data, password, len);
        secret->data[len] = '\0';
    }
    *psecret = secret;
    return SASL_OK;
}

int main(int argc, char *argv[])
{
    sasl_callback_t callbacks[7];
    sasl_security_properties_t secprops;
    sasl_channel_binding_t cb;
    sasl_conn_t *conn;
    const char *mechlist = NULL, *service = "test", *fqdn = "host.test";
    const char *ext_id = NULL, *chosen = NULL, *out = NULL;
    unsigned char *in;
    unsigned inlen, outlen = 0;
    sasl_ssf_t ext_ssf = 0;
    int have_cb = 0, have_ext_ssf = 0, ncb = 0, no_initial = 0, cmd;
    unsigned conn_flags = 0;
    int c, rc;

    memset(&secprops, 0, sizeof(secprops));
    secprops.max_ssf = 256;
    secprops.maxbufsize = 65536;
    memset(&cb, 0, sizeof(cb));

    while ((c = getopt(argc, argv, "m:u:a:w:o:c:Cn:x:b:f:e:E:NSs:h:")) != EOF) {
        switch (c) {
        case 'm': mechlist = optarg; break;
        case 'u': authname = optarg; break;
        case 'a': authzid = optarg; break;
        case 'w': password = optarg; break;
        case 'o': t_add_opt(optarg); break;
        case 'c': t_parse_cbinding(optarg, &cb); have_cb = 1; break;
        case 'C': cb.critical = 1; break;
        case 'n': secprops.min_ssf = (sasl_ssf_t) atoi(optarg); break;
        case 'x': secprops.max_ssf = (sasl_ssf_t) atoi(optarg); break;
        case 'b': secprops.maxbufsize = (unsigned) atoi(optarg); break;
        case 'f': secprops.security_flags = (unsigned) strtoul(optarg, NULL, 0); break;
        case 'e': ext_id = optarg; break;
        case 'E': ext_ssf = (sasl_ssf_t) atoi(optarg); have_ext_ssf = 1; break;
        case 'N': no_initial = 1; break;
        case 'S': conn_flags |= SASL_SUCCESS_DATA; break;
        case 's': service = optarg; break;
        case 'h': fqdn = optarg; break;
        default:
            fprintf(stderr, "usage: t_cli -m MECHLIST [options]\n");
            exit(2);
        }
    }
    if (!mechlist) {
        fprintf(stderr, "t_cli: -m MECHLIST is required\n");
        exit(2);
    }

    callbacks[ncb].id = SASL_CB_GETPATH;
    callbacks[ncb].proc = (sasl_callback_ft) &t_getpath;
    callbacks[ncb++].context = NULL;
    callbacks[ncb].id = SASL_CB_GETOPT;
    callbacks[ncb].proc = (sasl_callback_ft) &t_getopt;
    callbacks[ncb++].context = NULL;
    if (authname) {
        callbacks[ncb].id = SASL_CB_AUTHNAME;
        callbacks[ncb].proc = (sasl_callback_ft) &get_simple;
        callbacks[ncb++].context = NULL;
    }
    if (authzid) {
        callbacks[ncb].id = SASL_CB_USER;
        callbacks[ncb].proc = (sasl_callback_ft) &get_simple;
        callbacks[ncb++].context = NULL;
    }
    if (password) {
        callbacks[ncb].id = SASL_CB_PASS;
        callbacks[ncb].proc = (sasl_callback_ft) &get_secret;
        callbacks[ncb++].context = NULL;
    }
    callbacks[ncb].id = SASL_CB_LIST_END;
    callbacks[ncb].proc = NULL;
    callbacks[ncb].context = NULL;

    rc = sasl_client_init(callbacks);
    if (rc != SASL_OK) {
        fprintf(stderr, "sasl_client_init: %s\n", sasl_errstring(rc, NULL, NULL));
        exit(2);
    }

    rc = sasl_client_new(service, fqdn, NULL, NULL, callbacks, conn_flags, &conn);
    if (rc != SASL_OK) {
        fprintf(stderr, "sasl_client_new: %s\n", sasl_errstring(rc, NULL, NULL));
        exit(2);
    }

    sasl_setprop(conn, SASL_SEC_PROPS, &secprops);
    if (have_cb) sasl_setprop(conn, SASL_CHANNEL_BINDING, &cb);
    if (ext_id) sasl_setprop(conn, SASL_AUTH_EXTERNAL, ext_id);
    if (have_ext_ssf) sasl_setprop(conn, SASL_SSF_EXTERNAL, &ext_ssf);

    rc = sasl_client_start(conn, mechlist, NULL,
                           no_initial ? NULL : &out,
                           no_initial ? NULL : &outlen, &chosen);
    t_report(conn, rc, out, outlen, chosen);

    while ((rc == SASL_CONTINUE || rc == SASL_OK) &&
           t_read_msg(&cmd, &in, &inlen)) {
        if (cmd) {
            t_security_layer(conn, cmd, in, inlen);
        } else {
            out = NULL;
            outlen = 0;
            rc = sasl_client_step(conn, (const char *) in, inlen, NULL,
                                  &out, &outlen);
            t_report(conn, rc, out, outlen, NULL);
        }
        free(in);
    }

    sasl_dispose(&conn);
    sasl_client_done();
    return 0;
}
