/* Shared helpers for the wire-level conformance drivers (t_srv, t_cli).
 *
 * The drivers read one line per SASL call from stdin and write one JSON
 * object per call to stdout, so a test script can play the other side of
 * an exchange with exact bytes.
 *
 * Input line encoding (one SASL message per line):
 *   "-"        no data (NULL pointer, e.g. no initial response)
 *   ""         present but empty (zero-length, non-NULL)
 *   <hex>      the message bytes, hex-encoded
 *
 * See COPYING file for License */

#ifndef T_WIRE_H
#define T_WIRE_H

#include "config.h"

#include <stdio.h>
#include <sasl.h>
#include <saslplug.h>

#define T_MAX_OPTS 32
#define T_MAX_USERS 16

struct t_kv {
    const char *key;
    const char *value;
};

/* getopt values supplied with -o key=value */
extern struct t_kv t_opts[T_MAX_OPTS];
extern int t_nopts;

/* Parse "key=value" (or "key:value" with sep ':') into kv; exits on error. */
void t_parse_kv(const char *arg, char sep, struct t_kv *kv);

/* Add a -o key=value option. */
void t_add_opt(const char *arg);

/* SASL_CB_GETOPT callback that serves the -o options. */
int t_getopt(void *context, const char *plugin_name, const char *option,
             const char **result, unsigned *len);

/* SASL_CB_GETPATH callback: $T_PLUGINDIR, else the compiled-in PLUGINDIR. */
int t_getpath(void *context, const char **path);

/* Parse a channel binding argument "name:hexdata". */
void t_parse_cbinding(const char *arg, sasl_channel_binding_t *cb);

/* Decode a hex string into a newly allocated buffer; exits on bad input. */
unsigned char *t_hex_decode(const char *hex, unsigned *len);

/* Read one input line.  Returns 0 on EOF, 1 otherwise.  On return *data is
 * NULL for "-", or points to the decoded bytes (possibly zero-length). */
int t_read_msg(unsigned char **data, unsigned *len);

/* JSON output helpers.  Each driver call prints exactly one object. */
void t_json_begin(void);
void t_json_int(const char *key, long value);
void t_json_str(const char *key, const char *value);
void t_json_hex(const char *key, const unsigned char *data, unsigned len,
                int present);
void t_json_end(void);

/* Print the standard result object for a SASL call. */
void t_report(sasl_conn_t *conn, int rc, const char *out, unsigned outlen,
              const char *mech);

#endif /* T_WIRE_H */
