/* saslint.h - internal SASL library definitions
 * Tim Martin
 * $Id: saslint.h,v 1.4 1998/11/29 22:07:13 rob Exp $
 */
/***********************************************************
        Copyright 1998 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

#ifndef SASLINT_H
#define SASLINT_H

#ifdef WIN32
#include "winconfig.h"
#include <windows.h>
#else /* WIN32 */
#include <netinet/in.h>
#endif /* WIN32 */
#include "sasl.h"
#include "saslplug.h"

extern int _sasl_get_mech_list(const char *entryname,
			       int (*add_plugin)(void *,void *));
extern int _sasl_done_with_plugin(void *plugin);

extern void (*_sasl_client_cleanup_hook)(void);
extern void (*_sasl_server_cleanup_hook)(void);

extern int (*_sasl_client_idle_hook)(sasl_conn_t *conn);
extern int (*_sasl_server_idle_hook)(sasl_conn_t *conn);

extern sasl_server_getsecret_t *_sasl_server_getsecret_hook;
extern sasl_server_putsecret_t *_sasl_server_putsecret_hook;

extern int _sasl_strdup(const char *in, char **out, int *outlen);

typedef struct {
  const sasl_callback_t *callbacks;
  const char *appname;
} sasl_global_callbacks_t;

struct sasl_conn {
  void (*destroy_conn)(sasl_conn_t *); /* destroy function */

  int open; /* connection open or not */
  char *service;

  int secflags;  /* strength required by server */
  int got_ip_local, got_ip_remote;
  struct sockaddr_in ip_local, ip_remote;
  sasl_ssf_t ssf;

  void *context;
  sasl_out_params_t *oparams;

  sasl_security_properties_t props;

  char *username;
  char *realm;

  sasl_secret_t *secret;

  int uses_sec_layer;   /* if need to encrypt/decrpt all transmissions */

  void *mutex;

  int (*idle_hook)(sasl_conn_t *conn);
  const sasl_callback_t *callbacks;
  const sasl_global_callbacks_t *global_callbacks; /* global callbacks
						    * for this connection */
};

extern int _sasl_conn_init(sasl_conn_t *conn,
			   const char *service,
			   int secflags,
			   int (*idle_hook)(sasl_conn_t *conn),
			   const sasl_callback_t *callbacks,
			   const sasl_global_callbacks_t * global_callbacks);

extern void _sasl_conn_dispose(sasl_conn_t *conn);

typedef struct sasl_allocation_utils {
  sasl_malloc_t *malloc;
  sasl_calloc_t *calloc;
  sasl_realloc_t *realloc;
  sasl_free_t *free;
} sasl_allocation_utils_t;

extern sasl_allocation_utils_t _sasl_allocation_utils;

#define sasl_ALLOC(__size__) (_sasl_allocation_utils.malloc((__size__)))
#define sasl_CALLOC(__nelem__, __size__) \
	(_sasl_allocation_utils.calloc((__nelem__), (__size__)))
#define sasl_REALLOC(__ptr__, __size__) \
	(_sasl_allocation_utils.realloc((__ptr__), (__size__)))
#define sasl_FREE(__ptr__) (_sasl_allocation_utils.free((__ptr__)))

typedef struct sasl_mutex_utils {
  sasl_mutex_new_t *new;
  sasl_mutex_lock_t *lock;
  sasl_mutex_unlock_t *unlock;
  sasl_mutex_dispose_t *dispose;
} sasl_mutex_utils_t;

extern sasl_mutex_utils_t _sasl_mutex_utils;

#define sasl_MUTEX_NEW() (_sasl_mutex_utils.new())
#define sasl_MUTEX_LOCK(__mutex__) (_sasl_mutex_utils.lock((__mutex__)))
#define sasl_MUTEX_UNLOCK(__mutex__) (_sasl_mutex_utils.unlock((__mutex__)))
#define sasl_MUTEX_DISPOSE(__mutex__) \
	(_sasl_mutex_utils.dispose((__mutex__)))

extern sasl_utils_t *
_sasl_alloc_utils(sasl_conn_t *conn,
		  sasl_global_callbacks_t *global_callbacks);

extern int
_sasl_free_utils(sasl_utils_t ** utils);

extern sasl_server_getsecret_t *_sasl_db_getsecret;

extern sasl_server_putsecret_t *_sasl_db_putsecret;

#endif /* SASLINT_H */
