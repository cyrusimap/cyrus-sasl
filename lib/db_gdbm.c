/* db_gdbm.c--SASL gdbm interface
 * Rob Earhart
 * $Id: db_gdbm.c,v 1.1 1998/11/29 22:07:12 rob Exp $
 */
/***********************************************************
        Copyright 1998 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#ifdef WIN32
# include "winconfig.h"
#endif /* WIN32 */
#include <gdbm.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "sasl.h"
#include "saslint.h"

/* This provides a version of _sasl_db_getsecret and
 * _sasl_db_putsecret which work with gdbm. */

static int alloc_key(const char *mechanism,
		     const char *auth_identity,
		     char **key,
		     size_t *key_len)
{
  size_t auth_id_len,
         mech_len;

  I(mechanism);
  I(auth_identity);
  I(key);
  I(key_len);

  auth_id_len = strlen(auth_identity);
  mech_len = strlen(mechanism);
  *key_len = auth_id_len + mech_len + 1;
  *key = sasl_ALLOC(*key_len);
  if (! *key)
    return SASL_NOMEM;
  memcpy(*key, auth_identity, auth_id_len);
  (*key)[auth_id_len] = '\0';
  memcpy(*key + auth_id_len + 1, mechanism, mech_len);

  return SASL_OK;
}

static int
getsecret(void *context __attribute__((unused)),
	  const char *mechanism,
	  const char *auth_identity,
	  sasl_secret_t ** secret)
{
  int result = SASL_OK;
  char *key;
  size_t key_len;
  GDBM_FILE db;
  datum gkey, gvalue;

  if (! mechanism || ! auth_identity || ! secret)
    return SASL_FAIL;

  result = alloc_key(mechanism,
		     auth_identity,
		     &key,
		     &key_len);
  if (result != SASL_OK)
    return result;

  db = gdbm_open(SASL_DB_PATH, 0, GDBM_READER, S_IRUSR | S_IWUSR, NULL);
  if (! db) {
    result = SASL_FAIL;
    goto cleanup;
  }
  gkey.dptr = key;
  gkey.dsize = key_len;
  gvalue = gdbm_fetch(db, gkey);
  gdbm_close(db);
  if (! gvalue.dptr) {
    result = SASL_NOUSER;
    goto cleanup;
  }
  *secret = sasl_ALLOC(sizeof(sasl_secret_t)
		       + gvalue.dsize
		       + 1);
  if (! *secret) {
    result = SASL_NOMEM;
    free(gvalue.dptr);
    goto cleanup;
  }
  (*secret)->len = gvalue.dsize;
  memcpy(&(*secret)->data, gvalue.dptr, gvalue.dsize);
  (*secret)->data[(*secret)->len] = '\0'; /* sanity */
  /* Note: not sasl_FREE!  This is memory allocated by gdbm,
   * which is using libc malloc/free. */
  free(gvalue.dptr);

 cleanup:
  sasl_FREE(key);

  return result;
}

static int
putsecret(void *context __attribute__((unused)),
	  const char *mechanism,
	  const char *auth_identity,
	  const sasl_secret_t * secret)
{
  int result = SASL_OK;
  char *key;
  size_t key_len;
  GDBM_FILE db;
  datum gkey;

  if (! mechanism || ! auth_identity)
    return SASL_FAIL;

  result = alloc_key(mechanism,
		     auth_identity,
		     &key,
		     &key_len);
  if (result != SASL_OK)
    return result;

  db = gdbm_open(SASL_DB_PATH, 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, NULL);
  if (! db) {
    result = SASL_FAIL;
    goto cleanup;
  }
  gkey.dptr = key;
  gkey.dsize = key_len;
  if (secret) {
    datum gvalue;
    gvalue.dptr = (char *)&secret->data;
    gvalue.dsize = secret->len;
    if (gdbm_store(db, gkey, gvalue, GDBM_REPLACE))
      result = SASL_FAIL;
  } else
    if (gdbm_delete(db, gkey))
      result = SASL_FAIL;
  gdbm_close(db);

 cleanup:
  sasl_FREE(key);

  return result;
}

sasl_server_getsecret_t *_sasl_db_getsecret = &getsecret;
sasl_server_putsecret_t *_sasl_db_putsecret = &putsecret;
