/* db_ndbm.c--SASL ndbm interface
 * Rob Earhart
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

#include <config.h>
#include <ndbm.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "sasl.h"
#include "saslint.h"

/* This provides a version of _sasl_db_getsecret and
 * _sasl_db_putsecret which work with ndbm. */

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
  DBM *db;
  datum dkey, dvalue;

  if (! mechanism || ! auth_identity || ! secret)
    return SASL_FAIL;

  result = alloc_key(mechanism,
		     auth_identity,
		     &key,
		     &key_len);
  if (result != SASL_OK)
    return result;

  db = dbm_open(SASL_DB_PATH, O_RDONLY, S_IRUSR | S_IWUSR);
  if (! db) {
    result = SASL_FAIL;
    goto cleanup;
  }
  dkey.dptr = key;
  dkey.dsize = key_len;
  dvalue = dbm_fetch(db, dkey);
  dbm_close(db);
  if (! dvalue.dptr) {
    result = SASL_NOUSER;
    goto cleanup;
  }
  *secret = sasl_ALLOC(sizeof(sasl_secret_t)
		       + dvalue.dsize
		       + 1);
  if (! *secret) {
    result = SASL_NOMEM;
    free(dvalue.dptr);
    goto cleanup;
  }
  (*secret)->len = dvalue.dsize;
  memcpy(&(*secret)->data, dvalue.dptr, dvalue.dsize);
  (*secret)->data[(*secret)->len] = '\0'; /* sanity */
  /* Note: not sasl_FREE!  This is memory allocated by ndbm,
   * which is using libc malloc/free. */
  free(dvalue.dptr);

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
  DBM *db;
  datum dkey;

  if (! mechanism || ! auth_identity)
    return SASL_FAIL;

  result = alloc_key(mechanism,
		     auth_identity,
		     &key,
		     &key_len);
  if (result != SASL_OK)
    return result;

  db = dbm_open(SASL_DB_PATH,
		O_RDWR | O_CREAT /* TODO: what should this be? */,
		S_IRUSR | S_IWUSR);
  if (! db) {
    result = SASL_FAIL;
    goto cleanup;
  }
  dkey.dptr = key;
  dkey.dsize = key_len;
  if (secret) {
    datum dvalue;
    dvalue.dptr = (void *)&secret->data;
    dvalue.dsize = secret->len;
    if (dbm_store(db, dkey, dvalue, DBM_REPLACE))
      result = SASL_FAIL;
  } else
    if (dbm_delete(db, dkey))
      result = SASL_FAIL;
  dbm_close(db);

 cleanup:
  sasl_FREE(key);

  return result;
}

sasl_server_getsecret_t *_sasl_db_getsecret = &getsecret;
sasl_server_putsecret_t *_sasl_db_putsecret = &putsecret;
