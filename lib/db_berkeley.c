/* db_berkeley.c--SASL berkeley db interface
 * Tim Martin
 * $Id: db_berkeley.c,v 1.16 2001/01/04 21:20:45 leg Exp $
 */

/* 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#include <db.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <assert.h>
#include "sasl.h"
#include "saslint.h"

static int db_ok = 0;

/* This provides a version of _sasl_db_getsecret and
 * _sasl_db_putsecret which work with berkeley db. */

/*
 * Open the database
 *
 */
static int berkeleydb_open(sasl_conn_t *conn, int rdwr, DB **mbdb)
{
    const char *path = SASL_DB_PATH;
    int ret;
    void *cntxt;
    sasl_getopt_t *getopt;
    int flags;

    if (_sasl_getcallback(conn, SASL_CB_GETOPT,
			  &getopt, &cntxt) == SASL_OK) {
	const char *p;
	if (getopt(cntxt, NULL, "sasldb_path", &p, NULL) == SASL_OK 
	    && p != NULL && *p != 0) {
	    path = p;
	}
    }

    if (rdwr) flags = DB_CREATE;
    else flags = DB_RDONLY;
#if DB_VERSION_MAJOR < 3
    ret = db_open(path, DB_HASH, flags, 0660, NULL, NULL, mbdb);
#else /* DB_VERSION_MAJOR < 3 */
    ret = db_create(mbdb, NULL, 0);
    if (ret == 0 && *mbdb != NULL)
    {
	    ret = (*mbdb)->open(*mbdb, path, NULL, DB_HASH, flags, 0660);
	    if (ret != 0)
	    {
		    (void) (*mbdb)->close(*mbdb, 0);
		    *mbdb = NULL;
	    }
    }
#endif /* DB_VERSION_MAJOR < 3 */

    if (ret != 0) {
	_sasl_log (NULL, SASL_LOG_ERR, NULL,
		   SASL_FAIL,	/* %z */ 0,	/* %m */
		   "unable to open Berkeley db %s: %s",
		   path, strerror(ret));
	VL(("error opening password file. Do you have write permissions?\n"));
	return SASL_FAIL;
    }

    return SASL_OK;
}

/*
 * Close the database
 *
 */

static void berkeleydb_close(DB *mbdb)
{
    int ret;
    
    ret = mbdb->close(mbdb, 0);
    if (ret!=0) {
	/* error closing! */
	_sasl_log (NULL, SASL_LOG_ERR, NULL,
		   SASL_FAIL, /* %z */ 0, /* %m */
		   "error closing sasldb: %s",
		   strerror(ret));
    }
}

/*
 * Construct a key
 *
 */
static int alloc_key(const char *mechanism,
		     const char *auth_identity,
		     const char *realm,
		     char **key,
		     size_t *key_len)
{
  size_t auth_id_len, mech_len, realm_len;

  assert(mechanism && auth_identity && realm && key && key_len);

  auth_id_len = strlen(auth_identity);
  mech_len = strlen(mechanism);
  realm_len = strlen(realm);
  *key_len = auth_id_len + mech_len + realm_len + 2;
  *key = sasl_ALLOC(*key_len);
  if (! *key)
    return SASL_NOMEM;
  memcpy(*key, auth_identity, auth_id_len);
  (*key)[auth_id_len] = '\0';
  memcpy(*key + auth_id_len + 1, realm, realm_len);
  (*key)[auth_id_len + realm_len + 1] = '\0';
  memcpy(*key + auth_id_len + realm_len + 2, mechanism, mech_len);

  return SASL_OK;
}

/*
 * Retrieve the secret from the database. 
 * 
 * Return SASL_NOUSER if entry doesn't exist
 *
 */

static int
getsecret(void *context,
	  const char *mechanism,
	  const char *auth_identity,
	  const char *realm,
	  sasl_secret_t ** secret)
{
  int result = SASL_OK;
  char *key;
  size_t key_len;
  DBT dbkey, data;
  DB *mbdb = NULL;

  /* check parameters */
  if (! mechanism || ! auth_identity || ! secret || ! realm || ! db_ok)
    return SASL_FAIL;

  /* allocate a key */
  result = alloc_key(mechanism, auth_identity, realm,
		     &key, &key_len);
  if (result != SASL_OK)
    return result;

  /* open the db */
  result = berkeleydb_open((sasl_conn_t *) context, 0, &mbdb);
  if (result != SASL_OK) goto cleanup;

  /* zero out and create the key to search for */
  memset(&dbkey, 0, sizeof(dbkey));
  memset(&data, 0, sizeof(data));
  dbkey.data = key;
  dbkey.size = key_len;

  /* ask berkeley db for the entry */
  result = mbdb->get(mbdb, NULL, &dbkey, &data, 0);

  switch (result) {
  case 0:
    /* success */
    break;

  case DB_NOTFOUND:
    result = SASL_NOUSER;
    goto cleanup;
    break;
  default:
    _sasl_log (NULL, SASL_LOG_ERR, NULL,
	       SASL_FAIL,	/* %z */ 0,	/* %m */
	       "error fetching from sasldb: %s",
	       strerror(result));
    result = SASL_FAIL;
    goto cleanup;
    break;
  }

  *secret = sasl_ALLOC(sizeof(sasl_secret_t)
		       + data.size
		       + 1);
  if (! *secret) {
    result = SASL_NOMEM;
    goto cleanup;
  }

  (*secret)->len = data.size;
  memcpy(&(*secret)->data, data.data, data.size);
  (*secret)->data[(*secret)->len] = '\0'; /* sanity */

 cleanup:

  if (mbdb != NULL) berkeleydb_close(mbdb);

  sasl_FREE(key);

  return result;
}

/*
 * Put or delete an entry
 * 
 *
 */

static int
putsecret(void *context,
	  const char *mechanism,
	  const char *auth_identity,
	  const char *realm,
	  const sasl_secret_t * secret)
{
  int result = SASL_OK;
  char *key;
  size_t key_len;
  DBT dbkey;
  DB *mbdb = NULL;

  if (! mechanism || ! auth_identity || ! realm)
      return SASL_FAIL;

  VL(("Entering putsecret for %s\n",mechanism));

  result = alloc_key(mechanism, auth_identity, realm,
		     &key, &key_len);
  if (result != SASL_OK)
    return result;

  /* open the db */
  result=berkeleydb_open((sasl_conn_t *) context, 1, &mbdb);
  if (result!=SASL_OK) goto cleanup;

  /* create the db key */
  memset(&dbkey, 0, sizeof(dbkey));
  dbkey.data = key;
  dbkey.size = key_len;


  if (secret) {   /* putting secret */
    DBT data;

    memset(&data, 0, sizeof(data));    

    data.data = (char *)secret->data;
    data.size = secret->len;

    result = mbdb->put(mbdb, NULL, &dbkey, &data, 0);

    if (result != 0)
    {
      _sasl_log (NULL, SASL_LOG_ERR, NULL,
		 SASL_FAIL, /* %z */ 0,	/* %m */
		 "error updating sasldb: %s", strerror(result));
      VL(("DBERROR: error updating database for %s: %s",
	  key, strerror(result)));
      result = SASL_FAIL;
      goto cleanup;
    }



  } else {        /* removing secret */

    result=mbdb->del(mbdb, NULL, &dbkey, 0);

    if (result != 0)
    {
      _sasl_log (NULL, SASL_LOG_ERR, NULL,
		 SASL_FAIL, /* %z */ 0,	/* %m */
		 "error deleting entry from sasldb: %s", strerror(result));
      VL(("DBERROR: error deleting entry for database for %s: %s",
	  key, strerror(result)));

      if (result == DB_NOTFOUND)
	  result = SASL_NOUSER;
      else	  
	  result = SASL_FAIL;
      goto cleanup;
    }

  }

 cleanup:

  if (mbdb != NULL) berkeleydb_close(mbdb);

  sasl_FREE(key);

  return result;
}

sasl_server_getsecret_t *_sasl_db_getsecret = &getsecret;
sasl_server_putsecret_t *_sasl_db_putsecret = &putsecret;

int _sasl_server_check_db(const sasl_callback_t *verifyfile_cb)
{
    const char *path = SASL_DB_PATH;
    int ret;
    void *cntxt;
    sasl_getopt_t *getopt;

    if (_sasl_getcallback(NULL, SASL_CB_GETOPT,
			  &getopt, &cntxt) == SASL_OK) {
	const char *p;
	if (getopt(cntxt, NULL, "sasldb_path", &p, NULL) == SASL_OK 
	    && p != NULL && *p != 0) {
	    path = p;
	}
    }

    ret = ((sasl_verifyfile_t *)(verifyfile_cb->proc))(verifyfile_cb->context,
						       path, SASL_VRFY_PASSWD);
    if (ret == SASL_OK) {
	db_ok = 1;
    }

    if (ret == SASL_OK || ret == SASL_CONTINUE) {
	return SASL_OK;
    } else {
	return ret;
    }
}
