/* db_berkeley.c--SASL berkeley db interface
 * Tim Martin
 * $Id: db_berkeley.c,v 1.4 1999/11/16 20:32:48 leg Exp $
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
static int berkeleydb_open(sasl_conn_t *conn, DB **mbdb)
{
    const char *path = SASL_DB_PATH;
    int ret;
    DB_INFO dbinfo;
    void *cntxt;
    sasl_getopt_t *getopt;

    memset(&dbinfo, 0, sizeof(dbinfo));

    if (_sasl_getcallback(conn, SASL_CB_GETOPT,
			  &getopt, &cntxt) == SASL_OK) {
	const char *p;
	if (getopt(cntxt, NULL, "sasldb_path", &p, NULL) == SASL_OK 
	    && p != NULL && *p != 0) {
	    path = p;
	}
    }
    ret = db_open(path, DB_HASH, DB_CREATE, 0664, NULL, &dbinfo, mbdb);
    if (ret != 0) {
	_sasl_log (NULL, 0, NULL,
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
	VL(("Error closing mailbox"));
	_sasl_log (NULL, 0, NULL,
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
  DB *mbdb;

  /* check parameters */
  if (! mechanism || ! auth_identity || ! secret || ! realm || ! db_ok)
    return SASL_FAIL;

  VL(("getting secret for %s\n",key));

  /* open the db */
  result=berkeleydb_open((sasl_conn_t *) context, &mbdb);
  if (result!=SASL_OK) return result;

  /* allocate a key */
  result = alloc_key(mechanism, auth_identity, realm,
		     &key, &key_len);
  if (result != SASL_OK)
    return result;

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
    VL(("User not found\n"));
    result = SASL_NOUSER;
    goto cleanup;
    break;
  default:
    VL(("Other failure\n"));
    _sasl_log (NULL, 0, NULL,
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
  DB *mbdb;

  if (! mechanism || ! auth_identity || ! realm)
      return SASL_FAIL;

  VL(("Entering putsecret for %s\n",mechanism));

  /* open the db */
  result=berkeleydb_open((sasl_conn_t *) context, &mbdb);
  if (result!=SASL_OK) return result;

  result = alloc_key(mechanism, auth_identity, realm,
		     &key, &key_len);
  if (result != SASL_OK)
    return result;

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
      _sasl_log (NULL, 0, NULL,
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
      _sasl_log (NULL, 0, NULL,
		 SASL_FAIL, /* %z */ 0,	/* %m */
		 "error deleting entry from sasldb: %s", strerror(result));
      VL(("DBERROR: error deleting entry for database for %s: %s",
	  key, strerror(result)));
      result = SASL_FAIL;
      goto cleanup;
    }

  }

 cleanup:

  berkeleydb_close(mbdb);

  sasl_FREE(key);

  return result;
}

sasl_server_getsecret_t *_sasl_db_getsecret = &getsecret;
sasl_server_putsecret_t *_sasl_db_putsecret = &putsecret;

int _sasl_server_check_db(const sasl_callback_t *verifyfile_cb)
{
    int ret;

    ret = ((sasl_verifyfile_t *)(verifyfile_cb->proc))(verifyfile_cb->context,
						       SASL_DB_PATH);
    if (ret == SASL_OK) {
	db_ok = 1;
    }

    if (ret == SASL_OK || ret == SASL_CONTINUE) {
	return SASL_OK;
    } else {
	return ret;
    }
}
