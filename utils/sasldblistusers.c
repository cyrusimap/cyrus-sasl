/* sasldblistusers.c -- list users in sasldb
 * Tim Martin
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

#include <stdio.h>
#include <stdlib.h>

#include <sasl.h>

typedef void *listcb_t(const char *, const char *, const char *);

void listusers_cb(const char *authid, const char *realm, const char *mechanism)
{
    if ( !authid || !mechanism || !realm) {
	fprintf(stderr,"userlist callback has bad param");
	return;
    }

    /* the entries that just say the mechanism exists */
    if (strlen(authid)==0) return;

    printf("user: %s realm: %s mech: %s\n",authid,realm,mechanism);
}

/*
 * List all users in database
 */

#ifdef SASL_GDBM

#include <gdbm.h>
#include <fcntl.h>
#include <sys/stat.h>

int listusers(const char *path, listcb_t *cb)
{
    GDBM_FILE indb, outdb;
    datum dkey, nextkey, ekey;

    indb = gdbm_open(path, 0, GDBM_READER, S_IRUSR | S_IWUSR, NULL);

    if (!indb) {
	fprintf(stderr, "can't open %s\n", path);
	return 1;
    }

    dkey = gdbm_firstkey(indb);

    while (dkey.dptr != NULL) {
	char *authid = dkey.dptr;
	char *realm  = dkey.dptr+strlen(authid)+1;
	char *tmp    = realm + strlen(realm)+1;
	char *mech;

	mech = (char *) malloc(dkey.dsize+1);
	memset(mech,'\0',dkey.dsize+1);
	memcpy(mech, tmp, dkey.dsize - (tmp - ((char *)dkey.dptr)));

	/* don't check return values */
	cb(authid,realm,mech);

	free(mech);

	nextkey=gdbm_nextkey(indb, dkey);
	dkey=nextkey;
    }

    gdbm_close(indb);
}

#else /* SASL_GDBM */
#ifdef SASL_NDBM

#include <ndbm.h>
#include <fcntl.h>
#include <sys/stat.h>

int listusers(const char *path, listcb_t *cb)
{
    DBM *indb;
    datum dkey, nextkey;

    indb = dbm_open(path, O_RDONLY, S_IRUSR | S_IWUSR);

    if (!indb) {
	fprintf(stderr, "can't open %s\n", path);
	return 1;
    }

    dkey = dbm_firstkey(indb);

    while (dkey.dptr != NULL) {
	char *authid = dkey.dptr;
	char *realm  = dkey.dptr+strlen(authid)+1;
	char *tmp    = realm + strlen(realm)+1;
	char *mech;

	mech = (char *) malloc(dkey.dsize+1);
	memset(mech,'\0',dkey.dsize+1);
	memcpy(mech, tmp, dkey.dsize - (tmp - ((char *)dkey.dptr)));

	/* don't check return values */
	cb(authid,realm,mech);

	free(mech);

	nextkey=dbm_nextkey(indb);
	dkey=nextkey;
    }

    dbm_close(indb);
}

#else /* SASL_NDBM */
#ifdef SASL_BERKELEYDB

#include <db.h>
/*
 * Open the database
 *
 */
static int berkeleydb_open(const char *path,DB **mbdb)
{
    int ret;

#if DB_VERSION_MAJOR < 3
    ret = db_open(path, DB_HASH, DB_CREATE, 0664, NULL, NULL, mbdb);
#else /* DB_VERSION_MAJOR < 3 */
    ret = db_create(mbdb, NULL, 0);
    if (ret == 0 && *mbdb != NULL)
    {
	    ret = (*mbdb)->open(*mbdb, path, NULL, DB_HASH, DB_CREATE, 0664);
	    if (ret != 0)
	    {
		    (void) (*mbdb)->close(*mbdb, 0);
		    *mbdb = NULL;
	    }
    }
#endif /* DB_VERSION_MAJOR < 3 */

    if (ret != 0) {
	fprintf(stderr,"Error opening password file");
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
	fprintf(stderr,"error closing sasldb: %s",
		strerror(ret));
    }
}

int listusers(const char *path, listcb_t *cb)
{
    int result;
    DB *mbdb = NULL;
    DBC *cursor;
    DBT key, data;

    /* open the db */
    result=berkeleydb_open(path, &mbdb);
    if (result!=SASL_OK) goto cleanup;

    /* make cursor */
#if DB_VERSION_MAJOR < 3
    result = mbdb->cursor(mbdb, NULL,&cursor); 
#else /* DB_VERSION_MAJOR < 3 */
    result = mbdb->cursor(mbdb, NULL,&cursor, 0); 
#endif /* DB_VERSION_MAJOR < 3 */

    if (result!=0) {
	fprintf(stderr,"Making cursor failure: %s\n",strerror(result));
      result = SASL_FAIL;
      goto cleanup;
    }

    memset(&key,0,sizeof(key));
    memset(&data,0,sizeof(data));

    /* loop thru */
    result = cursor->c_get(cursor, &key, &data,
			   DB_FIRST);

    while (result != DB_NOTFOUND)
    {
	char *authid = key.data;
	char *realm  = ((char *)key.data)+strlen(authid)+1;
	char *tmp    = realm + strlen(realm)+1;
	char *mech;

	mech = (char *) malloc(key.size+1);
	memset(mech,'\0',key.size+1);
	memcpy(mech, tmp, key.size - (tmp - ((char *)key.data)));

	/* don't check return values */
	cb(authid,realm,mech);

	free(mech);
	
	result = cursor->c_get(cursor, &key, &data,
			       DB_NEXT);

    }

    if (result != DB_NOTFOUND) {
	fprintf(stderr,"failure: %s\n",strerror(result));
	result = SASL_FAIL;
	goto cleanup;
    }

    result = cursor->c_close(cursor);
    if (result!=0) result = SASL_FAIL;

    result = SASL_OK;

 cleanup:

    if (mbdb != NULL) berkeleydb_close(mbdb);
    return result;
}

#else 

int listusers(listcb_t *cb)
{
    fprintf(stderr,"Unsupported DB format");
    exit(1);
}

#endif /* BERKELEY */

#endif /* SASL_NDBM */

#endif /* SASL_GDBM */


int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    
    listusers(SASL_DB_PATH, (listcb_t *) &listusers_cb);

    exit(0);
}
