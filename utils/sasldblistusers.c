

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
    datum dkey, dvalue, nextkey, ekey;

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

	/* xxx	dvalue = gdbm_fetch(indb, dkey); */

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
    datum dkey, dvalue, nextkey, ekey;

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

	/* xxx	dvalue = gdbm_fetch(indb, dkey); */

	nextkey=dbm_nextkey(indb, dkey);
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
    result = mbdb->cursor(mbdb, NULL,&cursor, 0); 
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
	char *realm  = key.data+strlen(authid)+1;
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

    listusers(SASL_DB_PATH, (listcb_t *) &listusers_cb);

    exit(0);
}
