/* Converts SASL db file to use hashed cram secrets
 * Tim Martin 
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

#ifdef SASL_NDBM
#define DB_EXISTS
#endif
#ifdef SASL_GDBM
#define DB_EXISTS
#endif

#ifdef DB_EXISTS

#include <config.h>

#ifdef SASL_NDBM
#include <ndbm.h>
#else
#include <gdbm.h>
#endif

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <sasl.h>

static int verbose = 0;

void
exit_sasl(int result)
{
    printf("ERROR: %s\n", sasl_errstring(result, NULL, NULL));
    exit(-result);
}

static int alloc_key(const char *mechanism,
		     const char *auth_identity,
		     const char *realm,
		     char **key,
		     size_t *key_len)
{
  size_t auth_id_len, mech_len, realm_len;

  auth_id_len = strlen(auth_identity);
  mech_len = strlen(mechanism);
  realm_len = strlen(realm);
  *key_len = auth_id_len + mech_len + realm_len + 2;
  *key = malloc(*key_len);
  if (! *key)
    return SASL_NOMEM;
  memcpy(*key, auth_identity, auth_id_len);
  (*key)[auth_id_len] = '\0';
  memcpy(*key + auth_id_len + 1, realm, realm_len);
  (*key)[auth_id_len + realm_len + 1] = '\0';
  memcpy(*key + auth_id_len + realm_len + 2, mechanism, mech_len);

  return SASL_OK;
}

int dbm_convert(char *dbfilename, char *user_domain)
{
    int result = SASL_OK;
#ifdef SASL_NDBM
    DBM *indb, *outdb;
#else
    GDBM_FILE indb, outdb;
#endif
    datum dkey, dvalue, nextkey, ekey;

    /* first open the db */
#ifdef SASL_NDBM
    indb = dbm_open(dbfilename, O_RDONLY, S_IRUSR | S_IWUSR);
#else
    indb = gdbm_open(dbfilename, 0, GDBM_READER, S_IRUSR | S_IWUSR, NULL);
#endif
    if (!indb) {
	fprintf(stderr, "can't open %s\n", dbfilename);
	return 1;
    }
#ifdef SASL_NDBM
    outdb = dbm_open(SASL_DB_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
#else
    outdb = gdbm_open(SASL_DB_PATH, 0, GDBM_WRITER, S_IRUSR | S_IWUSR, NULL);
#endif
    if (!outdb) {
	fprintf(stderr, "can't open %s\n", SASL_DB_PATH);
	return 1;
    }

#ifdef SASL_NDBM
    dkey = dbm_firstkey(indb);
#else
    dkey = gdbm_firstkey(indb);
#endif

    while (dkey.dptr != NULL) {
	char *s;
	char *userid;
	char *mech;
	char *realm;
	char *key;
	size_t key_len;

	s = malloc(dkey.dsize);
	memcpy(s, dkey.dptr, dkey.dsize);

	/* grab the mechanism */
	mech = malloc(dkey.dsize);
	memset(mech, 0, dkey.dsize);
	memcpy(mech, dkey.dptr+strlen(dkey.dptr)+1, 
	       dkey.dsize-strlen(dkey.dptr)-1);

	userid = s;
	if (verbose) { printf("%s %s\n", userid, mech); }

	if (!strcmp(mech, "DIGEST-MD5")) {
	    realm = strchr(userid, ':');
	    if (realm == NULL) {
		fprintf(stderr,"error: bad userid for digest-md5, skipping\n");
		continue;
	    }
	    *realm++ = '\0';
	} else {
	    realm = user_domain;
	}

	result = alloc_key(mech, userid, realm,
			   &key, &key_len);
	if (result != SASL_OK) {
	    exit_sasl(result);
	}
	ekey.dptr = key;
	ekey.dsize = key_len;

	/* grab the secret */
#ifdef SASL_NDBM
	dvalue = dbm_fetch(indb, dkey);
	if (dbm_store(outdb, ekey, dvalue, DBM_REPLACE)) {
	    fprintf(stderr, "dbm error: %s %s %s\n", userid, mech, realm);
	}      
	nextkey=dbm_nextkey(indb);
#else
	dvalue = gdbm_fetch(indb, dkey);
	if (gdbm_store(outdb, ekey, dvalue, GDBM_REPLACE)) {
	    fprintf(stderr, "dbm error: %s %s %s\n", userid, mech, realm);
	}      
	nextkey=gdbm_nextkey(indb, dkey);
#endif

	dkey=nextkey;
    }

#ifdef SASL_NDBM
    dbm_close(indb);
    dbm_close(outdb);
#else
    gdbm_close(indb);
    gdbm_close(outdb);
#endif

    if (verbose) { printf("done\n"); }

    return 0;

}

void usage(char *progname)
{
  printf("usage:\n");
  printf(" %s [-v] <old sasldb> <realm>\n", progname);
  exit(1);
}

int main(int argc, char **argv)
{
    int a;

    if (argc != 3 && argc != 4) {
	usage(argv[0]);
    }

    a = 1;

    if (!strcmp(argv[a], "-v")) {
	verbose = 1;
	a++;
    }

    printf("This program will take the sasldb file specified on the\n"
	   "command line and convert it to a new sasldb file in the default\n"
	   "location (usually /etc/sasldb). It is STRONGLY RECOMMENDED that you\n"
	   "backup sasldb before allowing this program to run\n\n"
	   "Press return to continue\n");
    getchar();

    return dbm_convert(argv[a], argv[a+1]);
}


#else

int main()
{
    printf("Must have gdbm or ndbm for the program\n");
    exit(1);
}

#endif
