/* Converts SASL db file to use hashed cram secrets
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


/* Comment out this line if you are using gdbm */
#define NDBM

/* Then comment out this line no matter what was chosen above */
#define HASNOTBEENEDITED





#ifdef NDBM
#include <ndbm.h>
#else
#include <gdbm.h>
#endif

#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sasl.h>

#include <stdio.h>

void
exit_sasl(int result, const char *errstr)
{
  printf("ERROR: %s\n",
	 sasl_errstring(result, NULL, NULL));
  exit(-result);
}


int dbm_convert(char *dbfilename, char *user_domain)
{
  int result = SASL_OK;
  char *key;
  size_t key_len;
#ifdef NDBM
  DBM *db;
#else
  GDBM_FILE db;
#endif
  datum dkey, dvalue, nextkey;
  sasl_conn_t *conn;

  result = sasl_server_init(NULL, "saslpasswd");
  if (result != SASL_OK)
    exit_sasl(result, NULL);

  result = sasl_server_new("saslpasswd",
			   NULL,
			   user_domain,
			   NULL,
			   0,
			   &conn);
  if (result != SASL_OK)
    exit_sasl(result, NULL);

  /* first open the db */
#ifdef NDBM
  db = dbm_open(dbfilename, O_RDONLY, S_IRUSR | S_IWUSR);
#else
  db = gdbm_open(dbfilename, 0, GDBM_READER, S_IRUSR | S_IWUSR, NULL);
#endif
  if (! db) {
    printf("Can't open Db file %s\n",dbfilename);
    return SASL_FAIL;
  }

  printf("Opened Db file\n");

#ifdef NDBM
  dkey=dbm_firstkey(db);
#else
  dkey=gdbm_firstkey(db);
#endif

  while (dkey.dptr!=NULL)
  {
    char *userid;
    char *mech;

    const char *errstr;

    /* ok let's see if it's a cram secret */
    mech=malloc(dkey.dsize);
    memset(mech, 0, dkey.dsize);

    memcpy(mech, dkey.dptr+strlen(dkey.dptr)+1, 
	   dkey.dsize-strlen(dkey.dptr)-1);

    if (strcmp(mech,"CRAM-MD5")==0)
    {
      /* only gets here if it is the cram passwd */


      userid=dkey.dptr;
      printf("Found %s\n",userid);
      
      /* grab the password (which is plaintext ) */
#ifdef NDBM
      dvalue = dbm_fetch(db, dkey);
#else
      dvalue = gdbm_fetch(db, dkey);
#endif
    
      result = sasl_setpass(conn,
			    userid,
			    dvalue.dptr,
			    dvalue.dsize,
			    SASL_SET_CREATE,
			    &errstr);

      if (result != SASL_OK)
	exit_sasl(result, errstr);
    }

#ifdef NDBM
    nextkey=dbm_nextkey(db);
#else
    nextkey=gdbm_nextkey(db, dkey);
#endif    
    
    dkey=nextkey;
      
  }

#ifdef NDBM
  dbm_close(db);
#else
  gdbm_close(db);
#endif

  printf("Closed Db file. Suceeded!\n");

  return result;

}

void usage(void)
{
  printf("usage:\n");
  printf(" dbconverter <old sasldb> <realm>\n");
  exit(1);
}

int main(int argc, char **argv)
{
#ifdef HASNOTBEENEDITED
  printf("You did not specify which db format you are using before compiling this program.\n");
  exit(1);

#endif


  if (argc!=3)
    usage();

  printf("This program will take the sasldb file specified on the\n"
"command line and convert it to a new sasldb file in the default\n"
"location (usually /etc/sasldb). It is STRONGLY RECOMMENDED that you\n"
"remove sasldb before allowing this program to run\n\n"
"Press return to continue\n");
  getchar();

  dbm_convert(argv[1],argv[2]);  


  return 0;
}
