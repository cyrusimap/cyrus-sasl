/***************************************************************************
 *
 *           Copyright 1998 by Carnegie Mellon University
 * 
 *                       All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * Carnegie Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.
 * 
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL Carnegie Mellon University BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * 
 * Author: Ryan Troll <ryan+@andrew.cmu.edu>
 * 
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <sys/types.h>

#ifdef HAVE_STRINGS_H
# include <strings.h>
#else /* HAVE_STRINGS_H */
# include <string.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif /* HAVE_MALLOC_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

static char rcsid[] = 
"$Id: test-client.c,v 1.1 1998/11/19 02:00:25 ryan Exp $";

/***************************************************************************
 *
 ***************************************************************************/

/* ----------------------------------------------------------------------- */

#include <netdb.h>
#include <sys/param.h>
#include "sasl.h"
#include "saslint.h"
#include "saslutil.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "test-common.h"

#define TEST_USERID    "anonymous"
#define TEST_MECHANISM "ANONYMOUS"
#define TEST_SERVICE   "rcmd"



void checkerror(int result)
{
  const char *errstr;

  if ((result==SASL_OK) || (result==SASL_CONTINUE))
    return;
  
  errstr=sasl_errstring(result,NULL,NULL);

  fprintf(stderr, "error: (%i) %s\n", result, errstr);
  exit(1);
}


void Exit( sasl_conn_t *conn )

{
  fprintf(stderr, "Exiting.\n");
  sasl_dispose(&conn);
  sasl_done();
}

void Test( int fd, sasl_conn_t *conn )
{
  int result;
  char *in;
  int inlen;
  char *buf;
  int buflen;

  fprintf(stderr, "Waiting for encrypted test string from server.\n");

  test_ReadBuf('S', fd, &in, &inlen);

  fprintf(stderr, "Received %d bytes: '%.*s'\n", inlen, inlen, in);

  result = sasl_decode(conn, in, inlen, &buf, (unsigned int *)&buflen);
  checkerror(result);

  fprintf(stderr, "Decoded %d bytes: '%.*s'\n", buflen, buflen, buf);

  free(in);
  free(buf);
}

void interaction (sasl_interact_t *t)
{
  char result[1024];

  printf("%s:",t->prompt);
  scanf("%s",&result);

  t->len=strlen(result);
  t->result=(char *)malloc(t->len);
  memcpy(t->result, result, t->len);

}

static sasl_security_properties_t *make_secprops(char *Mechanism)
{
  int min = 0;
  int max = 0;
  sasl_security_properties_t *ret=(sasl_security_properties_t *)
    malloc(sizeof(sasl_security_properties_t));

  if (!strcmp(Mechanism, "KERBEROS_V4"))
    max = 56;

  ret->maxbufsize=1024;
  ret->min_ssf=min;
  ret->max_ssf=max;

  ret->security_flags=0;
  ret->property_names=NULL;
  ret->property_values=NULL;

  return ret;
}

void Usage(char *arg)
{
  if (arg)
    fprintf(stderr, "Unknown argument: %s\n", arg);
  fprintf(stderr, "\n");
  fprintf(stderr, "test-client [-d] [-v] [-u user] [-m mechanism] [-s service]\n");
  fprintf(stderr, "\n");
  exit(-1);
}


int main(int argc, char **argv)
{
  int result;
  sasl_conn_t *conn;
  sasl_secret_t *secret;
  sasl_interact_t *client_interact=NULL;
  int fd;

  char *serverin, *clientout;
  int serverinlen, clientoutlen;
  char *mechusing;

  int   Verbose   = 0;
  char *Mechanism = TEST_MECHANISM;
  char *UserID    = TEST_USERID;
  char *Service   = TEST_SERVICE;

  char hostname[MAXHOSTNAMELEN];
  extern int _sasl_debug;

  int c;

  while ((c = getopt (argc, argv, "dvu:m:s:")) != -1)
    switch (c)
    {
    case 'd':
      _sasl_debug = 1;
      break;
    case 'v':
      Verbose = 1;
      break;
    case 'u':
      UserID = optarg;
      break;
    case 's':
      Service = optarg;
      break;
    case 'm':
      Mechanism = optarg;
      break;
    default:
      Usage(NULL);
    }

  printf("Using mechanism %s\n", Mechanism);
  printf("Using userid %s\n", UserID);
  printf("Using service %s\n", Service);

  /* 0: Initialize */
  gethostname(hostname, MAXHOSTNAMELEN);

  secret=malloc(sizeof(sasl_secret_t)+9);
  strcpy(secret->data,"password");
  secret->len=strlen(secret->data);

  /* 1: client init */
  result=sasl_client_init(NULL);
  checkerror(result);

  fprintf(stderr, "Ready and waiting for server mechanisms.\n");

  /* 2: client new connection */
  result=sasl_client_new(Service, hostname, NULL, 0, &conn);

  /* Initialize connection properties */
  {
    sasl_security_properties_t *secprops=NULL;
    int ssf;
    struct hostent *hp;
    if ((hp = gethostbyname(hostname)) == NULL) {
	perror("gethostbyname");
	exit(1);
    }

    sasl_setprop(conn, SASL_USERNAME, UserID);
    sasl_setprop(conn, SASL_IP_LOCAL, &(hp->h_addr));
    sasl_setprop(conn, SASL_IP_REMOTE, &(hp->h_addr));

    ssf=0;
    sasl_setprop(conn, SASL_SSF_EXTERNAL, &ssf);  

    secprops = make_secprops(Mechanism);
    if (secprops!=NULL)
      sasl_setprop(conn, SASL_SEC_PROPS, secprops);
  }

  /* Read mechanisms from server */
  result = test_ReadBuf('S', 0, &serverin, &serverinlen);
  if (result == 0) Exit(conn);

  /* 3: Let SASL client decide what mechanism to use */
  result=sasl_client_start(conn, Mechanism, /* serverin  / mechlist */
			   secret, &client_interact,
			   &clientout, &clientoutlen,
			   &mechusing);

  if (client_interact != NULL) {
    interaction(client_interact); /* fill in prompt */
    result=sasl_client_start(conn, Mechanism, /* serverin / mechlist */
			     secret, &client_interact,
			     &clientout, &clientoutlen,
			     &mechusing);
  }
  checkerror(result);

  /* ASSERT: result should be SASL_OK */

  if (Verbose)
    fprintf(stderr, "client_start: out %d, %d (%s)\n",
	    clientoutlen, result, sasl_errstring(result,NULL,NULL));

  /* start server with the mech and any initial data */
  test_WriteBuf('C', 1, mechusing, strlen(mechusing));
  test_WriteBuf('C', 1, clientout, clientoutlen);

  /* ------------------------------------------------------------ */

  result = SASL_CONTINUE;

  while (result == SASL_CONTINUE) {

    result = test_ReadBuf('S', 0, &serverin, &serverinlen);

    result = sasl_client_step(conn,
			      serverin, serverinlen,
			      &client_interact,
			      &clientout, &clientoutlen);

    if (client_interact != NULL) {
      interaction(client_interact);

      result = sasl_client_step(conn,
				serverin, serverinlen,
				&client_interact,
				&clientout, &clientoutlen);
    }

    test_WriteBuf('C', 1, clientout, clientoutlen);

    if (Verbose)
      fprintf(stderr, "client_step: out %d, %d (%s)\n",
	      clientoutlen, result, sasl_errstring(result,NULL,NULL));
  }

  fprintf(stderr, "Authentication complete.\n");

  /* ASSERT:  We're done. */
  Test(0, conn);
  Exit(conn);
  return(1);
}
