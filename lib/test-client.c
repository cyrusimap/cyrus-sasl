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

#ifdef WIN32
# include "winconfig.h"
#endif /* WIN32 */

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

/***************************************************************************
 *
 ***************************************************************************/

/* ----------------------------------------------------------------------- */

#ifdef WIN32
#else /* WIN32 */
#include <netdb.h>
#include <sys/param.h>
#endif /* WIN32 */
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
  unsigned inlen;
  char *buf;
  unsigned buflen;

  fprintf(stderr, "Waiting for encrypted test string from server.\n");

  test_ReadBuf('S', fd, &in, &inlen);

  fprintf(stderr, "Received %d bytes: '%*s'\n", inlen, inlen, in);

  result = sasl_decode(conn, in, inlen, &buf, (unsigned int *)&buflen);
  checkerror(result);

  fprintf(stderr, "Decoded %d bytes: '%*s'\n", buflen, buflen, buf);

  free(in);
  free(buf);
}

void interaction (sasl_interact_t *t)
{
  char result[1024];
  char *p;

  printf("%s:",t->prompt);
  fgets(result, 1024, stdin);

  t->len=strlen(result);
  p = (char *)malloc(t->len);
  t->result=p;
  memcpy(p, result, t->len);
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
  fprintf(stderr, "test-client [-d] [-v] [-e bits] [-u user] [-m mechanism] [-s service] [-r remotehostname]\n");
  fprintf(stderr, "\n");
  exit(-1);
}


int main(int argc, char **argv)
{
  int result;
  sasl_conn_t *conn;
  sasl_secret_t *secret;
  sasl_interact_t *client_interact=NULL;

  char *serverin, *clientout;
  unsigned serverinlen, clientoutlen;
  const char *mechusing;

  char hostname[MAXHOSTNAMELEN];

  int   External  = 0;
  int   Verbose   = 0;
  char *Mechanism = TEST_MECHANISM;
  char *UserID    = TEST_USERID;
  char *Service   = TEST_SERVICE;
  char *RemoteHost = hostname;

  extern int _sasl_debug;

  int arg;

  for (arg=1; arg<argc; arg++) {
    if (argv[arg][0] == '-') {
      switch(argv[arg][1]) {
      case 'd':
        _sasl_debug = 1;
        break;
      case 'v':
        Verbose = 1;
        break;
      case 'u':
        UserID = argv[++arg];
        break;  
      case 's':
        Service = argv[++arg];
        break;
      case 'm':
        Mechanism = argv[++arg];
        break;
      case 'r':
        RemoteHost = argv[++arg];
        break;
      case 'e':
        External = atoi(argv[++arg]);
        break;
      default:
        Usage(argv[arg]);
      } 
    } else {
      goto EndOfDashArgs;
    } /* End of - */
  } /* End of loop */

EndOfDashArgs:

#ifdef WIN32
  {
    WORD wVersionRequested;
    WSADATA wsaData;
    int err; 

    wVersionRequested = MAKEWORD( 2, 2 ); 

    err = WSAStartup( wVersionRequested, &wsaData );
    if ( err != 0 ) {
      fprintf(stderr, "Unable to start winsock!\n");
      exit(0);
    }
  }
#endif /* WIN32 */

  printf("Using mechanism %s\n", Mechanism);
  printf("Using userid %s\n", UserID);
  printf("Using service %s\n", Service);

  /* 0: Initialize */
  result = gethostname(hostname, MAXHOSTNAMELEN);

  printf("Local hostname: %s\n", hostname);
  printf("Remote hostname: %s\n", RemoteHost);

  secret=malloc(sizeof(sasl_secret_t)+9);
  strcpy(secret->data,"password");
  secret->len=strlen(secret->data);

  /* 1: client init */
  result=sasl_client_init(NULL);
  checkerror(result);

  fprintf(stderr, "Ready and waiting for server mechanisms.\n");

  /* 2: client new connection */
  result=sasl_client_new(Service, RemoteHost, NULL, 0, &conn);

  /* Initialize connection properties */
  if (External) {
    sasl_external_properties_t extprops;
    extprops.ssf = External;
    extprops.auth_id = UserID;
    sasl_setprop(conn, SASL_SSF_EXTERNAL, &extprops);
  }
  
  {
    sasl_security_properties_t *secprops=NULL;
    int ssf;
    struct hostent *hp;

    if ((hp = gethostbyname(hostname)) == NULL) {
      perror("gethostbyname");
      exit(1);
    }

    sasl_setprop(conn, SASL_IP_LOCAL, &(hp->h_addr));

    if ((hp = gethostbyname(RemoteHost)) == NULL) {
      perror("gethostbyname (remote)");
      exit(1);
    }
    sasl_setprop(conn, SASL_IP_REMOTE, &(hp->h_addr));

    sasl_setprop(conn, SASL_USERNAME, UserID);

    ssf=0;
    sasl_setprop(conn, SASL_SSF_EXTERNAL, &ssf);  

    secprops = make_secprops(Mechanism);
    if (secprops!=NULL)
      sasl_setprop(conn, SASL_SEC_PROPS, secprops);
  }

  /* Read mechanisms from server */
  result = test_ReadBuf('S', 0, &serverin, &serverinlen);
  if (result == 0) Exit(conn);

  if (Verbose)
    fprintf(stderr, "read mechanisms '%s', looking for '%s'\n", serverin, Mechanism);

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

/* result is still set from the above sasl_client_start.  May be
 * done already (IE: ANONYMOUS)
 *
 * result = SASL_CONTINUE;
 */

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
