/*
 * Simple test server.
 */
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
"$Id: test-server.c,v 1.1 1998/11/19 02:00:26 ryan Exp $";

/***************************************************************************
 *
 ***************************************************************************/

/* ----------------------------------------------------------------------- */

#include <netdb.h>
#include <sys/param.h>
#include "sasl.h"
#include "saslint.h"
#include "saslutil.h"

#include "test-common.h"

#define TEST_STRING "If you receive this, everything worked."
#define TEST_SERVICE "rcmd"

void checkerror(int result)
{
  const char *errstr;
  char buf[1024];
  int buflen;

  if ((result==SASL_OK) || (result==SASL_CONTINUE))
    return;
  
  errstr=sasl_errstring(result,NULL,NULL);
  sprintf(buf, "error: (%i) %s", result, errstr); buflen = strlen(buf);
  test_WriteBuf('S', 1, buf, buflen);
  exit(1);
}


void Exit( sasl_conn_t *conn )

{
  printf("Exiting.\n");
  sasl_dispose(&conn);
  sasl_done();
}

void Test( sasl_conn_t *conn )
{
  int result;
  char *out;
  int outlen;

  result = sasl_encode(conn, TEST_STRING, strlen(TEST_STRING), &out, (unsigned int *)&outlen);
  checkerror(result);

  fprintf(stderr, "Sending for encrypted test string to client.\n");
  test_WriteBuf('S', 1, out, outlen);
  free(out);
}

void Usage(char *arg)
{
  if (arg)
    fprintf(stderr, "Unknown argument: %s\n", arg);
  fprintf(stderr, "\n");
  fprintf(stderr, "test-server [-d] [-v] [-s service]\n");
  fprintf(stderr, "\n");
  exit(-1);
}

int main(int argc, char **argv)
{
  int result;
  sasl_conn_t *conn;
  char hostname[MAXHOSTNAMELEN];
  char *mechlist;
  const char mechusing[1024];
  int len=0,num=0;
  char *clientin, *serverout;
  int clientinlen, serveroutlen;
  const char *errstr;

  extern int _sasl_debug;

  int   Verbose   = 0;
  char *Service   = TEST_SERVICE;

  int c;

  while ((c = getopt (argc, argv, "dvs:")) != -1)
    switch (c)
    {
    case 'd':
      _sasl_debug = 1;
      break;
    case 'v':
      Verbose = 1;
      break;
    case 's':
      Service = optarg;
      break;
    default:
      Usage(NULL);
    }

  printf("Using service %s\n", Service);

  /* 0: Initialize */
  gethostname(hostname, MAXHOSTNAMELEN);

  /* 1: server init -- load plugins */
  result=sasl_server_init(NULL, "TESTAPP");
  checkerror(result);

  /* 2: server new connection */
  result=sasl_server_new(Service,  /* Service */
			 hostname, /* Local domain */
			 hostname, /* Remote domain */
			 NULL,     /* Callbacks */
			 0,        /* Security flags */
			 &conn);   /* SASL connection */
  checkerror(result);

  /* Connection properties */
  {
    struct hostent *hp;
    if ((hp = gethostbyname(hostname)) == NULL) {
	perror("gethostbyname");
	exit(1);
    }

    sasl_setprop(conn,   SASL_IP_LOCAL, &(hp->h_addr));  
    sasl_setprop(conn,   SASL_IP_REMOTE, &(hp->h_addr));
  }

  /* 3: list mechanisms, and send them to the client */
  result=sasl_listmech(conn,        /* Mechanisms for this connection */
		       NULL,  /* User for these mechanisms */
		       "",          /* List prefix */
		       " ",         /* List separator */
		       "",          /* List suffix */
		       &mechlist,   /* Returned string */
		       &len,        /* Length of string */
		       &num);       /* Number of mechanisms */
  checkerror(result);
  {
    char buf[1024];
    int buflen;
    sprintf(buf, "mechlist: %s", mechlist); buflen = strlen(buf);
    test_WriteBuf('S', 1, buf, buflen);
  }
  free(mechlist);

  /* 4: Client specifies mechanism */
  result = test_ReadBuf('C', 0, &clientin, &clientinlen);
  if (result == 0) Exit(conn);
  sscanf(clientin, "%s\n", &mechusing);
  free(clientin);

  /* Client sends some authentication info, and we begin */
  clientin = NULL;
  clientinlen = 0;

  result = test_ReadBuf('C', 0, &clientin, &clientinlen);
  if (result == 0) Exit(conn);
  result=sasl_server_start(conn,
			   mechusing,   /* Client specified mechanism */
			   clientin,    /* Client initial response */
			   clientinlen, /* Client initial response len */
			   &serverout,  /* Server challenge */
			   &serveroutlen, /* Server challenge length */
			   &errstr);      /* Error condition */
  free(clientin);

  if (Verbose)
    fprintf(stderr, "server_start: returned %d (%s)\n", 
	    result, sasl_errstring(result,NULL,NULL));

  while (result == SASL_CONTINUE) {

    /* Send data to the client, and receive the next string. */
    test_WriteBuf('S', 1, serverout, serveroutlen);
    free(serverout);

    /* Read data from client */
    result = test_ReadBuf('C', 0, &clientin, &clientinlen);
    if (result == 0) Exit(conn);

    result=sasl_server_step(conn,
			    clientin,
			    clientinlen,
			    &serverout,
			    &serveroutlen,
			    &errstr);
    free(clientin);

    if (Verbose)
      fprintf(stderr, "server_step: returned %d (%s)\n", 
	      result, sasl_errstring(result,NULL,NULL));
  }

  if (result == SASL_OK)
    Test(conn);

  Exit(conn);
}
