/* test.c - SASL tester
 * Tim Martin
 * $Id: test.c,v 1.1 1998/11/16 20:06:37 rob Exp $
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


#include <netdb.h>
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/param.h>
#include "sasl.h"
#include "saslint.h"
#include "saslutil.h"
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#define TESTSTRING "i like ice cream!"
#define TEST_USERID "tmartin"
#define TEST_PORT 143;


void interaction (sasl_interact_t *t)
{
  char result[1024];

  printf("%s:",t->prompt);
  scanf("%s",&result);

  t->len=strlen(result);
  t->result=malloc(t->len);
  memcpy(t->result, result, t->len);

}

void exit_program(sasl_conn_t *conn)
{
  sasl_dispose(&conn);
  printf("did sasl_dispose\n");
  
  sasl_done();
  printf("did sasl_done\n");
}

void checkerror(int result)
{
  const char *errstr;

  if ((result==SASL_OK) || (result==SASL_CONTINUE))
    return;
  
  errstr=sasl_errstring(result,NULL,NULL);
  printf("error: (%i) %s\n",result, errstr);
  exit(1);
}

void usage()
{
  printf("usage: test -f mechanism_name\n");
  exit(1);
}

int main(int argc, char **argv)
{
  struct hostent *hp;
  int ipaddr;
  sasl_interact_t *client_interact=NULL;
  int lup,port;
  int result,clientresult;
  sasl_conn_t *conn;
  sasl_conn_t *c_conn;
  char *mechlist;
  const char *mechusing;
  char *b;
  int len=0,num=0;
  char *out,*out2;
  const char *errstr;
  int outlen;
  int ssf;
  sasl_secret_t *secret;
  char blah[4096];
  int blahlen;
  int filespec=0;
  /* parse command line options */
  char *cvalue = NULL;
  int c;
  char hostname[MAXHOSTNAMELEN];

  gethostname(hostname, MAXHOSTNAMELEN);

  while ((c = getopt (argc, argv, "f:")) != -1)
    switch (c)
    {
      case 'f':
        cvalue = optarg;
	filespec=1;
        break;
      default: usage();
    }
  if (filespec==0)
    usage();

  /* call memory/mutex functions */
  /* use default ones */

  /* client init */
  result=sasl_client_init(NULL,NULL);
  printf("sasl_client_init\n");
  checkerror(result);

  /* client new connection */
  result=sasl_client_new("smtp",
			 hostname,
			 NULL,
			 0,
			 &c_conn);

  printf("did sasl_client_new\n");
  checkerror(result);

  /* server init */
  result=sasl_server_init(NULL,NULL,"TESTAPP");
  printf("sasl_server_init\n");
  checkerror(result);

  /* server new connection */
  result=sasl_server_new("smtp",
			 hostname,
			 hostname,
			 NULL,
			 0,
			 &conn);

  printf("did sasl_server_new\n");
  checkerror(result);

  /* server list mechanisms */
  result=sasl_listmech(conn,
		"testuser",
		"",
		" ",
		"",
		&mechlist,
		&len,
		&num);

  printf("did sasl_listmech\n");
  checkerror(result);
  printf("list is: %s\n",mechlist);  

  /* create secret */
  secret=malloc(sizeof(sasl_secret_t)+9);
  strcpy(secret->data,"password");
  secret->len=strlen(secret->data);

  /* set username and port */
  sasl_setprop(c_conn, SASL_USERNAME, TEST_USERID);
  port=TEST_PORT;
  sasl_setprop(c_conn, SASL_PORTNUMBER, &port);
  sasl_setprop(conn, SASL_PORTNUMBER, &port);
  ssf=0;
  sasl_setprop(c_conn, SASL_SSF_EXTERNAL, &ssf);
  sasl_setprop(conn,   SASL_SSF_EXTERNAL, &ssf);  

  /* set server IP address */

    if ((hp = gethostbyname(hostname)) == NULL) {
	perror("gethostbyname");
	exit(1);
    }

  ipaddr=
    ((unsigned char) hp->h_addr[0])*256*256*256 +
    ((unsigned char) hp->h_addr[1])*256*256 +
    ((unsigned char) hp->h_addr[2])*256 +
    ((unsigned char) hp->h_addr[3]);

  sasl_setprop(conn,   SASL_IP_SERVER, &(ipaddr));  
  sasl_setprop(conn,   SASL_IP_CLIENT, &(ipaddr));  
  sasl_setprop(c_conn,   SASL_IP_CLIENT, &(ipaddr));  
  sasl_setprop(c_conn,   SASL_IP_SERVER, &(ipaddr));  

  /* call sasl client start */
  clientresult=sasl_client_start(c_conn, cvalue, /* mechlist */
			   secret, &client_interact,
			   &out2, &outlen,
			   &mechusing);

  if (client_interact!=NULL)
  {
    interaction(client_interact); /* fill in prompt */
    clientresult=sasl_client_start(c_conn, cvalue, /* mechlist */
			     secret, &client_interact,
			     &out2, &outlen,
			     &mechusing);
  }

  free(mechlist);
  printf("did sasl_client_start\n");
  checkerror(clientresult);
  printf("using mech=%s\n",mechusing);

  /* start server with the mech */
  printf("sending: mech using\n");
  result=sasl_server_start(conn,
		    mechusing,
		    out2,
		    outlen,
		    &out,
		    &outlen,
		    &errstr);
  

  printf("did sasl_server_start\n");
  checkerror(result);
  free(out2);



while (1)
{
  switch(clientresult) 
  {
    case SASL_CONTINUE:
        /* give client what server returned */

  clientresult=sasl_client_step(c_conn,
				out,
				outlen,
				&client_interact,
				&out2,
				&outlen);



  if (client_interact!=NULL)
  {
    interaction(client_interact); /* fill in prompt */
    clientresult=sasl_client_step(c_conn,
				  out,
				  outlen,
			    &client_interact,
			    &out2,
			    &outlen);
  }


  free((char *)out);
  out=NULL;
  printf("did sasl_client_step\n");
  checkerror(clientresult);

  /*printf("returned %i %s\n",outlen,out);*/

  /* give server what client says send what client returned */
  if (result==SASL_CONTINUE)
    result=sasl_server_step(conn,
			    out2,
			    outlen,
			    &out,
			    &outlen,
			    &errstr);

  printf("did sasl_server_step\n");
  checkerror(result);
  if (out2!=NULL)
    free((char *)out2);

  break;
    case SASL_OK:
      if (out!=NULL)
	free((char *) out);
      printf("send data from client -> server \n");
      result=sasl_encode(c_conn, TESTSTRING, strlen(TESTSTRING), &out,(unsigned int *) &outlen);
      checkerror(result);


      result=sasl_decode(conn,out, outlen, &b,(unsigned int *)&outlen);
      checkerror(result);
      for (lup=0;lup<outlen;lup++)
	printf("%c",b[lup]);       
      printf("\n");
      free((char *) b);
      free((char *) out);



      printf("send data from server -> client \n");
      result=sasl_encode(conn, TESTSTRING, strlen(TESTSTRING), &out,(unsigned int *)&outlen);
      checkerror(result);
      result=sasl_decode(c_conn,out, outlen, &b,(unsigned int *)&outlen);
      checkerror(result);
      for (lup=0;lup<outlen;lup++)
	printf("%c",b[lup]);       
      printf("\n");

      free((char *) b);
      free((char *)out);

      sasl_dispose(&conn);  
      printf("did sasl_dispose of server\n");

      sasl_dispose(&c_conn);  
      printf("did sasl_dispose of client\n");

      sasl_done();
      printf("did sasl_done\n");
      free(secret);
      return 0;
      break;
    default:
      break;

  }
}
 
}
