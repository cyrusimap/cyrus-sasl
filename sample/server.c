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
#include <stdarg.h>
#include <ctype.h>
#include <sysexits.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sasl.h>

#include "common.h"

/* create a socket listening on port 'port' */
int listensock(const char *port)
{
    struct sockaddr_in sin;
    struct servent *serv;
    int salen = sizeof(sin);
    int sock;
    int on = 1;

    memset(&sin, 0, sizeof(sin));
    
    serv = getservbyname(port, "tcp");
    if (serv) {
	sin.sin_port = serv->s_port;
    } else {
	sin.sin_port = htons(atoi(port));
	if (sin.sin_port == 0) {
	    fprintf(stderr, "port '%s' unknown\n", port);
	    exit(EX_USAGE);
	}
    }
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
	perror("socket");
	exit(EX_OSERR);
    }
    
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
		   (void *) &on, sizeof(on)) < 0) {
	perror("setsockopt");
	exit(EX_OSERR);
    }

    if (bind(sock, &sin, salen) < 0) {
	perror("bind");
	exit(EX_OSERR);
    }

    if (listen(sock, 5) < 0) {
	perror("listen");
	exit(EX_OSERR);
    }

    return sock;
}

void usage(void)
{
    fprintf(stderr, "usage: server [-p port] [-s service] [-m mech]\n");
    exit(EX_USAGE);
}

/* globals because i'm lazy */
char *mech;

/* do the sasl negotiation; return -1 if it fails */
int mysasl_negotiate(FILE *in, FILE *out, sasl_conn_t *conn)
{
    char buf[8192];
    char chosenmech[128];
    char *data;
    int len;
    int r;
    const char *errstr;
    const char *userid;
    
    /* generate the capability list */
    if (mech) {
	dprintf(2, "forcing use of mechanism %s\n", mech);
	data = strdup(mech);
    } else {
	int count;

	dprintf(1, "generating client mechanism list... ");
	r = sasl_listmech(conn, NULL, NULL, " ", NULL,
			  &data, &len, &count);
	if (r != SASL_OK) saslfail(r, "generating mechanism list", NULL);
	dprintf(1, "%d mechanisms\n", count);
    }

    /* send capability list to client */
    send_string(out, data, len);

    dprintf(1, "waiting for client mechanism...\n");
    len = recv_string(in, chosenmech, sizeof chosenmech);
    if (len <= 0) {
	printf("client didn't choose mechanism\n");
	fputc('N', out); /* send NO to client */
	fflush(out);
	return -1;
    }

    if (mech && strcasecmp(mech, chosenmech)) {
	printf("client didn't choose mandatory mechanism\n");
	fputc('N', out); /* send NO to client */
	fflush(out);
	return -1;
    }

    /* receive initial response (if any) */
    len = recv_string(in, buf, sizeof(buf));

    /* start libsasl negotiation */
    r = sasl_server_start(conn, chosenmech, buf, len,
			  &data, &len, &errstr);
    if (r != SASL_OK && r != SASL_CONTINUE) {
	saslerr(r, "starting SASL negotiation", errstr);
	fputc('N', out); /* send NO to client */
	fflush(out);
	return -1;
    }

    while (r == SASL_CONTINUE) {
	if (data) {
	    dprintf(2, "sending response length %d...\n", len);
	    fputc('C', out); /* send CONTINUE to client */
	    send_string(out, data, len);
	    free(data);
	} else {
	    dprintf(2, "sending null response...\n");
	    fputc('C', out); /* send CONTINUE to client */
	    send_string(out, "", 0);
	}

	dprintf(1, "waiting for client reply...\n");
	len = recv_string(in, buf, sizeof buf);
	if (len < 0) {
	    printf("client disconnected\n");
	    return -1;
	}

	r = sasl_server_step(conn, buf, len, &data, &len, &errstr);
	if (r != SASL_OK && r != SASL_CONTINUE) {
	    saslerr(r, "performing SASL negotiation", errstr);
	    fputc('N', out); /* send NO to client */
	    fflush(out);
	    return -1;
	}
    }

    if (r != SASL_OK) {
	saslerr(r, "incorrect authentication", errstr);
	fputc('N', out); /* send NO to client */
	fflush(out);
	return -1;
    }

    fputc('O', out); /* send OK to client */
    fflush(out);
    dprintf(1, "negotiation complete\n");
    if (data) {
	free(data);
    }

    r = sasl_getprop(conn, SASL_USERNAME, (void **) &userid);
    printf("successful authentication '%s'\n", userid);

    return 0;
}

int main(int argc, char *argv[])
{
    int c;
    char *port = "12345";
    char *service = "rcmd";
    int l;
    int r;
    sasl_conn_t *conn;

    while ((c = getopt(argc, argv, "p:s:m:")) != EOF) {
	switch(c) {
	case 'p':
	    port = optarg;
	    break;

	case 's':
	    service = optarg;
	    break;

	case 'm':
	    mech = optarg;
	    break;

	default:
	    usage();
	    break;
	}
    }

    /* initialize the sasl library */
    r = sasl_server_init(NULL, "sample");
    if (r != SASL_OK) saslfail(r, "initializing libsasl", NULL);

    /* get a listening socket */
    l = listensock(port);
    for (;;) {
	struct sockaddr_in localaddr, remoteaddr;
	int salen;
	int fd = -1;
	FILE *in, *out;

	fd = accept(l, NULL, NULL);
	if (fd < 0) {
	    perror("accept");
	    exit(0);
	}

	printf("accepted new connection\n");

	r = sasl_server_new(service, NULL, NULL, NULL,
			    SASL_SECURITY_LAYER, &conn);
	if (r != SASL_OK) saslfail(r, "allocating connection state", NULL);

	/* set external properties here
	   sasl_setprop(conn, SASL_SSF_EXTERNAL, &extprops); */

	/* set required security properties here
	   sasl_setprop(conn, SASL_SEC_PROPS, &secprops); */

	/* set ip addresses */
	salen = sizeof(localaddr);
	if (getsockname(fd, (struct sockaddr *)&localaddr, &salen) < 0) {
	    perror("getsockname");
	}
	salen = sizeof(remoteaddr);
	if (getpeername(fd, (struct sockaddr *)&remoteaddr, &salen) < 0) {
	    perror("getpeername");
	}

	r = sasl_setprop(conn, SASL_IP_LOCAL, &localaddr);
	if (r != SASL_OK) saslfail(r, "setting local IP address", NULL);
	r = sasl_setprop(conn, SASL_IP_REMOTE, &remoteaddr);
	if (r != SASL_OK) saslfail(r, "setting local IP address", NULL);

	in = fdopen(fd, "r");
	out = fdopen(fd, "w");

	r = mysasl_negotiate(in, out, conn);
	if (r == SASL_OK) {
	    /* send/receive data */


	}

	printf("closing connection\n");
	fclose(in);
	fclose(out);
	close(fd);
	sasl_dispose(&conn);
    }

    sasl_done();
}
