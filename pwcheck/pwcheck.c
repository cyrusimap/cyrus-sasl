/* pwcheck.c -- Unix pwcheck daemon
   $Id: pwcheck.c,v 1.3 1999/11/15 06:30:41 leg Exp $
Copyright 1998, 1999 Carnegie Mellon University

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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include <config.h>

extern int errno;

void newclient(int);
int retry_write(int, const char *, unsigned);

/*
 * Unix pwcheck daemon-authenticated login (shadow password)
 */

int
main()
{
    char fnamebuf[1024];
    int s;
    int c;
    struct sockaddr_un srvaddr;
    struct sockaddr_un clientaddr;
    int r;
    int len;
    mode_t oldumask;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	perror("socket");
	exit(1);
    }

    strcpy(fnamebuf, PWCHECKDIR);
    strcat(fnamebuf, "/pwcheck");

    (void) unlink(fnamebuf);

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    /* Most systems make sockets 0777 no matter what you ask for.
       Known exceptions are Linux and DUX. */
    oldumask = umask((mode_t) 0); /* for Linux, which observes the umask when
			    setting up the socket */
    r = bind(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    if (r == -1) {
	perror(fnamebuf);
	exit(1);
    }
    umask(oldumask); /* for Linux */
    chmod(fnamebuf, (mode_t) 0777); /* for DUX, where this isn't the default.
				    (harmlessly fails on some systems) */	
    r = listen(s, 5);
    if (r == -1) {
	perror("listen");
	exit(1);
    }

    for (;;) {
	len = sizeof(clientaddr);
	c = accept(s, (struct sockaddr *)&clientaddr, &len);
	if (c == -1) {
	    perror("accept");
	    continue;
	}

	newclient(c);
    }
}

void newclient(int c)
{
    char request[1024];
    int start, n;
    char *reply;
    extern char *pwcheck();
    
    start = 0;
    while (start < sizeof(request) - 1) {
	n = read(c, request+start, sizeof(request) - 1 - start);
	if (n < 1) {
	    reply = "Error reading request";
	    goto sendreply;
	}
		
	start += n;

	if (request[start-1] == '\0' && strlen(request) < start) {
	    break;
	}
    }

    if (start >= sizeof(request) - 1) {
	reply = "Request too big";
    }
    else {
	reply = pwcheck(request, request + strlen(request) + 1);
    }

sendreply:

    retry_write(c, reply, strlen(reply));
    close(c);
}
  
/*
 * Keep calling the write() system call with 'fd', 'buf', and 'nbyte'
 * until all the data is written out or an error occurs.
 */
int retry_write(int fd, const char *buf, unsigned nbyte)
{
    int n;
    int written = 0;

    if (nbyte == 0) return 0;

    for (;;) {
        n = write(fd, buf, nbyte);
        if (n == -1) {
            if (errno == EINTR) continue;
            return -1;
        }

        written += n;

        if (n >= nbyte) return written;

        buf += n;
        nbyte -= n;
    }
}
