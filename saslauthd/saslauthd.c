/* MODULE: saslauthd */

/* COPYRIGHT
 * Copyright (c) 1997-2000 Messaging Direct Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY MESSAGING DIRECT LTD. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL MESSAGING DIRECT LTD. OR
 * ITS EMPLOYEES OR AGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * END COPYRIGHT */

/* OVERVIEW
 * saslauthd provides an interface between the SASL library and various
 * external authentication mechanisms. The primary goal is to isolate
 * code that requires superuser privileges (for example, access to
 * the shadow password file) into a single easily audited module. It
 * can also act as an authentication proxy between plaintext-equivelent
 * authentication schemes (i.e. CRAM-MD5) and more secure authentication
 * services such as Kerberos, although such usage is STRONGLY discouraged
 * because it exposes the strong credentials via the insecure plaintext
 * mechanisms.
 *
 * The program listens for connections on a UNIX domain socket. Access to
 * the service is controlled by the UNIX filesystem permissions on the
 * socket.
 *
 * The service speaks a very simple protocol. The client connects and
 * sends the authentication identifier, a NUL, the plaintext password,
 * and a NUL. The server returns a single response beginning with "OK"
 * or "NO", an optional text string (seperated from the OK/NO by a
 * single space character), and a NUL. The server then closes the
 * connection.
 *
 * An "OK" response indicates the authentication credentials are valid.
 * A "NO" response indicates the authentication failed.
 *
 * The optional text string may be used to indicate an exceptional
 * condition in the authentication environment that should be communicated
 * to the client.
 * END OVERVIEW */

/* HISTORY
 * saslauthd is a re-implementation of the pwcheck utility included
 * with the CMU Cyrus IMAP server circa 1997. This implementation
 * was written by Lyndon Nerenberg of Messaging Direct Inc. (which
 * at that time was the Esys Corporation) and was included in the
 * company's IMAP message store product (Simeon Message Service) as
 * the smsauthd utility.
 *
 * This implementation was contributed to CMU by Messaging Direct Ltd.
 * in September 2000.
 * END HISTORY */

#ifdef __GNUC__
#ident "$Id: saslauthd.c,v 1.4 2001/01/04 21:20:45 leg Exp $"
#endif

/* PUBLIC DEPENDENCIES */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef _AIX
# include <strings.h>
#endif /* _AIX */
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "config.h"
#include "mechanisms.h"
#include "globals.h"
/* END PUBLIC DEPENDENCIES */

/* PRIVATE DEPENDENCIES */
/* globals */
authmech_t *authmech;		/* Authentication mechanism we're using  */
authmech_t *proxymech;		/* Auth mechanism to proxy accounts from */
int	debug;			/* Debugging level.                      */
int	flag_use_tod;		/* Pay attention to TOD restrictions.    */
char	*r_host;		/* Remote host for rimap driver		 */
char	*r_service;		/* Remote service for rimap driver	 */
#if defined(AUTH_SIA)
int	g_argc;			/* Copy of argc for sia_* routines	 */
char	**g_argv;		/* Copy of argv for sia_* routines       */
#endif /* AUTH_SIA */
/* path_mux needs to be accessable to server_exit() */
char	*path_mux;		/* path to AF_UNIX socket */

extern char *optarg;		/* getopt() */

/* forward declarations */
void		do_request(int, int);
RETSIGTYPE 	server_exit(int);
RETSIGTYPE 	sigchld_ignore(int);
void		show_version(void);
/* END PRIVATE DEPENDENCIES */

#define LOCK_FILE_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH)
#define LOCK_SUFFIX ".pid"
#define MAX_REQ_LEN 1024		/* login/pw input buffer size */

#ifdef _AIX
# define SALEN_TYPE size_t
#else /* ! _AIX */
# define SALEN_TYPE int
#endif /* ! _AIX */
/* END PRIVATE DEPENDENCIES */

/* FUNCTION: main */

int
main(
  /* PARAMETERS */
  int argc,				/* I: number of cmdline arguments */
  char *argv[]				/* I: array of cmdline arguments */
  /* END PARAMETERS */
  ) {

    /* VARIABLES */
    int c;				/* general purpose character holder */
    int	count;				/* loop counter */
    int	s;				/* fd handle on the domain socket.
					   scratch usage while losing
					   controlling tty */
    int conn;				/* per-connection socket fd */
    int rc;				/* generic return code holder  */
    int lfd;				/* master lock file descriptor */
    char *lockfile;			/* master lock file name       */
    struct flock lockinfo;		/* fcntl locking on lockfile   */
    char *cwd;				/* current working directory path */
    pid_t pid;				/* fork() control */
    struct sockaddr_un server, client;	/* domain socket control */
    SALEN_TYPE len;			/* sockaddr_un address lengths */
#ifdef SO_REUSEADDR
    int one = 1;			/* sockopt control variable */
#endif /* SO_REUSEADDR */
    /* END VARIABLES */

#if defined(AUTH_SIA)
    /*
     * The doc claims this must be the very first thing executed
     * in main(). The doc also claims that if the kernel test for the
     * security features being loaded fails, the program exits! (OSF)
     */
    set_auth_parameters(argc, argv);
#endif /* AUTH_SIA */

    /* initialization */
    authmech = NULL;
    proxymech = NULL;
    debug = 0;
    flag_use_tod = 0;
    path_mux = PATH_SASLAUTHD_RUNDIR "/mux";
    r_host = NULL;
    openlog("saslauthd", LOG_PID|LOG_NDELAY, LOG_AUTH);
    syslog(LOG_INFO, "START: saslauthd %s", VERSION);

    /* parse the command line arguments */
    while ((c = getopt(argc, argv, "a:dF:H:m:P:Tv")) != -1)
	switch (c) {

	  case 'a':			/* authentication mechanism */
	    for (authmech = mechanisms; authmech->name != NULL; authmech++) {
		if (!strcasecmp(authmech->name, optarg))
		    break;
	    }
	    if (authmech->name == NULL) {
		syslog(LOG_ERR,
		       "FATAL: unknown authentication mechanism: %s",
		       optarg);
		fprintf(stderr,
			"saslauthd: unknown authentication mechanism: %s\n",
			optarg);
		exit(1);
	    }
	    break;
		
	  case 'd':			/* enable debugging */
	    debug++;
	    break;

	  case 'H':
	    r_host = strdup(optarg);
	    break;
	    
	  case 'm':			/* alternate MUX location */
	    if (*optarg != '/') {
		syslog(LOG_ERR, "FATAL: -m requires an absolute pathname");
		fprintf(stderr, "saslauthd: -m requires an absolute pathname");
		exit(1);
	    }
	    path_mux = optarg;
	    break;

	  case 'P':			/* proxy authentication mechanism */
	    for (proxymech = mechanisms; proxymech->name != NULL; proxymech++) {
		if (!strcasecmp(proxymech->name, optarg))
		    break;
	    }
	    if (proxymech->name == NULL) {
		syslog(LOG_ERR,
		       "FATAL: unknown authentication mechanism: %s",
		       optarg);
		fprintf(stderr,
			"saslauthd: unknown authentication mechanism %s\n",
			optarg);
		exit(1);
	    }
	    break;
		
	  case 'T':			/* honour time-of-day restrictions */
	    flag_use_tod++;
	    break;

	  case 'v':			/* display version info and exit */
	    show_version();	    
	    exit(0);
	    break;

	  default:
	    break;
	}
#if defined(AUTH_SIA)
    g_argc = argc;
    g_argv = argv;
#endif /* AUTH_SIA */

    umask(077);			/* don't leave readable core dumps */
    signal(SIGPIPE, SIG_IGN);	/* take an EPIPE on write(2) */
    
    /*
     * chdir() into the directory containing the named socket file.
     * This ensures any core dumps don't get clobbered by other programs.
     */

    cwd = strdup(path_mux);
    if (cwd == NULL) {
	syslog(LOG_ERR, "FATAL: strdup(path_mux) failure");
	fprintf(stderr, "saslauthd: strdup(path_mux) failure\n");
	exit(1);
    }
    if (strrchr(cwd, '/') != NULL)
	*(strrchr(cwd, '/')) = '\0';

    if (chdir(cwd) == -1) {
	rc = errno;
	syslog(LOG_ERR, "FATAL: chdir(%s): %m", cwd);
	fprintf(stderr, "saslauthd: ");
	errno = rc;
	perror(cwd);
	exit(1);
    }
    free(cwd);

    if (authmech == NULL) {
	syslog(LOG_ERR, "FATAL: no authentication mechanism specified");
	fprintf(stderr, "saslauthd: no authentication mechanism specified\n");
	exit(1);
    }

    /* sanity check authentication proxy */
    if (proxymech != NULL) {

	if (proxymech == authmech) {
	    syslog(LOG_ERR, "FATAL: -a and -P specify identical mechanisms");
	    fprintf(stderr,
		    "saslauthd: -a and -P specify identical mechanisms\n");
	    exit(1);
	}

	/* : For now we can only create CRAM accounts */
	if (strcasecmp("sasldb", authmech->name)) {
	    syslog(LOG_ERR, "FATAL: %s does not support proxy creation",
		   authmech->name);
	    fprintf(stderr, "saslauthd: %s does not support proxy creation",
		    authmech->name);
	    exit(1);
	}
    }

    /* if we are running in debug mode, do not fork and exit */	
    if (!debug) {
	/* fork/exec/setsid into a new process group */
	count = 5;
	while (count--) {
	    pid = fork();
	    
	    if (pid > 0)
		_exit(0);		/* parent dies */
	    
	    if ((pid == -1) && (errno == EAGAIN)) {
		syslog(LOG_WARNING, "master fork failed (sleeping): %m");
		sleep(5);
		continue;
	    }
	}
	if (pid == -1) {
	    rc = errno;
	    syslog(LOG_ERR, "FATAL: master fork failed: %m");
	    fprintf(stderr, "saslauthd: ");
	    errno = rc;
	    perror("fork");
	    exit(1);
	}

	/*
	 * We're now running in the child. Lose our controlling terminal
	 * and obtain a new process group.
	 */
	if (setsid() == -1) {
	    rc = errno;
	    syslog(LOG_ERR, "FATAL: setsid: %m");
	    fprintf(stderr, "saslauthd: ");
	    errno = rc;
	    perror("setsid");
	    exit(1);
	}
	
	s = open("/dev/null", O_RDWR, 0);
	if (s == -1) {
	    rc = errno;
	    syslog(LOG_ERR, "FATAL: /dev/null: %m");
	    fprintf(stderr, "saslauthd: ");
	    errno = rc;
	    perror("/dev/null");
	    exit(1);
	    
	}
	dup2(s, fileno(stdin));
	dup2(s, fileno(stdout));
	dup2(s, fileno(stderr));
	if (s > 2) {
	    close(s);
	}
    } /* end if(!debug) */

    lockfile = malloc(strlen(path_mux) + sizeof(LOCK_SUFFIX));
    if (lockfile == NULL) {
	syslog(LOG_ERR, "malloc(lockfile) failed");
	exit(1);
    }
    
    strcpy(lockfile, path_mux);
    strcat(lockfile, LOCK_SUFFIX);
    
    lfd = open(lockfile, O_WRONLY|O_CREAT, LOCK_FILE_MODE);
    if (lfd < 0) {
	syslog(LOG_ERR, "FATAL: %s: %m", lockfile);
	exit(1);
    }
    /* try to get an exclusive lock */
    lockinfo.l_type = F_WRLCK;
    lockinfo.l_start = 0;
    lockinfo.l_len = 0;
    lockinfo.l_whence = SEEK_SET;
    rc = fcntl(lfd, F_SETLK, &lockinfo);
    if (rc == -1) {
	/*
	 * Probably another daemon running. Different systems return
	 * different errno values if the file is already locked so we
	 * can't pretty-print an "another daemon is running" message.
	 */
	syslog(LOG_ERR, "FATAL: setting master lock on %s: %m", lockfile);
	exit(1);
    }
    
    /* write in the process id */
    {
	char pid_buf[100];
	int l;
	
	sprintf(pid_buf, "%lu\n", (unsigned long)getpid());
	l = strlen(pid_buf);
	rc = write(lfd, pid_buf, l);
	if (rc < 0) {
	    syslog(LOG_ERR, "FATAL: %s: %m", lockfile);
	    exit(1);
	} else if (rc != l) {
	    syslog(LOG_ERR, "FATAL: %s: short write (%d != %d)",
		   lockfile, rc, l);
	    exit(1);
	}
    }
		      
    /*
     * Exit handlers must be in place before creating the socket.
     */
    signal(SIGHUP,  server_exit);
    signal(SIGINT,  server_exit);
    signal(SIGTERM, server_exit);

    /* unlink any stray turds from a previous run */
    (void)unlink(path_mux);
    
    s = socket(AF_UNIX, SOCK_STREAM, 0);

    if (s == -1) {
	syslog(LOG_ERR, "FATAL: socket :%m");
	exit(1);
    }

    memset(&server, 0, sizeof(server));
    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, path_mux);
#ifdef SO_REUSEADDR
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));
#endif
    
    /*
     * Some UNIXen honour the mode bits on a domain socket, others don't.
     * Since this isn't predictable we create the socket mode 777 and
     * use the permissions on the socket's directory to control access.
     */
    umask(0);
    rc = bind(s, (struct sockaddr *)&server, sizeof(server));
    if (rc == -1) {
	syslog(LOG_ERR, "FATAL: %s: %m", path_mux);
	closelog();
	/* unlink(path_mux); */
	exit(1);
    }
    
    if (chmod(path_mux, S_IRWXU|S_IRWXG|S_IRWXO) == -1) {
	syslog(LOG_ERR, "FATAL: chmod(%s): %m", path_mux);
	closelog();
	exit(1);
    }
    fchmod(s, S_IRWXU|S_IRWXG|S_IRWXO);
    umask(077);				/* restore a secure umask */

    /* perform any auth mechanism specific initializations */
    if (authmech->initialize != NULL) {
	if (authmech->initialize() != 0) {
	    syslog(LOG_ERR,
		   "FATAL: %s initialization failed",
		   authmech->name);
	    closelog();
	    exit(1);
	}
    }
    if ((proxymech != NULL) && (proxymech->initialize != NULL)) {
	if (proxymech->initialize() != 0) {
	    syslog(LOG_ERR,
		   "FATAL: %s initialization failed",
		   proxymech->name);
	    closelog();
	    exit(1);
	}
    }

    if (listen(s, 5) == -1) {
	syslog(LOG_ERR, "FATAL: listen: %m");
	closelog();
	exit(1);
    };
    
    syslog(LOG_INFO, "daemon started, listening on %s", path_mux);

    len = sizeof(client);

    signal(SIGCHLD, sigchld_ignore);
    
    while (1) {

	conn = accept(s, (struct sockaddr *)&client, &len);
	if (conn == -1) {
	    if (errno != EINTR) {
		/*
		 * We get EINTR whenever a child process terminates.
		 * That's not an error.
		 */
		syslog(LOG_ERR, "accept: %m");
	    }
	    continue;
	} 

	if (!debug) {
	    pid = fork();
	    if (pid == 0) {			/* child */
		close(s);
		do_request(conn, conn);	/* process the request */
		close(conn);
		closelog();
		exit(0);
	    }
	    if (pid > 0) {			/* parent */
		close(conn);
	    }
	    if (pid == -1) {
		syslog(LOG_ERR, "accept fork: %m");
		close(conn);
	    }
	} else {
	    do_request(conn, conn);
	    close(conn);
	}
    }

    /*NOTREACHED*/
    exit(0);
}

/* END FUNCTION: main */

/* FUNCTION: do_request */

/* SYNOPSIS
 * do_request: handle an incoming authentication request.
 *
 *	This function is the I/O interface between the socket
 *	and auth mechanism. It reads data from the socket until both
 *	a login id and password have been seen, calls the
 *	mechanism-specific authentication routine, and sends
 *	the result out to the client.
 * END SYNOPSIS */

void
do_request
(
  /* PARAMETERS */
  int in,				/* I: input file descriptor  */
  int out				/* I: output file descriptor */
  /* END PARAMETERS */
  )
{
    /* VARIABLES */
    char rb[MAX_REQ_LEN + 1];		/* input buffer */
    char *c;				/* scratch pointer */
    char *reply;			/* authentication response message.
					   This is a malloc()ed string that
					   is free()d at the end. If you assign
					   this internally, make sure to
					   strdup() the string you assign. */
    int count;				/* input data byte counter */
    int rc;				/* general purpose return code */
    int nul_count;			/* # of '\0' seen in input stream */
    char *login;			/* account name to authenticate */
    char *password;			/* password for authentication */
    int error_condition;		/* 1: error occured, can't continue */
/* END VARIABLES */

    /* initialization */
    count = 0;
    rc = 0;
    c = rb;
    nul_count = 0;
    error_condition = 0;
    reply = NULL;

    /*
     * The input data stream consists of the login id, a NUL,
     * the password, and a NUL. We read() until we have
     * seen two NUL characters, then dispatch the data.
     */
    while ((count < MAX_REQ_LEN) && (nul_count < 2)) {
	rc = read(in, c, MAX_REQ_LEN - count);
	if (rc == -1) {
	    if (errno == EINTR)
		continue;
	    else {
		syslog(LOG_ERR, "do_request read(fd=%d): %m");
		return;
	    }
	}
	if (rc == 0) {
	    syslog(LOG_WARNING, "do_request: NUL read?");
	    return;
	}
	count += rc;
	while (rc--)
	    if (*c++ == '\0')
		nul_count++;
    }
  
    if (count < 2) {
	/*
	 * Fell off the end of the buffer before receiving all the
	 * data. This is probably someone trying to exploit a buffer
	 * overflow ...
	 */

	error_condition = 1;
	syslog(LOG_ERR,
	       "ALERT: input data exceeds %d bytes! Possible intrusion attempt?",
	       MAX_REQ_LEN);
	reply = strdup("NO");		/* Don't give them any hint as to why*/
					/* this failed, in the hope that they*/
					/* will keep banging on the door long*/
					/* enough for someone to take action.*/
    }

    login = strdup(rb);			/* make a copy of the  account name */
    password = rb + strlen(rb) + 1;	/* point to password */

    if ((*login == '\0') || (*password == '\0')) {
	error_condition = 1;
	syslog(LOG_NOTICE, "null login/password received");
	reply = strdup("NO Null login/password (saslauthd)");
    } else {
	if (debug) {
	    syslog(LOG_DEBUG, "authenticating %s", login);
	}
    }

    if (!error_condition) {
	reply = authmech->authenticate(login, password);
	memset(password, 0, strlen(password));

	if (reply == NULL) {
	    error_condition = 1;
	    syslog(LOG_ERR,
		   "AUTHFAIL: mechanism %s doesn't grok this environment",
		   authmech->name);
	    reply = strdup("NO authentication mechanism failed to cope! (saslauthd)");
	}
    }

    if (!strncmp(reply, "NO", sizeof("NO")-1)) {
	if (strlen(reply) < sizeof("NO "))
	    syslog(LOG_WARNING, "AUTHFAIL: %s", login);
	else
	    syslog(LOG_WARNING, "AUTHFAIL: %s [%s]", login, reply + 3);
    } else {
	if (debug) {
	    syslog(LOG_INFO, "OK: %s", login);
	}
    }

    free(login);
    
    /* write the response out the socket */
    count = 0;
    while (1) {
	int n = strlen(reply);

	rc = write(out, reply, n);
	if (rc == -1) {
	    if (errno == EINTR)
		continue;
	    syslog(LOG_ERR, "do_request write failed: %m");
	    free(reply);
	    return;
	}
	count += rc;
	if (count >= n)
	    break;			/* finished */
	reply += n;
	count -= n;
    }

    free(reply);
    return;
}

/* END FUNCTION: do_request */

/* FUNCTION: show_version */

/* SYNOPSIS
 * print the program version number on stderr, then exit.
 * END SYNOPSIS */

void					/* R: none */
show_version(
  /* PARAMETERS */
  void					/* I: none */
  /* END PARAMETERS */
  )
{
    /* VARIABLES */
    authmech_t *authmech;		/* authmech table entry pointer */
    /* END VARIABLES */
    
    fprintf(stderr, "saslauthd %s\nauthentication mechanisms:", 
            VERSION);
    for (authmech = mechanisms; authmech->name != NULL; authmech++) {
	fprintf(stderr, " %s", authmech->name);
    }
    fputs("\n", stderr);
    exit(0);
    /* NOTREACHED */
}

/* END FUNCTION: show_version */

/* FUNCTION: server_exit */

/* SYNOPSIS
 * Terminate the server upon receipt of a signal.
 * END SYNOPSIS */

RETSIGTYPE				/* R: OS dependent */
server_exit(
  /* PARAMETERS */
  int sig				/* I: signal number */
  /* END PARAMETERS */
  )
{
    syslog(LOG_NOTICE, "Caught signal %d. Cleaning up and terminating.", sig);
    exit(0);
    /* NOTREACHED */
}

/* END FUNCTION: server_exit */

/* FUNCTION: sigchld_ignore */

/* SYNOPSIS
 * Reap process status from terminated children.
 * END SYNOPSIS */

RETSIGTYPE				/* R: OS dependent */
sigchld_ignore (
  /* PARAMETERS */
  int sig __attribute__((unused))	/* I: signal number */
  /* END PARAMETERS */
  )
{
    /* VARIABLES */
    pid_t pid;				/* process id from waitpid() */
    /* END VARIABLES */

    while ((pid = waitpid(-1, 0, WNOHANG)) > 0) {
	/*
	 * We don't do anything with the results from waitpid(), however
	 * we still need to call it to prevent terminated children from
	 * becoming zombies and filling the proc table.
	 */
    }
    /* Re-load the signal handler. */
    signal(SIGCHLD, sigchld_ignore);
    
#if RETSIGTYPE == void
    return;
#else
    return 0;
#endif
}

/* END FUNCTION: sigchld_ignore */
