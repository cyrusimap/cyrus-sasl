/* saslpasswd.c -- SASL password setting program
 * Rob Earhart
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

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

#include <config.h>
#include <termios.h>
#include <unistd.h>
#include <sasl.h>

#define PW_BUF_SIZE 2048

static const char build_ident[] = "$Build: saslpasswd " PACKAGE "-" VERSION " $";

const char *progname = NULL;

extern int _sasl_debug;

void read_password(const char *prompt,
		   int flag_pipe,
		   char ** password,
		   unsigned *passlen)
{
  char buf[PW_BUF_SIZE];
  struct termios ts, nts;
  ssize_t n_read;

  if (! flag_pipe) {
    fputs(prompt, stdout);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &ts);
    nts = ts;
    nts.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHOCTL| ECHOPRT | ECHOKE);
    nts.c_lflag |= ICANON | ECHONL;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &nts);
  }

  n_read = read(STDIN_FILENO, buf, PW_BUF_SIZE);
  if (n_read < 0) {
    perror(progname);
    exit(-SASL_FAIL);
  }

  if (! flag_pipe) {
    tcsetattr(STDIN_FILENO, TCSANOW, &ts);
    if (0 < n_read && buf[n_read - 1] != '\n') {
      /* if we didn't end with a \n, echo one */
      putchar('\n');
      fflush(stdout);
    }
  }

  if (0 < n_read && buf[n_read - 1] == '\n') /* if we ended with a \n */
    n_read--;			             /* remove it */

  *password = malloc(n_read + 1);
  if (! *password) {
    perror(progname);
    exit(-SASL_FAIL);
  }

  memcpy(*password, buf, n_read);
  (*password)[n_read] = '\0';	/* be nice... */
  *passlen = n_read;
}

void exit_sasl(int result, const char *errstr) __attribute__((noreturn));

void
exit_sasl(int result, const char *errstr)
{
  (void)fprintf(stderr, errstr ? "%s: %s: %s\n" : "%s: %s\n",
		progname,
		sasl_errstring(result, NULL, NULL),
		errstr);
  exit(-result);
}

int
main(int argc, char *argv[])
{
  int flag_pipe = 0, flag_create = 0, flag_disable = 0, flag_error = 0;
  int c;
  char *userid, *password, *verify;
  unsigned passlen, verifylen;
  const char *errstr = NULL;
  int result;
  sasl_conn_t *conn;
  char *user_domain = NULL;

  _sasl_debug=1;

  if (! argv[0])
    progname = "saslpasswd";
  else {
    progname = strrchr(argv[0], '/');
    if (progname)
      progname++;
    else
      progname = argv[0];
  }

  while ((c = getopt(argc, argv, "pcdu:h?")) != EOF)
    switch (c) {
    case 'p':
      flag_pipe = 1;
      break;
    case 'c':
      if (flag_disable)
	flag_error = 1;
      else
	flag_create = 1;
      break;
    case 'd':
      if (flag_create)
	flag_error = 1;
      else
	flag_disable = 1;
      break;
    case 'u':
      user_domain = optarg;
      break;
    default:
      flag_error = 1;
    }

  if (optind != argc - 1)
    flag_error = 1;

  if (flag_error) {
    (void)fprintf(stderr,
		  "%s: usage: %s [-p] [-c] [-d] [-u DOM] userid\n"
		  "\t-p\tpipe mode -- no prompt, password read on stdin\n"
		  "\t-c\tcreate -- ask mechs to create the account\n"
		  "\t-d\tdisable -- ask mechs to disable the account\n"
		  "\t-u DOM\tuse DOM for user domain\n",
		  progname, progname);
    exit(-SASL_FAIL);
  }

  userid = argv[optind];

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
  
  if (! flag_pipe && ! isatty(STDIN_FILENO))
    flag_pipe = 1;
  
  read_password("Password: ", flag_pipe, &password, &passlen);

  if (! flag_pipe) {
    read_password("Again (for verification): ", flag_pipe, &verify,
		  &verifylen);
    if (passlen != verifylen
	|| memcmp(password, verify, verifylen)) {
      fprintf(stderr, "%s: passwords don't match; aborting\n", progname);
      exit(-SASL_BADPARAM);
    }
  }

  printf("setting pass\n");
  result = sasl_setpass(conn,
			userid,
			password,
			passlen,
			(flag_create ? SASL_SET_CREATE : 0)
			| (flag_disable ? SASL_SET_DISABLE : 0),
			&errstr);
  printf("set pass\n");

  if (result != SASL_OK)
    exit_sasl(result, errstr);

  return 0;
}

