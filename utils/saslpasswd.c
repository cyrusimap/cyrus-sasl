/* saslpasswd.c -- SASL password setting program
 * Rob Earhart
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

#include <config.h>
#ifndef WIN32
#include <termios.h>
#include <unistd.h>
#else
#include <stdio.h>
#include <io.h>
typedef int ssize_t;
#define STDIN_FILENO stdin
#include <saslutil.h>
__declspec(dllimport) char *optarg;
__declspec(dllimport) int optind;
__declspec(dllimport) int getsubopt(char **optionp, char * const *tokens, char **valuep);
#endif /*WIN32*/
#include <sasl.h>

#define PW_BUF_SIZE 2048

static const char build_ident[] = "$Build: saslpasswd " PACKAGE "-" VERSION " $";

const char *progname = NULL;

void read_password(const char *prompt,
		   int flag_pipe,
		   char ** password,
		   unsigned *passlen)
{
  char buf[PW_BUF_SIZE];
#ifndef WIN32
  struct termios ts, nts;
  ssize_t n_read;
#else
  HANDLE hStdin;
  DWORD n_read, fdwMode, fdwOldMode;
  hStdin = GetStdHandle(STD_INPUT_HANDLE);
  if (hStdin == INVALID_HANDLE_VALUE) {
	  perror(progname);
	  exit(-SASL_FAIL);
  }
#endif /*WIN32*/

  if (! flag_pipe) {
    fputs(prompt, stdout);
    fflush(stdout);
#ifndef WIN32
    tcgetattr(STDIN_FILENO, &ts);
    nts = ts;
    nts.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHOCTL| ECHOPRT | ECHOKE);
    nts.c_lflag |= ICANON | ECHONL;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &nts);
#else
  if (! GetConsoleMode(hStdin, &fdwOldMode)) {
	  perror(progname);
	  exit(-SASL_FAIL);
  }
  fdwMode = fdwOldMode & ~ENABLE_ECHO_INPUT;
  if (! SetConsoleMode(hStdin, fdwMode)) {
	  perror(progname);
	  exit(-SASL_FAIL);
  }
#endif /*WIN32*/
  }

#ifndef WIN32
  n_read = read(STDIN_FILENO, buf, PW_BUF_SIZE);
  if (n_read < 0) {
#else
  if (! ReadFile(hStdin, buf, PW_BUF_SIZE, &n_read, NULL)) {
#endif /*WIN32*/

    perror(progname);
    exit(-SASL_FAIL);
  }

  if (! flag_pipe) {
#ifndef WIN32
    tcsetattr(STDIN_FILENO, TCSANOW, &ts);
    if (0 < n_read && buf[n_read - 1] != '\n') {
      /* if we didn't end with a \n, echo one */
      putchar('\n');
      fflush(stdout);
    }
#else
	SetConsoleMode(hStdin, fdwOldMode);
    putchar('\n');
    fflush(stdout);
#endif /*WIN32*/
  }

  if (0 < n_read && buf[n_read - 1] == '\n') /* if we ended with a \n */
    n_read--;			             /* remove it */

#ifdef WIN32
  /*WIN32 will have a CR in the buffer also*/
  if (0 < n_read && buf[n_read - 1] == '\r') /* if we ended with a \r */
    n_read--;			             /* remove it */
#endif /*WIN32*/

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
  char *appname = "saslpasswd";

  if (! argv[0])
    progname = "saslpasswd";
  else {
    progname = strrchr(argv[0], '/');
    if (progname)
      progname++;
    else
      progname = argv[0];
  }

  while ((c = getopt(argc, argv, "pcdu:a:h?")) != EOF)
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
    case 'a':
      appname = optarg;
      if (strchr(optarg, '/') != NULL) {
        (void)fprintf(stderr, "filename must not contain /\n");
        exit(-SASL_FAIL);
      }
      break;
    default:
      flag_error = 1;
      break;
    }

  if (optind != argc - 1)
    flag_error = 1;

  if (flag_error) {
    (void)fprintf(stderr,
		  "%s: usage: %s [-a appname] [-p] [-c] [-d] [-u DOM] userid\n"
		  "\t-p\tpipe mode -- no prompt, password read on stdin\n"
		  "\t-c\tcreate -- ask mechs to create the account\n"
		  "\t-d\tdisable -- ask mechs to disable the account\n"
		  "\t-a appname\tuse appname as application name\n"
		  "\t-u DOM\tuse DOM for user domain\n",
		  progname, progname);
    exit(-SASL_FAIL);
  }

  userid = argv[optind];

  result = sasl_server_init(NULL, appname);
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
 
#ifndef WIN32
  if (! flag_pipe && ! isatty(STDIN_FILENO))
    flag_pipe = 1;
#endif /*WIN32*/

  if (!flag_disable) {
      read_password("Password: ", flag_pipe, &password, &passlen);

      if (! flag_pipe) {
	  read_password("Again (for verification): ", flag_pipe, &verify,
		  &verifylen);
	  if (passlen != verifylen
	      || memcmp(password, verify, verifylen)) {
	      fprintf(stderr, "%s: passwords don't match; aborting\n", 
		      progname);
	      exit(-SASL_BADPARAM);
	  }
      }
  }

  result = sasl_setpass(conn,
			userid,
			password,
			passlen,
			(flag_create ? SASL_SET_CREATE : 0)
			| (flag_disable ? SASL_SET_DISABLE : 0),
			&errstr);

  if (result != SASL_OK)
    exit_sasl(result, errstr);

  return 0;
}

