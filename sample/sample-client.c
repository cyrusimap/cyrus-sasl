/* sample-client.c -- sample SASL client
 * Rob Earhart
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

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

#include <config.h>
#include <sasl.h>
#include <saslutil.h>
#include <netinet/in.h>

#define HAVE_SUBOPT

static const char
build_ident[] = "$Build: sample-client " PACKAGE "-" VERSION " $";

static const char *progname = NULL;

#define SAMPLE_SEC_BUF_SIZE (2048)

static const char
message[] = "Come here Watson, I want you.";

char buf[SAMPLE_SEC_BUF_SIZE];

static const char *bit_subopts[] = {
#define OPT_MIN (0)
  "min",
#define OPT_MAX (1)
  "max",
  NULL
};

static const char *ext_subopts[] = {
#define OPT_EXT_SSF (0)
  "ssf",
#define OPT_EXT_ID (1)
  "id",
  NULL
};

static const char *flag_subopts[] = {
#define OPT_NOPLAIN (0)
  "noplain",
#define OPT_NOACTIVE (1)
  "noactive",
#define OPT_NODICT (2)
  "nodict",
#define OPT_FORWARDSEC (3)
  "forwardsec",
#define OPT_MAXIMUM (4)
  "maximum",
#define OPT_PASSCRED (5)
  "passcred",
  NULL
};

static const char *ip_subopts[] = {
#define OPT_IP_LOCAL (0)
  "local",
#define OPT_IP_REMOTE (1)
  "remote",
  NULL
};

char *mech = NULL,
  *iplocal = NULL,
  *ipremote = NULL,
  *searchpath = NULL,
  *service = "rcmd",
  *fqdn = "",
  *userid = NULL,
  *authid = NULL;
sasl_conn_t *conn = NULL;

static void
free_conn(void)
{
  if (conn)
    sasl_dispose(&conn);
}

static int
log(void *context __attribute__((unused)),
    int priority,
    const char *message) 
{
  const char *label;

  if (! message)
    return SASL_BADPARAM;

  switch (priority) {
  case SASL_LOG_ERR:
    label = "Error";
    break;
  case SASL_LOG_WARNING:
    label = "Warning";
    break;
  case SASL_LOG_INFO:
    label = "Info";
    break;
  default:
    return SASL_BADPARAM;
  }

  fprintf(stderr, "%s: SASL %s: %s\n",
	  progname, label, message);

  return SASL_OK;
}

static int
getpath(void *context __attribute__((unused)),
	char ** path) 
{
  if (! path)
    return SASL_BADPARAM;

  if (searchpath) {
    *path = strdup(searchpath);
    if (! *path)
      return SASL_NOMEM;
  } else
    *path = NULL;

  return SASL_OK;
}

static int
simple(void *context __attribute__((unused)),
       int id,
       const char **result,
       unsigned *len)
{
  if (! result)
    return SASL_BADPARAM;
  switch (id) {
  case SASL_CB_USER:
    *result = userid;
    if (len)
      *len = userid ? strlen(userid) : 0;
    break;
  case SASL_CB_AUTHNAME:
    *result = authid;
    if (len)
      *len = authid ? strlen(authid) : 0;
    break;
  case SASL_CB_LANGUAGE:
    *result = NULL;
    if (len)
      *len = 0;
    break;
  default:
    return SASL_BADPARAM;
  }
  return SASL_OK;
}

#ifndef HAVE_GETPASSPHRASE
static char *
getpassphrase(const char *prompt)
{
  return getpass(prompt);
}
#endif /* ! HAVE_GETPASSPHRASE */

static int
getsecret(sasl_conn_t *conn,
	  void *context __attribute__((unused)),
	  int id,
	  sasl_secret_t **psecret)
{
  if (! conn || ! psecret || id != SASL_CB_PASS)
    return SASL_BADPARAM;

  *psecret = (sasl_secret_t *) getpassphrase("Password: ");
  if (! *psecret)
    return SASL_FAIL;

  return SASL_OK;
}

static int
prompt(void *context __attribute__((unused)),
       int id,
       const char *challenge,
       const char *prompt,
       const char *defresult,
       const char **result,
       unsigned *len)
{
  if ((id != SASL_CB_ECHOPROMPT && id != SASL_CB_NOECHOPROMPT)
      || !prompt || !result || !len)
    return SASL_BADPARAM;

  if (! defresult)
    defresult = "";
  
  fputs(prompt, stdout);
  if (challenge)
    printf(" [challenge: %s]", challenge);
  printf(" [%s]: ", defresult);
  fflush(stdout);
  
  if (id == SASL_CB_ECHOPROMPT) {
    char *original = getpassphrase("");
    if (! original)
      return SASL_FAIL;
    if (*original)
      *result = strdup(original);
    else
      *result = strdup(defresult);
    memset(original, 0L, strlen(original));
  } else {
    char buf[1024];
    fgets(buf, 1024, stdin);
    if (buf[0]) {
      *result = strdup(buf);
    } else {
      *result = strdup(defresult);
    }
    memset(buf, 0L, sizeof(buf));
  }
  if (! *result)
    return SASL_NOMEM;

  *len = strlen(*result);
  
  return SASL_OK;
}

static sasl_callback_t callbacks[] = {
  {
    SASL_CB_LOG, &log, NULL
  }, {
    SASL_CB_GETPATH, &getpath, NULL
  }, {
    SASL_CB_USER, &simple, NULL
  }, {
    SASL_CB_AUTHNAME, &simple, NULL
  }, {
    SASL_CB_PASS, &getsecret, NULL
  }, {
    SASL_CB_ECHOPROMPT, &prompt, NULL
  }, {
    SASL_CB_NOECHOPROMPT, &prompt, NULL
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

static void
saslfail(int why, const char *what, const char *errstr)
{
  fprintf(stderr, "%s: %s: %s",
	  progname,
	  what,
	  sasl_errstring(why, NULL, NULL));
  if (errstr)
    fprintf(stderr, " (%s)\n", errstr);
  else
    putc('\n', stderr);
  exit(EXIT_FAILURE);
}

static void
fail(const char *what)
{
  fprintf(stderr, "%s: %s\n",
	  progname, what);
  exit(EXIT_FAILURE);
}

static void
osfail()
{
  perror(progname);
  exit(EXIT_FAILURE);
}

static void
set_ip(char *ipaddr, int prop)
{
  char *sep;
  struct hostent *hent;
  struct sockaddr_in sin;
  int result;

  if (! ipaddr)
    return;

  memset(&sin, 0L, sizeof(sin));

  sep = strchr(ipaddr, ':');
  if (! sep)
    fail("IP addr doesn't contain a ':'");
  *sep = '\0';
  sep++;
  hent = gethostbyname(ipaddr);
  if (! hent) {
    /* xxx no work on solaris   herror(ipaddr); */
    exit(EXIT_FAILURE);
  }
  memcpy(&sin.sin_addr, hent->h_addr, sizeof(struct in_addr));
  sin.sin_port = htons(atoi(sep));
  if (! sin.sin_port)
    fail("Unable to parse port in IP addr");
  result = sasl_setprop(conn, prop, &sin);
  if (result != SASL_OK)
    saslfail(result, "Setting IP address\n", NULL);
}

static void
samp_send(const char *buffer,
	  unsigned length)
{
  char *buf;
  unsigned len, alloclen;
  int result;

  alloclen = (((length / 3) + 1) * 4);
  buf = malloc(alloclen);
  if (! buf)
    osfail();
  result = sasl_encode64(buffer, length, buf, alloclen, &len);
  if (result != SASL_OK)
    saslfail(result, "Encoding data in base64", NULL);
  printf("C: %*s\n", len, buf);
  free(buf);
}

static unsigned
samp_recv()
{
  unsigned len;
  int result;
  
  if (! fgets(buf, SAMPLE_SEC_BUF_SIZE, stdin)
      || strncmp(buf, "S: ", 3))
    fail("Unable to parse input");
  result = sasl_decode64(buf + 3, strlen(buf + 3), buf, &len);
  if (result != SASL_OK)
    saslfail(result, "Decoding data from base64", NULL);
  buf[len] = '\0';
  return len;
}

int
main(int argc, char *argv[])
{
  int c = 0;
  int errflag = 0;
  int result;
  sasl_security_properties_t secprops;
  sasl_external_properties_t extprops;
  char *options, *value, *data;
  const char *chosenmech;
  unsigned len;
  
  progname = strrchr(argv[0], '/');
  if (progname)
    progname++;
  else
    progname = argv[0];

  /* Init defaults... */
  memset(&secprops, 0L, sizeof(secprops));
  secprops.maxbufsize = SAMPLE_SEC_BUF_SIZE;
  secprops.max_ssf = 9999; /* xxx doesn't work on solaris? UINT_MAX; */
  memset(&extprops, 0L, sizeof(extprops));

  while ((c = getopt(argc, argv, "hb:e:m:f:i:p:s:n:u:a:?")) != EOF)
    switch (c) {
    case 'b':
      options = optarg;
      while (*options != '\0')
	switch(getsubopt(&options, bit_subopts, &value)) {
	case OPT_MIN:
	  if (! value)
	    errflag = 1;
	  else
	    secprops.min_ssf = atoi(value);
	  break;
	case OPT_MAX:
	  if (! value)
	    errflag = 1;
	  else
	    secprops.max_ssf = atoi(value);
	  break;
	default:
	  errflag = 1;
	  break;
	  }
      break;

    case 'e':
      options = optarg;
      while (*options != '\0')
	switch(getsubopt(&options, ext_subopts, &value)) {
	case OPT_EXT_SSF:
	  if (! value)
	    errflag = 1;
	  else
	    extprops.ssf = atoi(value);
	  break;
	case OPT_MAX:
	  if (! value)
	    errflag = 1;
	  else
	    extprops.auth_id = value;
	  break;
	default:
	  errflag = 1;
	  break;
	  }
      break;

    case 'm':
      mech = optarg;
      break;

    case 'f':
      options = optarg;
      while (*options != '\0') {
	switch(getsubopt(&options, flag_subopts, &value)) {
	case OPT_NOPLAIN:
	  secprops.security_flags |= SASL_SEC_NOPLAINTEXT;
	  break;
	case OPT_NOACTIVE:
	  secprops.security_flags |= SASL_SEC_NOACTIVE;
	  break;
	case OPT_NODICT:
	  secprops.security_flags |= SASL_SEC_NODICTIONARY;
	  break;
	case OPT_FORWARDSEC:
	  secprops.security_flags |= SASL_SEC_FORWARD_SECRECY;
	  break;
	case OPT_MAXIMUM:
	  secprops.security_flags |= SASL_SEC_MAXIMUM;
	  break;
	case OPT_PASSCRED:
	  secprops.security_flags |= SASL_SEC_PASS_CREDENTIALS;
	  break;
	default:
	  errflag = 1;
	  break;
	  }
	if (value) errflag = 1;
      }
      break;

    case 'i':
      options = optarg;
      while (*options != '\0')
	switch(getsubopt(&options, ip_subopts, &value)) {
	case OPT_IP_LOCAL:
	  if (! value)
	    errflag = 1;
	  else
	    iplocal = value;
	  break;
	case OPT_IP_REMOTE:
	  if (! value)
	    errflag = 1;
	  else
	    ipremote = value;
	  break;
	default:
	  errflag = 1;
	  break;
	  }
      break;

    case 'p':
      searchpath = optarg;
      break;

    case 's':
      service = optarg;
      break;

    case 'n':
      fqdn = optarg;
      break;

    case 'u':
      userid = optarg;
      break;

    case 'a':
      authid = optarg;
      break;

    default:			/* unknown flag */
      errflag = 1;
      break;
    }

  if (optind != argc) {
    /* We don't *have* extra arguments */
    errflag = 1;
  }

  if (errflag) {
    fprintf(stderr, "%s: Usage: %s [-b min=N,max=N] [-e ssf=N,id=ID] [-m MECH] [-f FLAGS] [-i local=IP,remote=IP] [-p PATH] [-s NAME] [-n FQDN] [-u ID] [-a ID]\n"
	    "\t-b ...\t#bits to use for encryption\n"
	    "\t\tmin=N\tminumum #bits to use (1 => integrity)\n"
	    "\t\tmax=N\tmaximum #bits to use\n"
	    "\t-e ...\tassume external encryption\n"
	    "\t\tssf=N\texternal mech provides N bits of encryption\n"
	    "\t\tid=ID\texternal mech provides authentication id ID\n"
	    "\t-m MECH\tforce use of MECH for security\n"
	    "\t-f ...\tset security flags\n"
	    "\t\tnoplain\t\trequire security vs. passive attacks\n"
	    "\t\tnoactive\trequire security vs. active attacks\n"
	    "\t\tnodict\t\trequire security vs. passive dictionary attacks\n"
	    "\t\tforwardsec\trequire forward secrecy\n"
	    "\t\tmaximum\t\trequire all security flags\n"
	    "\t\tpasscred\tattempt to pass client credentials\n"
	    "\t-i ...\tset IP addresses (required by some mechs)\n"
	    "\t\tlocal=IP:PORT\tset local address to IP, port PORT\n"
	    "\t\tremote=IP:PORT\tset remote address to IP, port PORT\n"
	    "\t-p PATH\tcolon-seperated search path for mechanisms\n"
	    "\t-s NAME\tservice name pass to mechanisms\n"
	    "\t-n FQDN\tserver fully-qualified domain name\n"
	    "\t-u ID\tuser (authorization) id to request\n"
	    "\t-a ID\tid to authenticate as\n",
	    progname, progname);
    exit(EXIT_FAILURE);
  }

  result = sasl_client_init(callbacks);
  if (result != SASL_OK)
    saslfail(result, "Initializing libsasl", NULL);

  atexit(&sasl_done);

  result = sasl_client_new(service,
			   fqdn,
			   NULL,
			   SASL_SECURITY_LAYER,
			   &conn);
  if (result != SASL_OK)
    saslfail(result, "Allocating sasl connection state", NULL);
  
  atexit(&free_conn);

  result = sasl_setprop(conn,
			SASL_SSF_EXTERNAL,
			&extprops);

  if (result != SASL_OK)
    saslfail(result, "Setting external properties", NULL);

  result = sasl_setprop(conn,
			SASL_SEC_PROPS,
			&secprops);

  if (result != SASL_OK)
    saslfail(result, "Setting security properties", NULL);

  set_ip(iplocal, SASL_IP_LOCAL);
  set_ip(ipremote, SASL_IP_REMOTE);

  puts("Waiting for mechanism list from server...");
  len = samp_recv();

  if (mech) {
    printf("Forcing use of mechanism %s\n", mech);
    strncpy(buf, mech, SAMPLE_SEC_BUF_SIZE);
    buf[SAMPLE_SEC_BUF_SIZE] = '\0';
  }

  printf("Choosing best mechanism from: %s\n", buf);
  
  result = sasl_client_start(conn,
			     buf,
			     NULL,
			     NULL,
			     &data,
			     &len,
			     &chosenmech);

  if (result != SASL_OK && result != SASL_CONTINUE)
    saslfail(result, "Starting SASL negotiation", NULL);

  printf("Using mechanism %s\n", chosenmech);
  strcpy(buf, chosenmech);
  if (data) {
    if (SAMPLE_SEC_BUF_SIZE - strlen(buf) - 1 < len)
      fail("Not enough buffer space");
    puts("Preparing initial.");
    memcpy(buf + strlen(buf) + 1, data, len);
    len += strlen(buf) + 1;
  } else {
    len = strlen(buf);
  }
  
  puts("Sending initial response...");
  samp_send(buf, len);

  while (result == SASL_CONTINUE) {
    puts("Waiting for server reply...");
    len = samp_recv();
    result = sasl_client_step(conn, buf, len, NULL,
			      &data, &len);
    if (result != SASL_OK && result != SASL_CONTINUE)
      saslfail(result, "Performing SASL negotiation", NULL);
    if (data) {
      puts("Sending response...");
      samp_send(data, len);
      free(data);
    }
  }
  puts("Negotiation complete");

  return (EXIT_SUCCESS);
}
