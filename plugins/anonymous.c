/* Anonymous SASL plugin
 * Tim Martin 
 * $Id: anonymous.c,v 1.9 1998/12/15 04:00:12 tmartin Exp $
 */
/***********************************************************
        Copyright 1998 by Carnegie Mellon University

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#ifdef WIN32
# include "winconfig.h"
#endif /* WIN32 */
#include <stdlib.h>
#if HAVE_UNISTD_H
# include <sys/types.h>
# include <unistd.h>
#endif
#if STDC_HEADERS
# include <string.h>
#else
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
char *strchr(), *strrchr();
# ifndef HAVE_MEMCPY
#  define memcpy(d, s, n) bcopy ((s), (d), (n))
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# endif
#endif
#include <sasl.h>
#include <saslplug.h>

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslANONYMOUS.h"
#else /* WIN32 */
#include <netinet/in.h>
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define ANONYMOUS_VERSION 2;

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

typedef struct context {
  int state;
  sasl_malloc_t *malloc;
} context_t;

static int start(void *glob_context, 
		 sasl_server_params_t *sparams,
		 const char *challenge, int challen,
		 void **conn,
		 const char **errstr)
{
  context_t *text;

/* should be no client data
   if there is then ignore it i guess */

  /* holds state are in */
  text= sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;

  text->malloc = sparams->utils->malloc;
  text->state=1;
  
  *conn=text;

  return SASL_OK;
}



static void dispose(void *conn_context, sasl_utils_t *utils)
{

  utils->free(conn_context);
}

static void mech_free(void *global_context, sasl_utils_t *utils)
{
  utils->free(global_context);  
}



static int continue_step (void *conn_context,
	      sasl_server_params_t *sparams,
	      const char *clientin,
	      int clientinlen,
	      char **serverout,
	      int *serveroutlen,
	      sasl_out_params_t *oparams,
	      const char **errstr)
{
  int result;
  context_t *text;
  text=conn_context;

  if (clientinlen>0)
    text->state = 2;		/* skip initial response */

  if (text->state==1)
  {
    *serverout = text->malloc(1);
    if (! *serverout) return SASL_NOMEM;
    **serverout = '\0';
    *serveroutlen = 0;

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  { 
    struct sockaddr_in remote_addr;   
    int result =sparams->utils->getprop(sparams->utils->conn,
					SASL_IP_REMOTE, (void **)&remote_addr);

    if (result==SASL_OK) {
      int ipnum = remote_addr.sin_addr.s_addr;

      sparams->utils->log(sparams->utils->conn,
			  SASL_LOG_INFO,
			  "ANONYMOUS", 0, 0,
			  "login: \"%s\" from [%i.%i.%i.%i]",
			  clientin,
			  ipnum >> 24 & 0xFF,
			  ipnum >> 16 & 0xFF,
			  ipnum >> 8 &0xFF,
			  ipnum & 0xFF);
    } else {
      sparams->utils->log(sparams->utils->conn,
			  SASL_LOG_INFO,
			  "ANONYMOUS", 0, 0,
			  "login: \"%s\" from [no IP given]", clientin);
    }


    oparams->mech_ssf=0;
    oparams->maxoutbuf=0;
    oparams->encode=NULL;
    oparams->decode=NULL;

    oparams->user="anonymous"; /* set username */
    oparams->authid="anonymous";

    oparams->realm=NULL;
    oparams->param_version=0;

    /*nothing more to do; authenticated */
    oparams->doneflag=1;

    *serverout = NULL;
    *serveroutlen = 0;
    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "ANONYMOUS",
    0,
    0,
    NULL,
    &start,
    &continue_step,
    &dispose,
    &mech_free,
    NULL,
    NULL,
    NULL
  }
};

int sasl_server_plug_init(sasl_utils_t *utils, int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<1)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=ANONYMOUS_VERSION;

  return SASL_OK;
}

/* put in sasl_wrongmech */
static int c_start(void *glob_context, 
		 sasl_client_params_t *params,
		 void **conn)
{
  context_t *text;

/* should be no client data
   if there is then ignore it i guess */

  /* holds state are in */
  text= params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;

  text->state=1;  
  text->malloc = params->utils->malloc;
  *conn=text;

  return SASL_OK;
}

static int c_continue_step (void *conn_context,
	      sasl_client_params_t *params,
	      const char *serverin,
	      int serverinlen,
	      sasl_interact_t **prompt_need,
	      char **clientout,
	      int *clientoutlen,
	      sasl_out_params_t *oparams)
{
  int result;
  context_t *text;
  text=conn_context;

  oparams->mech_ssf=0;
  oparams->maxoutbuf=0;
  oparams->encode=NULL;
  oparams->decode=NULL;
  oparams->user="anonymous"; /* set username */
  oparams->authid="anonymous";
  oparams->realm=NULL;
  oparams->param_version=0;

  /* doesn't really matter how the server responds */

  if (text->state==1)
  {
    unsigned userlen;
    const char *username;
    char hostname[256];

    /* check if sec layer strong enough */
    if (params->props.min_ssf>0)
      return SASL_TOOWEAK;

    result = params->utils->getprop(params->utils->conn,
				    SASL_USERNAME,
				    (void **)&username);
    if (result != SASL_OK)
      username = "(unknown)";

    VL(("user=%s\n",username));

    userlen = strlen(username);

    memset(hostname, 0, sizeof(hostname));
    gethostname(hostname,sizeof(hostname));

    *clientoutlen = userlen + strlen(hostname) + 1;

    *clientout = text->malloc(*clientoutlen + 1);
    if (! *clientout) return SASL_NOMEM;

    strcpy(*clientout, username);
    (*clientout)[userlen] = '@';
    strcpy(*clientout + userlen, hostname);

    VL(("out=%s\n", *clientout));

    oparams->doneflag = 1;

    text->state=2;

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "ANONYMOUS",
    0,
    0,
    NULL,
    NULL,
    &c_start,
    &c_continue_step,
    &dispose,
    &mech_free,
    NULL,
    NULL
  }
};

int sasl_client_plug_init(sasl_utils_t *utils, int maxversion,
			  int *out_version, const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<1)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=ANONYMOUS_VERSION;

  return SASL_OK;
}
