/* Anonymous SASL plugin
 * Tim Martin 
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
#include <sasl.h>
#include <saslplug.h>

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslANONYMOUS.h"
#else /* WIN32 */
#include <netinet/in.h>
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

static const char anonymous_id[] = "anonymous";

#define ANONYMOUS_VERSION (3)

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

static int
start(void *glob_context __attribute__((unused)),
      sasl_server_params_t *sparams __attribute__((unused)),
      const char *challenge __attribute__((unused)),
      int challen __attribute__((unused)),
      void **conn,
      const char **errstr)
{
  /* holds state are in */
  if (!conn
      || !errstr)
    return SASL_BADPARAM;
  
  *conn = NULL;
  *errstr = NULL;

  return SASL_OK;
}

static int
continue_step (void *conn_context __attribute__((unused)),
	       sasl_server_params_t *sparams,
	       const char *clientin,
	       int clientinlen,
	       char **serverout,
	       int *serveroutlen,
	       sasl_out_params_t *oparams,
	       const char **errstr)
{
  int result;
  struct sockaddr_in remote_addr;   

  if (!sparams
      || !serverout
      || !serveroutlen
      || !oparams
      || !errstr)
    return SASL_BADPARAM;

  *errstr = NULL;

  if (! clientin) {
    *serverout = NULL;
    *serveroutlen = 0;
    return SASL_CONTINUE;
  }

  result = sparams->utils->getprop(sparams->utils->conn,
				   SASL_IP_REMOTE, (void **)&remote_addr);

  if (result==SASL_OK) {
    int ipnum = remote_addr.sin_addr.s_addr;

    sparams->utils->log(sparams->utils->conn,
			SASL_LOG_INFO,
			"ANONYMOUS", 0, 0,
			"login: \"%*s\" from [%i.%i.%i.%i]",
			clientinlen,
			clientin,
			ipnum >> 24 & 0xFF,
			ipnum >> 16 & 0xFF,
			ipnum >> 8 &0xFF,
			ipnum & 0xFF);
  } else {
    sparams->utils->log(sparams->utils->conn,
			SASL_LOG_INFO,
			"ANONYMOUS", 0, 0,
			"login: \"%*s\" from [no IP given]",
			clientinlen,
			clientin);
  }

  oparams->mech_ssf=0;
  oparams->maxoutbuf=0;
  oparams->encode=NULL;
  oparams->decode=NULL;

  oparams->user = sparams->utils->malloc(sizeof(anonymous_id));
  if (oparams->user)
    strcpy(oparams->user, anonymous_id);

  oparams->authid = sparams->utils->malloc(sizeof(anonymous_id));
  if (oparams->authid)
    strcpy(oparams->authid, anonymous_id);

  oparams->realm=NULL;
  oparams->param_version=0;

  /*nothing more to do; authenticated */
  oparams->doneflag=1;
  
  *serverout = NULL;
  *serveroutlen = 0;
  return SASL_OK;
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "ANONYMOUS",		/* mech_name */
    0,				/* max_ssf */
    0,				/* security_flags */
    NULL,			/* glob_context */
    &start,			/* mech_new */
    &continue_step,		/* mech_step */
    NULL,			/* mech_dispose */
    NULL,			/* mech_free */
    NULL,			/* setpass */
    NULL,			/* user_query */
    NULL,			/* idle */
    NULL,			/* install_credentials */
    NULL,			/* uninstall_credentials */
    NULL			/* free_credentials */
  }
};

int sasl_server_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<ANONYMOUS_VERSION)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=ANONYMOUS_VERSION;

  return SASL_OK;
}

/* put in sasl_wrongmech */
static int
c_start(void *glob_context __attribute__((unused)),
	sasl_client_params_t *params __attribute__((unused)),
	void **conn)
{
  if (! conn)
    return SASL_BADPARAM;

  *conn=NULL;

  return SASL_OK;
}

static int
c_continue_step(void *conn_context __attribute__((unused)),
		sasl_client_params_t *params,
		const char *serverin __attribute__((unused)),
		int serverinlen,
		sasl_interact_t **prompt_need,
		char **clientout,
		int *clientoutlen,
		sasl_out_params_t *oparams)
{
  int result;
  unsigned userlen;
  char hostname[256];
  sasl_getsimple_t *getuser_cb;
  void *getuser_context;
  const char *user;

  if (!params
      || !prompt_need
      || !clientout
      || !clientoutlen
      || !oparams)
    return SASL_BADPARAM;

  if (serverinlen != 0)
    return SASL_BADPROT;

  /* check if sec layer strong enough */
  if (params->props.min_ssf>0)
    return SASL_TOOWEAK;

  /* Get the username */
  if (*prompt_need) {
    /* We used an interaction to get it. */
    if (! (*prompt_need)[0].result)
      return SASL_BADPARAM;
    user = (*prompt_need)[0].result;
    params->utils->free(*prompt_need);
    *prompt_need = NULL;
  } else {
    /* Try to get the callback... */
    result = params->utils->getcallback(params->utils->conn,
					SASL_CB_USER,
					&getuser_cb,
					&getuser_context);
    switch (result) {
    case SASL_INTERACT:
      /* Set up the interaction... */
      *prompt_need = params->utils->malloc(sizeof(sasl_interact_t) * 2);
      if (! *prompt_need)
	return SASL_FAIL;
      memset(*prompt_need, 0, sizeof(sasl_interact_t) * 2);
      (*prompt_need)[0].id = SASL_CB_USER;
      (*prompt_need)[0].prompt = "Anonymous Identification";
      (*prompt_need)[0].defresult = "";
      (*prompt_need)[1].id = SASL_CB_LIST_END;
      return SASL_INTERACT;
    case SASL_OK:
      if (! getuser_cb
	  || (getuser_cb(getuser_context,
			 SASL_CB_USER,
			 &user,
			 &userlen)
	      != SASL_OK)) {
	/* We just lose. */
	return SASL_FAIL;
      }
      break;
    default:
      /* We just lose. */
      return result;
    }
  }
  
  VL(("anonymous: user=%s\n",user));

  userlen = strlen(user);

  memset(hostname, 0, sizeof(hostname));
  gethostname(hostname,sizeof(hostname));

  *clientoutlen = userlen + strlen(hostname) + 1;

  *clientout = params->utils->malloc(*clientoutlen + 1);
  if (! *clientout) return SASL_NOMEM;

  strcpy(*clientout, user);
  (*clientout)[userlen] = '@';
  strcpy(*clientout + userlen, hostname);

  VL(("anonymous: out=%s\n", *clientout));

  oparams->doneflag = 1;
  oparams->mech_ssf=0;
  oparams->maxoutbuf=0;
  oparams->encode=NULL;
  oparams->decode=NULL;

  oparams->user = params->utils->malloc(sizeof(anonymous_id));
  if (oparams->user)
    strcpy(oparams->user, anonymous_id);

  oparams->authid = params->utils->malloc(sizeof(anonymous_id));
  if (oparams->authid)
    strcpy(oparams->authid, anonymous_id);

  oparams->realm=NULL;
  oparams->param_version=0;

  return SASL_OK;
}

static const long client_required_prompts[] = {
  SASL_CB_USER,
  SASL_CB_LIST_END
};

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "ANONYMOUS",		/* mech_name */
    0,				/* max_ssf */
    0,				/* security_flags */
    client_required_prompts,	/* required_prompts */
    NULL,			/* glob_context */
    &c_start,			/* mech_new */
    &c_continue_step,		/* mech_step */
    NULL,			/* mech_dispose */
    NULL,			/* mech_free */
    NULL,			/* auth_create */
    NULL			/* idle */
  }
};

int sasl_client_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion < ANONYMOUS_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=ANONYMOUS_VERSION;

  return SASL_OK;
}
