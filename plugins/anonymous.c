/* Anonymous SASL plugin
 * Tim Martin 
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
#include <sasl.h>
#include <saslplug.h>

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslANONYMOUS.h"
#endif

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

static const char anonymous_id[] = "anonymous";

#define ANONYMOUS_VERSION (3)

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

/* only used by client */
typedef struct context {
  int state;
} context_t;

static int
server_start(void *glob_context __attribute__((unused)),
      sasl_server_params_t *sparams __attribute__((unused)),
      const char *challenge __attribute__((unused)),
      int challen __attribute__((unused)),
      void **conn,
      const char **errstr)
{
  /* holds state are in */
  if (!conn)
      return SASL_BADPARAM;
  
  *conn = NULL;
  if (errstr)
      *errstr = NULL;

  return SASL_OK;
}

static int
server_continue_step (void *conn_context __attribute__((unused)),
	       sasl_server_params_t *sparams,
	       const char *clientin,
	       int clientinlen,
	       char **serverout,
	       int *serveroutlen,
	       sasl_out_params_t *oparams,
	       const char **errstr)
{
  int result;
  struct sockaddr_in *remote_addr;   
  char *clientdata;

  if (!sparams
      || !serverout
      || !serveroutlen
      || !oparams)
    return SASL_BADPARAM;

  if (clientinlen < 0)
      return SASL_BADPARAM;

  if (errstr)
      *errstr = NULL;

  if (! clientin) {
    *serverout = NULL;
    *serveroutlen = 0;
    return SASL_CONTINUE;
  }

  /* NULL-terminate the clientin... */
  clientdata = sparams->utils->malloc(clientinlen + 1);
  if (! clientdata)
    return SASL_NOMEM;
  strncpy(clientdata, clientin, clientinlen);
  clientdata[clientinlen] = '\0';

  result = sparams->utils->getprop(sparams->utils->conn,
				   SASL_IP_REMOTE, (void **)&remote_addr);

  if (result==SASL_OK) {
    int ipnum = remote_addr->sin_addr.s_addr;

    sparams->utils->log(sparams->utils->conn,
			SASL_LOG_INFO,
			"ANONYMOUS", 0, 0,
			"login: \"%s\" from [%d.%d.%d.%d]",
			clientdata,
			ipnum >> 24 & 0xFF,
			ipnum >> 16 & 0xFF,
			ipnum >> 8 &0xFF,
			ipnum & 0xFF);
  } else {
    sparams->utils->log(sparams->utils->conn,
			SASL_LOG_INFO,
			"ANONYMOUS", 0, 0,
			"login: \"%s\" from [no IP given]",
			clientdata);
  }

  if (clientdata != clientin)
    sparams->utils->free(clientdata);
  
  oparams->mech_ssf=0;
  oparams->maxoutbuf = 0;
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
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    NULL,			/* glob_context */
    &server_start,		/* mech_new */
    &server_continue_step,	/* mech_step */
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

static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (!text)
    return;

  utils->free(text);
}

/* put in sasl_wrongmech */
static int
client_start(void *glob_context __attribute__((unused)),
	sasl_client_params_t *params __attribute__((unused)),
	void **conn)
{
  context_t *text;

  if (! conn)
    return SASL_BADPARAM;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;  
  *conn=text;

  return SASL_OK;
}

static int
client_continue_step(void *conn_context,
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
  const char *user = NULL;
  context_t *text;
  text=conn_context;

  if (text->state == 3) {
      *clientout = NULL;
      *clientoutlen = 0;
      VL(("Verify we're done step"));
      text->state++;
      return SASL_OK;      
  }

  if (clientout == NULL && text->state == 1) {
      /* no initial client send */
      text->state = 2;
      return SASL_CONTINUE;
  } else if (text->state == 1) {
      text->state = 2;
  }

  if (text->state != 2) {
      return SASL_FAIL;
  }

  VL(("ANONYMOUS: step 1\n"));

  if (!params
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
  if (prompt_need && *prompt_need) {
    VL(("Received prompt\n"));
    /* We used an interaction to get it. */
    if (! (*prompt_need)[0].result)
      return SASL_BADPARAM;

    user = (*prompt_need)[0].result;
    userlen = (*prompt_need)[0].len;
    params->utils->free(*prompt_need);
    *prompt_need = NULL;
  } else {
    /* Try to get the callback... */
    result = params->utils->getcallback(params->utils->conn,
					SASL_CB_AUTHNAME,
					&getuser_cb,
					&getuser_context);
    switch (result) {
    case SASL_INTERACT:
      /* Set up the interaction... */
      if (prompt_need) {
	*prompt_need = params->utils->malloc(sizeof(sasl_interact_t) * 2);
	if (! *prompt_need)
	  return SASL_FAIL;
	memset(*prompt_need, 0, sizeof(sasl_interact_t) * 2);
	(*prompt_need)[0].id = SASL_CB_AUTHNAME;
	(*prompt_need)[0].prompt = "Anonymous identification";
	(*prompt_need)[0].defresult = "";
	(*prompt_need)[1].id = SASL_CB_LIST_END;
      }
      return SASL_INTERACT;
    case SASL_OK:
      if (! getuser_cb
	  || (getuser_cb(getuser_context,
			 SASL_CB_AUTHNAME,
			 &user,
			 &userlen)
	      != SASL_OK)) {
	/* Use default */
      }
      break;
    default:
      /* Use default */
      break;
    }
  }
  
  if (!user) {
      user = "anonymous";
      userlen = strlen(user);
  }
  
  memset(hostname, 0, sizeof(hostname));
  gethostname(hostname, sizeof(hostname));
  hostname[sizeof(hostname)-1] = '\0';
  
  *clientoutlen = userlen + strlen(hostname) + 1;

  *clientout = params->utils->malloc(*clientoutlen + 1);
  if (! *clientout) return SASL_NOMEM;

  strcpy(*clientout, user);
  (*clientout)[userlen] = '@';
  strcpy(*clientout + userlen + 1, hostname);

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

  text->state = 2;

  return SASL_CONTINUE;
}

static const long client_required_prompts[] = {
  SASL_CB_AUTHNAME,
  SASL_CB_LIST_END
};

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "ANONYMOUS",		/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    client_required_prompts,	/* required_prompts */
    NULL,			/* glob_context */
    &client_start,		/* mech_new */
    &client_continue_step,	/* mech_step */
    &dispose,			/* mech_dispose */
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
