/* Anonymous SASL plugin
 * Rob Siemborski
 * Tim Martin 
 * $Id: anonymous.c,v 1.41 2002/02/05 23:37:34 rjs3 Exp $
 */
/* 
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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
#include <string.h> 
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef macintosh 
#include <sasl_anonymous_plugin_decl.h> 
#endif 

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslANONYMOUS.h"
#endif

#include "plugin_common.h"

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

static const char anonymous_id[] = "anonymous";

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

/* only used by client */
typedef struct context {
  int state;
  char *out_buf;
  unsigned out_buf_len;
} context_t;

static int
anonymous_server_mech_new(void *glob_context __attribute__((unused)),
			  sasl_server_params_t *sparams,
			  const char *challenge __attribute__((unused)),
			  unsigned challen __attribute__((unused)),
			  void **conn_context)
{
    /* holds state are in */
    if (!conn_context) {
	PARAMERROR( sparams->utils );
	return SASL_BADPARAM;
    }
  
    *conn_context = NULL;

    return SASL_OK;
}

static int
anonymous_server_mech_step(void *conn_context __attribute__((unused)),
			   sasl_server_params_t *sparams,
			   const char *clientin,
			   unsigned clientinlen,
			   const char **serverout,
			   unsigned *serveroutlen,
			   sasl_out_params_t *oparams)
{
  int ret;
  char *clientdata;

  if (!sparams
      || !serverout
      || !serveroutlen
      || !oparams) {
      PARAMERROR( sparams->utils );
      return SASL_BADPARAM;
  }
  
  if (! clientin) {
    *serverout = NULL;
    *serveroutlen = 0;
    return SASL_CONTINUE;
  }

  /* We force a truncation 255 characters (specified by RFC 2245) */
  if (clientinlen > 255) clientinlen = 255;

  /* NULL-terminate the clientin... */
  clientdata = sparams->utils->malloc(clientinlen + 1);
  if (! clientdata) {
      MEMERROR(sparams->utils);
      return SASL_NOMEM;
  }
  
  strncpy(clientdata, clientin, clientinlen);
  clientdata[clientinlen] = '\0';

  sparams->utils->log(sparams->utils->conn,
		      SASL_LOG_NOTE,
		      "ANONYMOUS login: \"%s\"",
		      clientdata);

  if (clientdata != clientin)
    sparams->utils->free(clientdata);
  
  oparams->mech_ssf=0;
  oparams->maxoutbuf=0;
  oparams->encode=NULL;
  oparams->decode=NULL;

  ret = sparams->canon_user(sparams->utils->conn,
			    anonymous_id, 0,
		      	    SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
  if(ret != SASL_OK) return ret;

  oparams->param_version=0;

  /*nothing more to do; authenticated */
  oparams->doneflag=1;
  
  *serverout = NULL;
  *serveroutlen = 0;
  return SASL_OK;
}

static sasl_server_plug_t anonymous_server_plugins[] = 
{
  {
    "ANONYMOUS",		/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* glob_context */
    &anonymous_server_mech_new,	/* mech_new */
    &anonymous_server_mech_step,/* mech_step */
    NULL,			/* mech_dispose */
    NULL,			/* mech_free */
    NULL,			/* setpass */
    NULL,			/* user_query */
    NULL,			/* idle */
    NULL,			/* mech_avail */
    NULL                        /* spare */
  }
};

int anonymous_server_plug_init(const sasl_utils_t *utils,
			       int maxversion,
			       int *out_version,
			       sasl_server_plug_t **pluglist,
			       int *plugcount)
{
    if (maxversion<SASL_SERVER_PLUG_VERSION) {
	SETERROR( utils, "ANONYMOUS version mismatch" );
	return SASL_BADVERS;
    }
    
    *pluglist=anonymous_server_plugins;
    
    *plugcount=1;  
    *out_version=SASL_SERVER_PLUG_VERSION;
    
    return SASL_OK;
}

static void anonymous_client_dispose(void *conn_context,
				     const sasl_utils_t *utils)
{
  context_t *text;

  if(!conn_context) return;

  text=(context_t *)conn_context;
  if (!text) return;

  if(text->out_buf) utils->free(text->out_buf);

  utils->free(text);
}

static int
anonymous_client_mech_new(void *glob_context __attribute__((unused)),
			  sasl_client_params_t *cparams,
			  void **conn_context)
{
  context_t *text;

  if (! conn_context) {
      PARAMERROR(cparams->utils);
      return SASL_BADPARAM;
  }
  
  /* holds state are in */
  text = cparams->utils->malloc(sizeof(context_t));
  if (text==NULL) {
      MEMERROR(cparams->utils);
      return SASL_NOMEM;
  }
  
  text->state=1;
 
  text->out_buf = NULL;
  text->out_buf_len = 0;

  *conn_context=text;

  return SASL_OK;
}

static int
anonymous_client_mech_step(void *conn_context,
			   sasl_client_params_t *cparams,
			   const char *serverin __attribute__((unused)),
			   unsigned serverinlen,
			   sasl_interact_t **prompt_need,
			   const char **clientout,
			   unsigned *clientoutlen,
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

  if (text->state != 1) {
      SETERROR( cparams->utils, "Invalid state in ANONYMOUS continue_step" );
      return SASL_FAIL;
  }

  if (!cparams
      || !clientout
      || !clientoutlen
      || !oparams) {
      PARAMERROR( cparams->utils );
      return SASL_BADPARAM;
  }
      
  if (serverinlen != 0) {
      SETERROR( cparams->utils, "Nonzero serverinlen in ANONYMOUS continue_step" );
      return SASL_BADPROT;
  }

  /* check if sec layer strong enough */
  if (cparams->props.min_ssf>0) {
      SETERROR( cparams->utils, "SSF requested of ANONYMOUS plugin");
      return SASL_TOOWEAK;
  }

  /* Watch out if this doesn't start nulled! */
  /* Get the username */
  if (prompt_need && *prompt_need) {
      if (! (*prompt_need)[0].result) {
	  SETERROR( cparams->utils, "ANONYMOUS continue_step expected interaction result but got none");
	  return SASL_BADPARAM;
      }

      user = (*prompt_need)[0].result;
      userlen = (*prompt_need)[0].len;
      cparams->utils->free(*prompt_need);
  } else {
    /* Try to get the callback... */
    result = cparams->utils->getcallback(cparams->utils->conn,
					SASL_CB_AUTHNAME,
					&getuser_cb,
					&getuser_context);
    switch (result) {
    case SASL_INTERACT:
      /* Set up the interaction... */
      if (prompt_need) {
	*prompt_need = cparams->utils->malloc(sizeof(sasl_interact_t) * 2);
	if (! *prompt_need) {
	    MEMERROR( cparams->utils );
	    return SASL_NOMEM;
	}
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

  result = _plug_buf_alloc(cparams->utils, &text->out_buf,
			   &text->out_buf_len, *clientoutlen);

  if(result != SASL_OK) return result;

  *clientout = text->out_buf;

  strcpy(text->out_buf, user);
  text->out_buf[userlen] = '@';
  strcpy(text->out_buf + userlen + 1, hostname);

  oparams->doneflag = 1;
  oparams->mech_ssf=0;
  oparams->maxoutbuf=0;
  oparams->encode=NULL;
  oparams->decode=NULL;

  result = cparams->canon_user(cparams->utils->conn,
			       anonymous_id, 0,
			       SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
  if(result != SASL_OK) return result;

  oparams->param_version=0;

  text->state = 2;

  return SASL_OK;
}

static const long anonymous_required_prompts[] = {
  SASL_CB_AUTHNAME,
  SASL_CB_LIST_END
};

static sasl_client_plug_t anonymous_client_plugins[] = 
{
  {
    "ANONYMOUS",		/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    anonymous_required_prompts,	/* required_prompts */
    NULL,			/* glob_context */
    &anonymous_client_mech_new, /* mech_new */
    &anonymous_client_mech_step,/* mech_step */
    &anonymous_client_dispose,	/* mech_dispose */
    NULL,			/* mech_free */
    NULL,			/* idle */
    NULL,			/* spare */
    NULL                        /* spare */
  }
};

int anonymous_client_plug_init(
    const sasl_utils_t *utils,
    int maxversion,
    int *out_version,
    sasl_client_plug_t **pluglist,
    int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR( utils, "ANONYMOUS version mismatch" );
	return SASL_BADVERS;
    }

    *pluglist=anonymous_client_plugins;
    
    *plugcount=1;
    *out_version=SASL_CLIENT_PLUG_VERSION;

    return SASL_OK;
}
