/* SASL server API implementation
 * Rob Siemborski
 * Tim Martin
 * $Id: external.c,v 1.5 2002/01/30 21:53:33 ken3 Exp $
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
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <sasl.h>
#include <saslutil.h>
#include "saslint.h"

static int
external_server_new(void *glob_context __attribute__((unused)),
		    sasl_server_params_t *sparams,
		    const char *challenge __attribute__((unused)),
		    unsigned challen __attribute__((unused)),
		    void **conn_context)
{
  if (!conn_context
      || !sparams
      || !sparams->utils
      || !sparams->utils->conn)
    return SASL_BADPARAM;
  if (!sparams->utils->conn->external.auth_id)
    return SASL_NOMECH;
  *conn_context = NULL;
  return SASL_OK;
}

static int
external_server_step(void *conn_context __attribute__((unused)),
		     sasl_server_params_t *sparams,
		     const char *clientin,
		     unsigned clientinlen,
		     const char **serverout,
		     unsigned *serveroutlen,
		     sasl_out_params_t *oparams)
{
  int result;
  const char *user;
  
  if (!sparams
      || !sparams->utils
      || !sparams->utils->conn
      || !sparams->utils->getcallback
      || !serverout
      || !serveroutlen
      || !oparams)
    return SASL_BADPARAM;

  if (!sparams->utils->conn->external.auth_id)
    return SASL_BADPROT;

  if (! clientin) {
    /* No initial data; we're in a protocol which doesn't support it.
     * So we let the server app know that we need some... */
    *serverout = NULL;
    *serveroutlen = 0;
    return SASL_CONTINUE;
  }

  if (clientinlen) {		/* if we have a non-zero authorization id */
      /* The user's trying to authorize as someone they didn't
       * authenticate as */
      user = clientin;
  } else {
      user = sparams->utils->conn->external.auth_id;
  }

  result = sparams->canon_user(sparams->utils->conn,
			       user, 0, SASL_CU_AUTHZID, oparams);
  if(result != SASL_OK) return result;

  result = sparams->canon_user(sparams->utils->conn,
			       sparams->utils->conn->external.auth_id, 0,
			       SASL_CU_AUTHID, oparams);
  if (result != SASL_OK) return result;

  oparams->doneflag = 1;
  oparams->mech_ssf = 0;
  oparams->maxoutbuf = 0;
  oparams->encode_context = NULL;
  oparams->encode = NULL;
  oparams->decode_context = NULL;
  oparams->decode = NULL;
  oparams->param_version = 0;

  return SASL_OK;
}

sasl_server_plug_t external_server_mech =
{
    "EXTERNAL",			/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT
    | SASL_SEC_NODICTIONARY,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* glob_context */
    &external_server_new,	/* mech_new */
    &external_server_step,	/* mech_step */
    NULL,			/* mech_dispose */
    NULL,			/* mech_free */
    NULL,			/* setpass */
    NULL,			/* user_query */
    NULL,			/* idle */
    NULL,			/* mech_avail */
    NULL			/* spare */
};

int external_server_init(const sasl_utils_t *utils __attribute__((unused)),
			 int max_version,
			 int *out_version,
			 sasl_server_plug_t **pluglist,
			 int *plugcount)
{
  if (!out_version || !pluglist || !plugcount)
    return SASL_BADPARAM;
  if (max_version != SASL_SERVER_PLUG_VERSION)
    return SASL_BADVERS;
  *out_version = SASL_SERVER_PLUG_VERSION;
  *pluglist = &external_server_mech;
  *plugcount = 1;
  return SASL_OK;
}

typedef struct external_client_context 
{
    char *out_buf;
    unsigned out_buf_len;
} external_client_context_t;

static int
external_client_new(void *glob_context __attribute__((unused)),
		    sasl_client_params_t *params __attribute__((unused)),
		    void **conn_context)
{
    external_client_context_t *ret;
    
    if (!params
	|| !params->utils
	|| !params->utils->conn
	|| !conn_context)
	return SASL_BADPARAM;
    if (!params->utils->conn->external.auth_id)
	return SASL_NOMECH;
    ret = sasl_ALLOC(sizeof(external_client_context_t));
    if(!ret) return SASL_NOMEM;
    
    memset(ret, 0, sizeof(external_client_context_t));

    *conn_context = ret;
    return SASL_OK;
}

static int
external_client_step(void *conn_context,
		     sasl_client_params_t *params,
		     const char *serverin __attribute__((unused)),
		     unsigned serverinlen,
		     sasl_interact_t **prompt_need,
		     const char **clientout,
		     unsigned *clientoutlen,
		     sasl_out_params_t *oparams)
{
  int result;
  sasl_getsimple_t *getuser_cb;
  void *getuser_context;
  const char *user;
  unsigned len;
  external_client_context_t *text = (external_client_context_t *)conn_context;
  
  if (!params
      || !params->utils
      || !params->utils->conn
      || !params->utils->getcallback
      || !clientout
      || !clientoutlen
      || !oparams)
    return SASL_BADPARAM;

  if (!params->utils->conn->external.auth_id)
    return SASL_BADPROT;

  if (serverinlen != 0)
    return SASL_BADPROT;

  if (prompt_need && *prompt_need) {
    /* Second time through; we used a SASL_INTERACT to get the user. */
    if (! (*prompt_need)[0].result)
      return SASL_BADPARAM;
    user = (*prompt_need)[0].result;
    *clientoutlen = strlen(user);
    params->utils->free(*prompt_need);
    *prompt_need = NULL;
  } else {
    /* We need to get the user. */
    result = params->utils->getcallback(params->utils->conn,
					SASL_CB_USER,
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
	(*prompt_need)[0].id = SASL_CB_USER;
	(*prompt_need)[0].prompt = "Authorization Identity";
	(*prompt_need)[0].defresult = "";
	(*prompt_need)[1].id = SASL_CB_LIST_END;
      }
      return SASL_INTERACT;
    case SASL_OK:
      if (getuser_cb &&
	  (getuser_cb(getuser_context,
		      SASL_CB_USER,
		      &user,
		      &len)
	   == SASL_OK)) {
	*clientoutlen = strlen(user);
	break;
      }
      /* Otherwise, drop through into the default we-lose case. */
    default:
      /* Assume userid == authid. */
      user = params->utils->conn->external.auth_id;
      *clientoutlen = 0;
    }
  }

  result = _buf_alloc(&text->out_buf, &text->out_buf_len, *clientoutlen + 1);

  if (result != SASL_OK) return result;

  if (user)
    memcpy(text->out_buf, user, *clientoutlen);

  text->out_buf[*clientoutlen] = '\0';
  
  *clientout = text->out_buf;

  if (prompt_need)
    *prompt_need = NULL;

  result = params->canon_user(params->utils->conn,
			      user, 0, SASL_CU_AUTHZID, oparams);
  if(result != SASL_OK) return result;

  result = params->canon_user(params->utils->conn,
			      params->utils->conn->external.auth_id, 0,
			      SASL_CU_AUTHID, oparams);

  if (result == SASL_OK)
  {
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;

    return SASL_OK;
  }  /* otherwise */

  return result;
}

static void external_client_dispose(void *conn_context,
				    const sasl_utils_t *utils __attribute__((unused))) 
{
    external_client_context_t *text;
    
    if(!conn_context) return;

    text = (external_client_context_t *)conn_context;

    if(text->out_buf) sasl_FREE(text->out_buf);

    sasl_FREE(text);
}

static const long external_client_required_prompts[] = {
  SASL_CB_USER,
  SASL_CB_LIST_END
};

sasl_client_plug_t external_client_mech =
{
    "EXTERNAL",			/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT
    | SASL_SEC_NODICTIONARY,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    external_client_required_prompts,	/* required_prompts */
    NULL,			/* glob_context */
    &external_client_new,	/* mech_new */
    &external_client_step,	/* mech_step */
    &external_client_dispose,	/* mech_dispose */
    NULL,			/* mech_free */
    NULL,			/* idle */
    NULL,			/* spare */
    NULL			/* spare */
};

int external_client_init(const sasl_utils_t *utils,
			 int max_version,
			 int *out_version,
			 sasl_client_plug_t **pluglist,
			 int *plugcount)
{
  if (!utils || !out_version || !pluglist || !plugcount)
    return SASL_BADPARAM;
  if (max_version != SASL_CLIENT_PLUG_VERSION)
    return SASL_BADVERS;
  *out_version = SASL_CLIENT_PLUG_VERSION;
  *pluglist = &external_client_mech;
  *plugcount = 1;
  return SASL_OK;
}
