/* NTLM SASL plugin
 * Ken Murchison
 * $Id: ntlm.c,v 1.2 2002/09/10 17:40:59 ken3 Exp $
 */
/* 
 * Copyright (c) 2002 Carnegie Mellon University.  All rights reserved.
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

#include <ntlm.h> 

#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

/*****************************  Common Section  *****************************/

static const char plugin_id[] = "$Id: ntlm.c,v 1.2 2002/09/10 17:40:59 ken3 Exp $";

/*****************************  Server Section  *****************************/

int ntlm_server_plug_init(const sasl_utils_t *utils __attribute__((unused)),
			  int maxversion __attribute__((unused)),
			  int *out_version __attribute__((unused)),
			  sasl_server_plug_t **pluglist __attribute__((unused)),
			  int *plugcount __attribute__((unused)))
{
    return SASL_NOMECH;
}

/*****************************  Client Section  *****************************/

typedef struct client_context {
    int state;

    char *authid;

    sasl_secret_t *password;
    unsigned int free_password; /* set if we need to free password */

    tSmbNtlmAuthRequest   request;              
    tSmbNtlmAuthResponse  response;
} client_context_t;

static int ntlm_client_mech_new(void *glob_context __attribute__((unused)),
			       sasl_client_params_t *params,
			       void **conn_context)
{
    client_context_t *text;
    
    /* holds state are in */
    text = params->utils->malloc(sizeof(client_context_t));
    if (text == NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(client_context_t));
    
    text->state = 1;
    
    *conn_context = text;
    
    return SASL_OK;
}

static int ntlm_client_mech_step1(client_context_t *text,
				  sasl_client_params_t *params,
				  const char *serverin __attribute__((unused)),
				  unsigned serverinlen __attribute__((unused)),
				  sasl_interact_t **prompt_need,
				  const char **clientout,
				  unsigned *clientoutlen,
				  sasl_out_params_t *oparams)
{
    const char *authid = NULL;
    int auth_result = SASL_OK;
    int pass_result = SASL_OK;
    int result;
    
    /* check if sec layer strong enough */
    if (params->props.min_ssf > params->external_ssf) {
	SETERROR( params->utils, "SSF requested of NTLM plugin");
	return SASL_TOOWEAK;
    }
    
    /* try to get the authid */    
    if (oparams->authid == NULL) {
	auth_result = _plug_get_authid(params->utils, &authid, prompt_need);
	
	if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
	    return auth_result;
    }
    
    /* try to get the password */
    if (text->password == NULL) {
	pass_result = _plug_get_password(params->utils, &text->password,
					 &text->free_password, prompt_need);
	
	if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
	    return pass_result;
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }
    
    /* if there are prompts not filled in */
    if ((auth_result == SASL_INTERACT) || (pass_result == SASL_INTERACT)) {
	/* make the prompt list */
	result =
	    _plug_make_prompts(params->utils, prompt_need,
			       NULL, NULL,
			       auth_result == SASL_INTERACT ?
			       "Please enter your authentication name" : NULL,
			       NULL,
			       pass_result == SASL_INTERACT ?
			       "Please enter your password" : NULL, NULL,
			       NULL, NULL, NULL,
			       NULL, NULL, NULL);
	if (result != SASL_OK) return result;
	
	return SASL_INTERACT;
    }
    
    result = params->canon_user(params->utils->conn, authid, 0,
				SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if (result != SASL_OK) return result;
    
    buildSmbNtlmAuthRequest(&text->request, (char *) oparams->authid, NULL);

    *clientout = (char *) &text->request;
    *clientoutlen = SmbLength(&text->request);
    
    text->state = 2;
    
    return SASL_CONTINUE;
}

static int ntlm_client_mech_step2(client_context_t *text,
				  sasl_client_params_t *params __attribute__((unused)),
				  const char *serverin,
				  unsigned serverinlen __attribute__((unused)),
				  sasl_interact_t **prompt_need __attribute__((unused)),
				  const char **clientout,
				  unsigned *clientoutlen,
				  sasl_out_params_t *oparams)
{
    tSmbNtlmAuthChallenge *challenge = (tSmbNtlmAuthChallenge *) serverin;

    buildSmbNtlmAuthResponse(challenge, &text->response,
			     (char *) oparams->authid, text->password->data);

    *clientout = (char *) &text->response;
    *clientoutlen = SmbLength(&text->response);
    
    /* set oparams */
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

static int ntlm_client_mech_step(void *conn_context,
				sasl_client_params_t *params,
				const char *serverin,
				unsigned serverinlen,
				sasl_interact_t **prompt_need,
				const char **clientout,
				unsigned *clientoutlen,
				sasl_out_params_t *oparams)
{
    client_context_t *text = (client_context_t *) conn_context;
    
    *clientout = NULL;
    *clientoutlen = 0;
    
    switch (text->state) {
	
    case 1:
	return ntlm_client_mech_step1(text, params, serverin, serverinlen,
				      prompt_need, clientout, clientoutlen,
				      oparams);
	
    case 2:
	return ntlm_client_mech_step2(text, params, serverin, serverinlen,
				      prompt_need, clientout, clientoutlen,
				      oparams);
	
    default:
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid NTLM client step %d\n", text->state);
	return SASL_FAIL;
    }
    
    return SASL_FAIL; /* should never get here */
}

static void ntlm_client_mech_dispose(void *conn_context,
				    const sasl_utils_t *utils)
{
    client_context_t *text = (client_context_t *) conn_context;
    
    if (!text) return;
    
    if (text->free_password) _plug_free_secret(utils, &(text->password));
    
    utils->free(text);
}

static sasl_client_plug_t ntlm_client_plugins[] = 
{
    {
	"NTLM",				/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_FORWARD_SECRECY,	/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST,	/* features */
	NULL,				/* required_prompts */
	NULL,				/* glob_context */
	&ntlm_client_mech_new,		/* mech_new */
	&ntlm_client_mech_step,		/* mech_step */
	&ntlm_client_mech_dispose,	/* mech_dispose */
	NULL,				/* mech_free */
	NULL,				/* idle */
	NULL,				/* spare */
	NULL				/* spare */
    }
};

int ntlm_client_plug_init(sasl_utils_t *utils,
			 int maxversion,
			 int *out_version,
			 sasl_client_plug_t **pluglist,
			 int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "NTLM version mismatch");
	return SASL_BADVERS;
    }
    
    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = ntlm_client_plugins;
    *plugcount = 1;
    
    return SASL_OK;
}
