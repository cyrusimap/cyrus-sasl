/* OTP SASL plugin
 * Ken Murchison
 * $Id: otp.c,v 1.5 2001/12/07 17:30:50 ken3 Exp $
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <string.h> 
#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

#ifdef HAVE_OPIE
#include <opie.h>

#ifndef OPIE_KEYFILE
#define OPIE_KEYFILE "/etc/opiekeys"
#endif
#endif

#ifdef WIN32
/* This must be after sasl.h */
# include "saslOTP.h"
#endif /* WIN32 */

#ifdef macintosh 
#include <sasl_otp_plugin_decl.h> 
#endif 

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#undef L_DEFAULT_GUARD
#define L_DEFAULT_GUARD (0)

typedef struct context {
    int state;
#ifdef HAVE_OPIE
    struct opie opie;
#endif
    char *user;
    char *authid;
    char challenge[100]; /* otp-<alg(4)> <seq(4)> <seed(16)> ext[,id]... */
    char *response;
    char *out_buf;
    unsigned out_buf_len;
} context_t;

static void otp_both_mech_dispose(void *conn_context,
				  const sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (!text)
    return;

  if (text->user) _plug_free_string(utils,&(text->user));
  if (text->authid) _plug_free_string(utils,&(text->authid));
  if (text->response) _plug_free_string(utils,&(text->response));
  
  if(text->out_buf) utils->free(text->out_buf);

  utils->free(text);
}

static void otp_both_mech_free(void *global_context,
			       const sasl_utils_t *utils)
{
    if(global_context) utils->free(global_context);  
}

#ifdef HAVE_OPIE
/*
 * The server side of the OTP plugin depends on the OPIE library.
 */
static int otp_server_mech_new(void *glob_context __attribute__((unused)), 
				 sasl_server_params_t *sparams,
				 const char *challenge __attribute__((unused)),
				 unsigned challen __attribute__((unused)),
				 void **conn)
{
  context_t *text;

  /* holds state are in */
  text=sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) {
      MEMERROR(sparams->utils);
      return SASL_NOMEM;
  }

  memset(text, 0, sizeof(context_t));

  text->state=1;

  *conn=text;

  return SASL_OK;
}

static void otp_server_mech_dispose(void *conn_context,
				    const sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (!text)
    return;

  /* if we created a challenge, but bailed before the verification of the
     response, do a verify here to release the lock on the user key */
  if (text->state == 2) opieverify(&text->opie, "");

  otp_both_mech_dispose(conn_context, utils);
}

static const char blank_server_out[] = "";

static int
otp_server_mech_step(void *conn_context,
		       sasl_server_params_t *params,
		       const char *clientin,
		       unsigned clientinlen,
		       const char **serverout,
		       unsigned *serveroutlen,
		       sasl_out_params_t *oparams)
{
    context_t *text;
    text=conn_context;

    oparams->mech_ssf=0;
    oparams->maxoutbuf = 0;
  
    oparams->encode = NULL;
    oparams->decode = NULL;

    oparams->user = NULL;
    oparams->authid = NULL;

    oparams->param_version = 0;

  if (text->state == 1) {
    const char *author;
    const char *authen;
    size_t authen_len;
    unsigned lup=0;
    int result;

    /* should have received author-id NUL authen-id */

    /* get author */
    author = clientin;
    while ((lup < clientinlen) && (clientin[lup] != 0))
      ++lup;

    if (lup >= clientinlen)
    {
	SETERROR(params->utils, "Can only find author (no authen)");
	return SASL_BADPROT;
    }

    /* get authen */
    ++lup;
    authen = clientin + lup;
    while ((lup < clientinlen) && (clientin[lup] != 0))
      ++lup;

    authen_len = clientin + lup - authen;

    if (lup != clientinlen) {
	SETERROR(params->utils,
		 "Got more data than we were expecting in the OTP plugin\n");
	return SASL_BADPROT;
    }
    
    if (strlen(author)) {
	text->user = params->utils->malloc(strlen(author) + 1);    
	if (text->user == NULL) {
	    MEMERROR(params->utils);
	    return SASL_NOMEM;
	}

	strcpy(text->user, author);
    }

    text->authid = params->utils->malloc(authen_len + 1);    
    if (text->authid == NULL) {
	MEMERROR(params->utils);
	return SASL_NOMEM;
    }

    /* we can't assume that authen is null-terminated */
    strncpy(text->authid, authen, authen_len);
    text->authid[authen_len] = '\0';

    /* create challenge - return sasl_continue on success */
    result = opiechallenge(&text->opie, text->authid, text->challenge);

    switch (result) {
    case 0:
	*serverout = text->challenge;
	*serveroutlen = strlen(text->challenge);
	text->state = 2;
	return SASL_CONTINUE;
	break;

    case 1:
	SETERROR(params->utils, "opiechallenge: user not found or locked");
	result = SASL_NOUSER;
	break;

    default:
	SETERROR(params->utils,
		 "opiechallenge: system error (file, memory, I/O)");
	result = SASL_FAIL;
	break;
    }
    
    *serverout = blank_server_out;
    *serveroutlen = 0;
    text->state = 3; /* so fails if called again */
    return result;
  }

  if (text->state == 2) {
    char response[OPIE_RESPONSE_MAX+1];
    int result;

    /* should have received extended response,
       but we'll take anything that we can verify */

    if (clientinlen > OPIE_RESPONSE_MAX) {
	SETERROR(params->utils, "response too long");
	return SASL_BADPROT;
    }

    /* we can't assume that the response is null-terminated */
    strncpy(response, clientin, clientinlen);
    response[clientinlen] = '\0';

    /* verify response */
    result = opieverify(&text->opie, response);

    switch (result) {
    case 0:
	result = params->canon_user(params->utils->conn,
				    text->user ? text->user : text->authid, 0,
				    SASL_CU_AUTHZID, oparams);
	if (result != SASL_OK)
	    break;

	result = params->canon_user(params->utils->conn,
				    text->authid, 0,
				    SASL_CU_AUTHID, oparams);
	if (result == SASL_OK)
	    oparams->doneflag = 1;
	break;

    case 1:
	SETERROR(params->utils, "opieverify: invalid/incorrect response");
	result = SASL_BADAUTH;
	break;

    default:
	SETERROR(params->utils, "opieverify: system error (file, memory, I/O)");
	result = SASL_FAIL;
	break;
    }
    
    *serverout = blank_server_out;
    *serveroutlen = 0;
    text->state = 3; /* so fails if called again */
    return result;
  }

  SETERROR( params->utils,
	    "Unexpected State Reached in OTP plugin");
  return SASL_FAIL; /* should never get here */
}

#ifdef DO_OTP_SETPASS
static int otp_setpass(void *glob_context __attribute__((unused)),
		       sasl_server_params_t *sparams,
		       const char *user,
		       const char *pass,
		       unsigned passlen __attribute__((unused)),
		       const char *oldpass __attribute__((unused)),
		       unsigned oldpasslen __attribute__((unused)),
		       unsigned flags)
{
    unsigned short randnum;
    char seed[OPIE_SEED_MAX+1];
    int n = 499, rval;

    /* XXX should we do a lookup for any reason? */

    sparams->utils->rand(sparams->utils->rpool,
			 (char*) &randnum, sizeof(randnum));
    sprintf(seed, "%.2s%04u", sparams->serverFQDN, (randnum % 9999) + 1);

    if (flags & SASL_SET_DISABLE)
	rval = opiepasswd(NULL, 0, (char*) user, 0, seed, NULL);
    else 
	rval = opiepasswd(NULL, OPIEPASSWD_CONSOLE | OPIEPASSWD_FORCE,
			  (char*) user, n, seed, (char*) pass);

    return (rval ? SASL_FAIL : SASL_OK);
}
#endif /* DO_OTP_SETPASS */

static int otp_mech_avail(void *glob_context __attribute__((unused)),
	  	          sasl_server_params_t *sparams,
		          void **conn_context __attribute__((unused))) 
{
    const char *fname;
    unsigned int len;

    sparams->utils->getopt(sparams->utils->getopt_context,
			   "OTP", "opiekeys", &fname, &len);

    if (!fname) fname = OPIE_KEYFILE;

    if (access(fname, R_OK|W_OK) != 0) {
	sparams->utils->log(NULL, SASL_LOG_ERR,
			    "OTP unavailable because "
			    "can't read/write key database %s: %m",
			    fname, errno);
	return SASL_NOMECH;
    }

    return SASL_OK;
}

static sasl_server_plug_t otp_server_plugins[] = 
{
  {
    "OTP",
    0,
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
    SASL_FEAT_WANT_CLIENT_FIRST,
    NULL,
    &otp_server_mech_new,
    &otp_server_mech_step,
    &otp_server_mech_dispose,
    &otp_both_mech_free,
#ifdef DO_OTP_SETPASS
    &otp_setpass,
#else
    NULL,
#endif
    NULL,
    NULL,
    &otp_mech_avail,
    NULL
  }
};

int otp_server_plug_init(const sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_server_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion<SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "OTP version mismatch");
	return SASL_BADVERS;
    }
    
    *pluglist=otp_server_plugins;

    *plugcount=1;  
    *out_version=SASL_SERVER_PLUG_VERSION;

    return SASL_OK;
}
#else /* HAVE_OPIE */
/* we need this stub for linkage reasons (otp_init.c) */
int otp_server_plug_init(const sasl_utils_t *utils __attribute__((unused)),
			   int maxversion __attribute__((unused)),
			   int *out_version,
			   sasl_server_plug_t **pluglist,
			   int *plugcount)
{
    *pluglist=NULL;
    *plugcount=0;  
    *out_version=SASL_SERVER_PLUG_VERSION;

    return SASL_OK;
}
#endif /* HAVE_OPIE */

/* put in sasl_wrongmech */
static int otp_client_mech_new(void *glob_context __attribute__((unused)),
				 sasl_client_params_t *params,
				 void **conn)
{
    context_t *text;

    /* holds state are in */
    text = params->utils->malloc(sizeof(context_t));
    if (text==NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(context_t));

    text->state=1;
    *conn=text;

    return SASL_OK;
}

/* 
 * Trys to find the prompt with the lookingfor id in the prompt list
 * Returns it if found. NULL otherwise
 */
static sasl_interact_t *find_prompt(sasl_interact_t **promptlist,
				    unsigned int lookingfor)
{
  sasl_interact_t *prompt;

  if (promptlist && *promptlist)
    for (prompt = *promptlist;
	 prompt->id != SASL_CB_LIST_END;
	 ++prompt)
      if (prompt->id==lookingfor)
	return prompt;

  return NULL;
}

/*
 * Somehow retrieve the userid
 * This is the same as in digest-md5 so change both
 */
static int get_userid(sasl_client_params_t *params,
		      const char **userid,
		      sasl_interact_t **prompt_need)
{
  int result;
  sasl_getsimple_t *getuser_cb;
  void *getuser_context;
  sasl_interact_t *prompt;
  const char *id;

  /* see if we were given the userid in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_USER);
  if (prompt!=NULL)
    {
	*userid = prompt->result;
	return SASL_OK;
    }

  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_USER,
				      &getuser_cb,
				      &getuser_context);
  if (result == SASL_OK && getuser_cb) {
    id = NULL;
    result = getuser_cb(getuser_context,
			SASL_CB_USER,
			&id,
			NULL);
    if (result != SASL_OK)
      return result;
    if (! id) {
	PARAMERROR(params->utils);
	return SASL_BADPARAM;
    }
    
    *userid = id;
  }

  return result;
}

static int get_authid(sasl_client_params_t *params,
		      const char **authid,
		      sasl_interact_t **prompt_need)
{

  int result;
  sasl_getsimple_t *getauth_cb;
  void *getauth_context;
  sasl_interact_t *prompt;
  const char *id;

  /* see if we were given the authname in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_AUTHNAME);
  if (prompt!=NULL)
  {
      *authid = prompt->result;
      
      return SASL_OK;
  }

  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_AUTHNAME,
				      &getauth_cb,
				      &getauth_context);
  if (result == SASL_OK && getauth_cb) {
    id = NULL;
    result = getauth_cb(getauth_context,
			SASL_CB_AUTHNAME,
			&id,
			NULL);
    if (result != SASL_OK)
      return result;
    if (! id) {
	PARAMERROR( params->utils );
	return SASL_BADPARAM;
    }
    
    *authid = id;
  }

  return result;
}

static int get_otpassword(sasl_client_params_t *params,
			  const char *challenge,
			  const char **password,
			  sasl_interact_t **prompt_need)
{

  int result;
  sasl_chalprompt_t *getecho_cb;
  void *getecho_context;
  sasl_interact_t *prompt;

  /* see if we were given the password in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_ECHOPROMPT);
  if (prompt!=NULL)
  {
      /* We prompted, and got.*/
	
      if (! prompt->result) {
	  SETERROR(params->utils, "Unexpectedly missing a prompt result");
	  return SASL_FAIL;
      }
      
      *password = prompt->result;

      return SASL_OK;
  }


  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_ECHOPROMPT,
				      &getecho_cb,
				      &getecho_context);

  if (result == SASL_OK && getecho_cb)
    result = getecho_cb(getecho_context,
			SASL_CB_ECHOPROMPT,
			challenge,
			"Please enter your one-time password", NULL,
			password,
			NULL);

  return result;
}

#ifdef HAVE_OPIE
static int get_secret(sasl_client_params_t *params,
		      sasl_secret_t **secret,
		      sasl_interact_t **prompt_need)
{

  int result;
  sasl_getsecret_t *getpass_cb;
  void *getpass_context;
  sasl_interact_t *prompt;

  /* see if we were given the secret in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_PASS);
  if (prompt!=NULL)
  {
      /* We prompted, and got.*/
	
      if (! prompt->result) {
	  SETERROR(params->utils, "Unexpectedly missing a prompt result");
	  return SASL_FAIL;
      }
      
      /* copy what we got into a secret_t */
      *secret = (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t)+
							prompt->len+1);
      if (! *secret) {
	  MEMERROR( params->utils );
	  return SASL_NOMEM;
      }
      
      (*secret)->len=prompt->len;
      memcpy((*secret)->data, prompt->result, prompt->len);
      (*secret)->data[(*secret)->len]=0;

      return SASL_OK;
  }


  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_PASS,
				      &getpass_cb,
				      &getpass_context);

  if (result == SASL_OK && getpass_cb)
    result = getpass_cb(params->utils->conn,
			getpass_context,
			SASL_CB_PASS,
			secret);

  return result;
}
#endif /* HAVE_OPIE */

/*
 * Make the necessary prompts
 */
static int make_prompts(void *conn_context,
			sasl_client_params_t *params,
			sasl_interact_t **prompts_res,
			int user_res,
			int auth_res,
			int echo_res,
			int pass_res)
{
  int num=1;
  sasl_interact_t *prompts;
  context_t *text;

  text=conn_context;

  if (user_res==SASL_INTERACT) num++;
  if (auth_res==SASL_INTERACT) num++;
  if (echo_res==SASL_INTERACT) num++;
  if (pass_res==SASL_INTERACT) num++;

  if (num==1) {
      SETERROR( params->utils, "make_prompts called with no actual prompts" );
      return SASL_FAIL;
  }

  prompts=params->utils->malloc(sizeof(sasl_interact_t)*(num+1));
  if ((prompts) ==NULL) {
      MEMERROR( params->utils );
      return SASL_NOMEM;
  }
  
  *prompts_res=prompts;

  if (user_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_USER;
    (prompts)->challenge="Authorization Name";
    (prompts)->prompt="Please enter your authorization name";
    (prompts)->defresult=NULL;

    prompts++;
  }

  if (auth_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_AUTHNAME;
    (prompts)->challenge="Authentication Name";
    (prompts)->prompt="Please enter your authentication name";
    (prompts)->defresult=NULL;

    prompts++;
  }


  if (echo_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_ECHOPROMPT;
    (prompts)->challenge=text->challenge;
    (prompts)->prompt="Please enter your one-time password";
    (prompts)->defresult=NULL;

    prompts++;
  }

  if (pass_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_PASS;
    (prompts)->challenge="Secret";
    (prompts)->prompt="Please enter your secret pass-phrase";
    (prompts)->defresult=NULL;

    prompts++;
  }

  /* add the ending one */
  (prompts)->id=SASL_CB_LIST_END;
  (prompts)->challenge=NULL;
  (prompts)->prompt   =NULL;
  (prompts)->defresult=NULL;

  return SASL_OK;
}



static int otp_client_mech_step(void *conn_context,
				sasl_client_params_t *params,
				const char *serverin,
				unsigned serverinlen,
				sasl_interact_t **prompt_need,
				const char **clientout,
				unsigned *clientoutlen,
				sasl_out_params_t *oparams)
{

  int result;
  const char *user, *authid;
  
  context_t *text;
  text=conn_context;

  *clientout = NULL;
  *clientoutlen = 0;

  /* doesn't really matter how the server responds */

  if (text->state==1) {
    int user_result=SASL_OK;
    int auth_result=SASL_OK;
    int echo_result=SASL_OK;
    int pass_result=SASL_OK;

    /* check if sec layer strong enough */
    if (params->props.min_ssf>0+params->external_ssf) {
	SETERROR( params->utils, "The OTP plugin cannot support any SSF");
	return SASL_TOOWEAK;
    }

    /* try to get the authid */    
    if (oparams->authid==NULL)
    {
      auth_result=get_authid(params,
			     &authid,
			     prompt_need);

      if ((auth_result!=SASL_OK) && (auth_result!=SASL_INTERACT))
	return auth_result;
    }			

    /* try to get the userid */
    if (oparams->user==NULL)
    {
      user_result=get_userid(params,
			     &user,
			     prompt_need);

      /* Fallback to authid */
      if ((user_result!=SASL_OK) && (user_result!=SASL_INTERACT)) {
	  user = authid;
      }
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }

    /* if there are prompts not filled in */
    if ((user_result==SASL_INTERACT) || (auth_result==SASL_INTERACT))
    {
      /* make the prompt list */
      result=make_prompts(text, params, prompt_need,
			  user_result, auth_result, echo_result, pass_result);
      if (result!=SASL_OK) return result;
      
      return SASL_INTERACT;
    }
    
    params->canon_user(params->utils->conn, user, 0,
		       SASL_CU_AUTHZID, oparams);
    params->canon_user(params->utils->conn, authid, 0,
		       SASL_CU_AUTHID, oparams);

    /* send authorized id NUL authentication id */
    {
      *clientoutlen = (oparams->ulen + 1 + oparams->alen);

      /* remember the extra NUL on the end for stupid clients */
      result = _plug_buf_alloc(params->utils, &(text->out_buf),
			       &(text->out_buf_len), *clientoutlen + 1);
      if(result != SASL_OK) return result;

      memset(text->out_buf, 0, *clientoutlen + 1);
      memcpy(text->out_buf, oparams->user, oparams->ulen);
      memcpy(text->out_buf+oparams->ulen+1, oparams->authid, oparams->alen);
      *clientout=text->out_buf;
    }

    /* set oparams */
    oparams->mech_ssf=0;
    oparams->maxoutbuf=0;
    oparams->encode=NULL;
    oparams->decode=NULL;

    oparams->param_version = 0;

    text->state = 2;

    return SASL_CONTINUE;
  }

  if (text->state==2) {
    int user_result=SASL_OK;
    int auth_result=SASL_OK;
    int echo_result=SASL_OK;
    int pass_result=SASL_OK;
#ifdef HAVE_OPIE
    sasl_secret_t *secret = NULL;
#endif

    if (serverinlen > sizeof(text->challenge)) {
	SETERROR(params->utils, "challenge too long");
	return SASL_BADPROT;
    }

    /* we can't assume that challenge is null-terminated */
    strncpy(text->challenge, serverin, serverinlen);
    text->challenge[serverinlen] = '\0';

    /* try to get the one-time password */
    echo_result=get_otpassword(params, text->challenge,
			       (const char **)&text->response, prompt_need);

    if ((echo_result!=SASL_OK) && (echo_result!=SASL_INTERACT)) {
#ifdef HAVE_OPIE
	/*
	 * try to get the secret pass-phrase
	 *
	 * we only do this if we have OPIE to generate a response
	 */
	pass_result=get_secret(params, &secret, prompt_need);
      
	if ((pass_result!=SASL_OK) && (pass_result!=SASL_INTERACT))
	    return pass_result;
#else
	return echo_result;
#endif /* HAVE_OPIE */
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }

    /* if there are prompts not filled in */
    if ((echo_result==SASL_INTERACT) || (pass_result==SASL_INTERACT))
    {
      /* make the prompt list */
      result=make_prompts(text, params, prompt_need,
			  user_result, auth_result, echo_result, pass_result);
      if (result!=SASL_OK) return result;
      
      return SASL_INTERACT;
    }

    /* the application provided us with a one-time password so use it */
    if (text->response) {
	text->state = 3;
	*clientout = text->response;
	*clientoutlen = strlen(text->response);
	return SASL_OK;
    }

#ifdef HAVE_OPIE
    /* generate our own response using the user's secret pass-phrase */
    else {
	if (!secret) {
	    PARAMERROR(params->utils);
	    return SASL_BADPARAM;
	}

	text->response = params->utils->malloc(OPIE_RESPONSE_MAX + 1);    
	if (text->response == NULL) {
	    MEMERROR(params->utils);
	    return SASL_NOMEM;
	}

	/*
	 * generate response - return sasl_ok on success
	 *
	 * this will auto-reset the user's secret pass-phrase if necessary
	 * (ONLY with patched opiegenerator())
	 */
	result = opiegenerator(text->challenge, secret->data, text->response);

	/* free sensitive info */
	_plug_free_secret(params->utils, &secret);

	text->state = 3;

	switch (result) {
	case 0:
#if 0
	    /*
	     * make sure we're using extended syntax
	     *
	     * XXX  NOT necessary with patched opiegenerator() and
	     *      _opieparsechallenge()
	     */
	    if (!strchr(text->response, ':')) {
		char *type = (strlen(text->response) < 23) ? "hex:" : "word:";
		memmove(text->response + strlen(type), text->response,
		       strlen(text->response)+1);
		strncpy(text->response, type, strlen(type));
	    }
#endif

	    *clientout = text->response;
	    *clientoutlen = strlen(text->response);
	    return SASL_OK;
	    break;

	case -2:
	    SETERROR(params->utils, "opiegenerator: invalid secret pass phrase");
	    result = SASL_FAIL;
	    break;

	case -1:
	    SETERROR(params->utils, "opiegenerator: error processing challenge");
	    result = SASL_FAIL;
	    break;

	case 1:
	    SETERROR(params->utils, "opiegenerator: invalid challenge");
	    result = SASL_BADPROT;
	    break;

	default:
	    SETERROR(params->utils, "opiegenerator: unknown error");
	    result = SASL_FAIL;
	    break;
	}

	*clientout = NULL;
	*clientoutlen = 0;
	return result;
    }
#endif /* HAVE_OPIE */

  }

  return SASL_FAIL; /* should never get here */
}

static sasl_client_plug_t otp_client_plugins[] = 
{
  {
    "OTP",
    0,
    SASL_SEC_NOANONYMOUS,
    SASL_FEAT_WANT_CLIENT_FIRST,
    NULL,
    NULL,
    &otp_client_mech_new,
    &otp_client_mech_step,
    &otp_both_mech_dispose,
    &otp_both_mech_free,
    NULL,
    NULL,
    NULL
  }
};

int otp_client_plug_init(sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_client_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion<SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "OTP version mismatch");
	return SASL_BADVERS;
    }

    *pluglist=otp_client_plugins;

    *plugcount=1;
    *out_version=SASL_CLIENT_PLUG_VERSION;

    return SASL_OK;
}
