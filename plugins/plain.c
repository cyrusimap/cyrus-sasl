/* Plain SASL plugin
 * Rob Siemborski
 * Tim Martin 
 * $Id: plain.c,v 1.45 2001/12/04 02:06:49 rjs3 Exp $
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
#include <string.h> 
#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

#ifdef WIN32
/* This must be after sasl.h */
# include "saslPLAIN.h"
#endif /* WIN32 */

#ifdef macintosh 
#include <sasl_plain_plugin_decl.h> 
#endif 

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#undef L_DEFAULT_GUARD
#define L_DEFAULT_GUARD (0)

typedef struct context {
    int state;
    sasl_secret_t *password;
    char *out_buf;
    unsigned out_buf_len;
} context_t;

static int plain_server_mech_new(void *glob_context __attribute__((unused)), 
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

static void plain_both_mech_dispose(void *conn_context,
				    const sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (!text)
    return;

  /* free sensitive info */
  _plug_free_secret(utils, &(text->password));
  
  if(text->out_buf)
      utils->free(text->out_buf);

  utils->free(text);
}

static void plain_both_mech_free(void *global_context,
				 const sasl_utils_t *utils)
{
    if(global_context) utils->free(global_context);  
}

/* fills in password; remember to free password and wipe it out correctly */
static
int verify_password(sasl_server_params_t *params, 
		    const char *user, const char *pass)
{
    int result;
    
    /* if it's null, checkpass will default */
    result = params->utils->checkpass(params->utils->conn,
				      user, 0, pass, 0);
    
    return result;
}

static const char blank_server_out[] = "";

static int
plain_server_mech_step(void *conn_context,
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
    const char *password;
    size_t password_len;
    unsigned lup=0;
    int result;
    char *passcopy; 

    /* should have received author-id NUL authen-id NUL password */

    /* get author */
    author = clientin;
    while ((lup < clientinlen) && (clientin[lup] != 0))
      ++lup;

    if (lup >= clientinlen)
    {
	SETERROR(params->utils, "Can only find author (no password)");
	return SASL_BADPROT;
    }

    /* get authen */
    ++lup;
    authen = clientin + lup;
    while ((lup < clientinlen) && (clientin[lup] != 0))
      ++lup;

    if (lup >= clientinlen)
    {
	params->utils->seterror(params->utils->conn, 0,
				"Can only find author/en (no password)");
	return SASL_BADPROT;
    }

    /* get password */
    lup++;
    password = clientin + lup;
    while ((lup < clientinlen) && (clientin[lup] != 0))
      ++lup;

    password_len = clientin + lup - password;

    if (lup != clientinlen) {
	SETERROR(params->utils, "Got more data than we were expecting in the PLAIN plugin\n");
	return SASL_BADPROT;
    }
    
    /* this kinda sucks. we need password to be null terminated
       but we can't assume there is an allocated byte at the end
       of password so we have to copy it */
    passcopy = params->utils->malloc(password_len + 1);    
    if (passcopy == NULL) {
	MEMERROR(params->utils);
	return SASL_NOMEM;
    }

    strncpy(passcopy, password, password_len);
    passcopy[password_len] = '\0';

    /* verify password - return sasl_ok on success*/    
    result = verify_password(params, authen, passcopy);
    
    _plug_free_string(params->utils, &passcopy);

    if (result != SASL_OK)
    {
	params->utils->seterror(params->utils->conn, 0,
				"Password verification failed");
	return result;
    }

    if (! author || !*author)
      author = authen;

    result = params->canon_user(params->utils->conn,
				author, 0, authen, 0, 0, oparams);
    if(result != SASL_OK) return result;

    if (params->transition)
    {
	params->transition(params->utils->conn,
			   password, password_len);
    }
    
    *serverout = blank_server_out;
    *serveroutlen = 0;

    text->state++; /* so fails if called again */

    oparams->doneflag = 1;

    return SASL_OK;
  }

  SETERROR( params->utils,
	    "Unexpected State Reached in PLAIN plugin");
  return SASL_FAIL; /* should never get here */
}

static sasl_server_plug_t plain_server_plugins[] = 
{
  {
    "PLAIN",
    0,
    SASL_SEC_NOANONYMOUS,
    SASL_FEAT_WANT_CLIENT_FIRST,
    NULL,
    &plain_server_mech_new,
    &plain_server_mech_step,
    &plain_both_mech_dispose,
    &plain_both_mech_free,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
  }
};

int plain_server_plug_init(const sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_server_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion<SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "PLAIN version mismatch");
	return SASL_BADVERS;
    }
    
    *pluglist=plain_server_plugins;

    *plugcount=1;  
    *out_version=SASL_SERVER_PLUG_VERSION;

    return SASL_OK;
}

/* put in sasl_wrongmech */
static int plain_client_mech_new(void *glob_context __attribute__((unused)),
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

static int get_password(sasl_client_params_t *params,
		      sasl_secret_t **password,
		      sasl_interact_t **prompt_need)
{

  int result;
  sasl_getsecret_t *getpass_cb;
  void *getpass_context;
  sasl_interact_t *prompt;

  /* see if we were given the password in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_PASS);
  if (prompt!=NULL)
  {
      /* We prompted, and got.*/
	
      if (! prompt->result) {
	  SETERROR(params->utils, "Unexpectedly missing a prompt result");
	  return SASL_FAIL;
      }
      
      /* copy what we got into a secret_t */
      *password = (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t)+
							  prompt->len+1);
      if (! *password) {
	  MEMERROR( params->utils );
	  return SASL_NOMEM;
      }
      
      (*password)->len=prompt->len;
      memcpy((*password)->data, prompt->result, prompt->len);
      (*password)->data[(*password)->len]=0;

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
			password);

  return result;
}

/*
 * Make the necessary prompts
 */
static int make_prompts(sasl_client_params_t *params,
			sasl_interact_t **prompts_res,
			int user_res,
			int auth_res,
			int pass_res)
{
  int num=1;
  sasl_interact_t *prompts;

  if (user_res==SASL_INTERACT) num++;
  if (auth_res==SASL_INTERACT) num++;
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


  if (pass_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_PASS;
    (prompts)->challenge="Password";
    (prompts)->prompt="Please enter your password";
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



static int plain_client_mech_step(void *conn_context,
				  sasl_client_params_t *params,
				  const char *serverin __attribute__((unused)),
				  unsigned serverinlen __attribute__((unused)),
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
    int pass_result=SASL_OK;

    /* check if sec layer strong enough */
    if (params->props.min_ssf>0+params->external_ssf) {
	SETERROR( params->utils, "The PLAIN plugin cannot support any SSF");
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

    /* try to get the password */
    if (text->password==NULL)
    {
      pass_result=get_password(params,
			       &text->password,
			       prompt_need);
      
      if ((pass_result!=SASL_OK) && (pass_result!=SASL_INTERACT))
	return pass_result;
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }

    /* if there are prompts not filled in */
    if ((user_result==SASL_INTERACT) || (auth_result==SASL_INTERACT) ||
	(pass_result==SASL_INTERACT))
    {
      /* make the prompt list */
      result=make_prompts(params,prompt_need,
			  user_result, auth_result, pass_result);
      if (result!=SASL_OK) return result;
      
      return SASL_INTERACT;
    }
    
    params->canon_user(params->utils->conn, user, 0, authid, 0, 0, oparams);

    if (!text->password) {
	PARAMERROR(params->utils);
	return SASL_BADPARAM;
    }
    
    /* send authorized id NUL authentication id NUL password */
    {
      *clientoutlen = (oparams->ulen + 1
		       + oparams->alen + 1
		       + text->password->len);

      /* remember the extra NUL on the end for stupid clients */
      result = _plug_buf_alloc(params->utils, &(text->out_buf),
			       &(text->out_buf_len), *clientoutlen + 1);
      if(result != SASL_OK) return result;

      memset(text->out_buf, 0, *clientoutlen + 1);
      memcpy(text->out_buf, oparams->user, oparams->ulen);
      memcpy(text->out_buf+oparams->ulen+1, oparams->authid, oparams->alen);
      memcpy(text->out_buf+oparams->ulen+oparams->alen+2,
	     text->password->data,
	     text->password->len);

      *clientout=text->out_buf;
    }

    /* set oparams */
    oparams->mech_ssf=0;
    oparams->maxoutbuf=0;
    oparams->encode=NULL;
    oparams->decode=NULL;

    oparams->param_version = 0;

    text->state = 2;

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static sasl_client_plug_t plain_client_plugins[] = 
{
  {
    "PLAIN",
    0,
    SASL_SEC_NOANONYMOUS,
    SASL_FEAT_WANT_CLIENT_FIRST,
    NULL,
    NULL,
    &plain_client_mech_new,
    &plain_client_mech_step,
    &plain_both_mech_dispose,
    &plain_both_mech_free,
    NULL,
    NULL,
    NULL
  }
};

int plain_client_plug_init(sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_client_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion<SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "PLAIN version mismatch");
	return SASL_BADVERS;
    }

    *pluglist=plain_client_plugins;

    *plugcount=1;
    *out_version=SASL_CLIENT_PLUG_VERSION;

    return SASL_OK;
}
