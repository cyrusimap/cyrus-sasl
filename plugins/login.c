/* Login SASL plugin
 * Rob Siemborski (SASLv2 Conversion)
 * contributed by Rainer Schoepf <schoepf@uni-mainz.de>
 * based on PLAIN, by Tim Martin <tmartin@andrew.cmu.edu>
 * $Id: login.c,v 1.11 2002/01/19 22:15:07 rjs3 Exp $
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
#include <ctype.h>
#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

#ifdef WIN32
/* This must be after sasl.h */
# include "saslLOGIN.h"
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#undef L_DEFAULT_GUARD
#define L_DEFAULT_GUARD (0)

#define USERNAME "Username:"
#define PASSWORD "Password:"

typedef struct context {
    int state;
    sasl_secret_t *username;
    sasl_secret_t *password;
} context_t;

static int login_server_mech_new(void *glob_context __attribute__((unused)), 
				 sasl_server_params_t *sparams,
				 const char *challenge __attribute__((unused)),
				 unsigned challen __attribute__((unused)),
				 void **conn)
{
  context_t *text;

  /* holds state are in */
  text=sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) {
      MEMERROR( sparams->utils );
      return SASL_NOMEM;
  }

  memset(text, 0, sizeof(context_t));

  text->state=1;

  *conn=text;

  return SASL_OK;
}

static void login_both_mech_dispose(void *conn_context,
				    const sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (!text)
    return;

  /* free sensitive info */
  _plug_free_secret(utils, &(text->username));
  _plug_free_secret(utils, &(text->password));

  utils->free(text);
}

static void login_both_mech_free(void *global_context,
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

static int
login_server_mech_step(void *conn_context,
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
      text->state = 2;

      /* Check inlen, (possibly we have already the user name) */
      /* In this case fall through to state 2 */
      if (clientinlen == 0) {
	  /* get username */
	  
	  *serveroutlen = strlen(USERNAME);
	  *serverout = USERNAME;
	  
	  return SASL_CONTINUE;
      }
  }

  if (text->state == 2) {
    /* Catch really long usernames */
    if(clientinlen > 1024) {
	SETERROR(params->utils, "username too long (>1024 characters)");
	return SASL_BADPROT;
    }

    /* get username */
    text->username =
	(sasl_secret_t *)params->utils->malloc(sizeof(sasl_secret_t)+clientinlen+1);
    if (! text->username) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }

    strncpy(text->username->data,clientin,clientinlen);
    text->username->data[clientinlen] = '\0';
    text->username->len = clientinlen;

    /* Request password */

    *serveroutlen = strlen(PASSWORD);
    *serverout = PASSWORD;

    text->state = 3;

    return SASL_CONTINUE;
  }

  if (text->state == 3) {
    int result;

    /* Catch really long passwords */
    if(clientinlen > 1024) {
	SETERROR(params->utils, "clientinlen is > 1024 characters in LOGIN plugin");
	return SASL_BADPROT;
    }

    /* get password */
    text->password = params->utils->malloc(sizeof(sasl_secret_t) + clientinlen + 1);
    if (! text->password) {
	MEMERROR(params->utils);
	return SASL_NOMEM;
    }

    strncpy(text->password->data,clientin,clientinlen);
    text->password->data[clientinlen] = '\0';
    text->password->len = clientinlen;

    /* verify_password - return sasl_ok on success */

    result = verify_password(params, text->username->data,
			     text->password->data);

    if (result != SASL_OK)
      return result;

    result = params->canon_user(params->utils->conn, text->username->data, 0,
				SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if(result != SASL_OK) return result;

    if (params->transition)
    {
	params->transition(params->utils->conn,
			   text->password->data, text->password->len);
    }
    
    *serverout = NULL;
    *serveroutlen = 0;

    text->state++; /* so fails if called again */

    oparams->doneflag = 1;

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static sasl_server_plug_t login_server_plugins[] = 
{
  {
    "LOGIN",
    0,
    SASL_SEC_NOANONYMOUS,
    0,
    NULL,
    &login_server_mech_new,
    &login_server_mech_step,
    &login_both_mech_dispose,
    &login_both_mech_free,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
  }
};

int login_server_plug_init(sasl_utils_t *utils __attribute__((unused)),
			   int maxversion,
			   int *out_version,
			   sasl_server_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion<SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "LOGIN version mismatch");
	return SASL_BADVERS;
    }
    
    *pluglist=login_server_plugins;

    *plugcount=1;  
    *out_version=SASL_SERVER_PLUG_VERSION;

    return SASL_OK;
}

/* put in sasl_wrongmech */
static int login_client_mech_new(void *glob_context __attribute__((unused)),
				 sasl_client_params_t *params,
				 void **conn)
{
  context_t *text;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) {
      MEMERROR(params->utils);
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

/* Note: we want to grab the authname and not the userid, which is
 *       who we AUTHORIZE as, and will be the same as the authname
 *       for the LOGIN mech.
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
  prompt=find_prompt(prompt_need,SASL_CB_AUTHNAME);
  if (prompt!=NULL)
    {
	*userid = prompt->result;
	return SASL_OK;
    }

  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_AUTHNAME,
				      &getuser_cb,
				      &getuser_context);
  if (result == SASL_OK && getuser_cb) {
    id = NULL;
    result = getuser_cb(getuser_context,
			SASL_CB_AUTHNAME,
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
	  SETERROR(params->utils, "Expected prompt result and got none in LOGIN");
	  return SASL_FAIL;
      }
      

      /* copy what we got into a secret_t */
      *password = (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t)
							  + prompt->len+1);
      if (! *password) {
	  MEMERROR(params->utils);
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
			int pass_res)
{
  int num=1;
  sasl_interact_t *prompts;

  if (user_res==SASL_INTERACT) num++;
  if (pass_res==SASL_INTERACT) num++;

  if (num==1) {
      SETERROR(params->utils, "LOGIN make_prompts called without any results");
      return SASL_FAIL;
  }

  prompts=params->utils->malloc(sizeof(sasl_interact_t)*(num+1));
  if ((prompts) ==NULL) {
      MEMERROR(params->utils);
      return SASL_NOMEM;
  }
  
  *prompts_res=prompts;

  if (user_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_AUTHNAME;
    (prompts)->challenge="Authorization Name";
    (prompts)->prompt="Please enter your authorization name";
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



static int login_client_mech_step(void *conn_context,
				  sasl_client_params_t *params,
				  const char *serverin __attribute__((unused)),
				  unsigned serverinlen __attribute__((unused)),
				  sasl_interact_t **prompt_need,
				  const char **clientout,
				  unsigned *clientoutlen,
				  sasl_out_params_t *oparams)
{
  int result, ret;
  const char *user;

  context_t *text;
  text=conn_context;

  if (text->state==1)
  {
    int user_result=SASL_OK;
    int pass_result=SASL_OK;

    /* check if sec layer strong enough */
    if (params->props.min_ssf>0+params->external_ssf) {
	SETERROR( params->utils, "SSF requested of LOGIN plugin");
	return SASL_TOOWEAK;
    }

    /* try to get the userid */
    if (oparams->user==NULL)
    {
      user_result=get_userid(params,
			     &user,
			     prompt_need);

      if ((user_result!=SASL_OK) && (user_result!=SASL_INTERACT))
	return user_result;
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
    if ((user_result==SASL_INTERACT) ||	(pass_result==SASL_INTERACT))
    {
      /* make the prompt list */
      result=make_prompts(params,prompt_need,
			  user_result, pass_result);
      if (result!=SASL_OK) return result;
      
      return SASL_INTERACT;
    }

    ret = params->canon_user(params->utils->conn, user, 0,
			     SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if(ret != SASL_OK) return ret;
    
    /* set oparams */
    oparams->mech_ssf=0;
    oparams->maxoutbuf=0;
    oparams->encode=NULL;
    oparams->decode=NULL;
    oparams->param_version = 0;

    text->state = 2;

    /* Watch for initial client send, which we do not support */
    if(serverinlen == 0) {
	*clientout = NULL;
	*clientoutlen = 0;
        return SASL_CONTINUE;
    }
  }

  if (text->state == 2) {
      /* server should have sent request for username */
      if (serverinlen != strlen(USERNAME) || strcmp(USERNAME,serverin)) {
	  SETERROR( params->utils, "Invalid Server USERNAME response in LOGIN plugin");
	  return SASL_BADPROT;
      }

      if(!clientout) {
	  PARAMERROR( params->utils );
	  return SASL_BADPARAM;
      }
      
      if(clientoutlen) *clientoutlen = oparams->alen;
      *clientout = oparams->authid;

      text->state = 3;

      return SASL_CONTINUE;
  }

  if (text->state == 3) {
      if (serverinlen != strlen(PASSWORD) || strcmp(PASSWORD,serverin)) {
	  SETERROR( params->utils, "Invalid Server PASSWORD response in LOGIN plugin");
	  return SASL_BADPROT;
      }

      if(!clientout) {
	  PARAMERROR(params->utils);
	  return SASL_BADPARAM;
      }

      if(clientoutlen) *clientoutlen = text->password->len;
      *clientout = text->password->data;
      
      /* set oparams */
      oparams->param_version = 0;
      oparams->doneflag = 1;

      text->state = 99;

      return SASL_OK;
  }

  SETERROR( params->utils, "Did the impossible in client-side of LOGIN.");
  return SASL_FAIL; /* should never get here */
}

static sasl_client_plug_t login_client_plugins[] = 
{
  {
    "LOGIN",
    0,
    SASL_SEC_NOANONYMOUS,
    0,
    NULL,
    NULL,
    &login_client_mech_new,
    &login_client_mech_step,
    &login_both_mech_dispose,
    &login_both_mech_free,
    NULL,
    NULL,
    NULL
  }
};

int login_client_plug_init(sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_client_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion<SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "Version mismatch in LOGIN");
	return SASL_BADVERS;
    }

    *pluglist=login_client_plugins;

    *plugcount=1;
    *out_version=SASL_CLIENT_PLUG_VERSION;

    return SASL_OK;
}

