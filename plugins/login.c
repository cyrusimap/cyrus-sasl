/* Login SASL plugin
 * contributed by Rainer Schoepf <schoepf@uni-mainz.de>
 * based on PLAIN, by Tim Martin <tmartin@andrew.cmu.edu>
 * $Id: login.c,v 1.6 2001/02/19 19:15:12 leg Exp $
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
#include <stdio.h>
#include <ctype.h>
#include <sasl.h>
#include <saslplug.h>

#ifdef WIN32
/* This must be after sasl.h */
# include "saslLOGIN.h"
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define LOGIN_VERSION (3)
#undef L_DEFAULT_GUARD
#define L_DEFAULT_GUARD (0)

#define USERNAME "Username:"
#define PASSWORD "Password:"

typedef struct context {
  int state;
  sasl_secret_t *username;
  sasl_secret_t *password;
} context_t;


static int start(void *glob_context __attribute__((unused)), 
		 sasl_server_params_t *sparams,
		 const char *challenge __attribute__((unused)),
		 int challen __attribute__((unused)),
		 void **conn,
		 const char **errstr)
{
  context_t *text;

  if (errstr)
    *errstr = NULL;

  /* holds state are in */
  text= sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;

  text->username = NULL;
  text->password = NULL;

  *conn=text;

  return SASL_OK;
}

static void free_secret(sasl_utils_t *utils,
			sasl_secret_t **secret)
{
  size_t lup;

  VL(("Freeing secret\n"));

  if (secret==NULL) return;
  if (*secret==NULL) return;

  /* overwrite the memory */
  for (lup=0;lup<(*secret)->len;lup++)
    (*secret)->data[lup]='X';

  (*secret)->len=0;

  /* this fail in the debug version on win32, which does tighter checking */
  utils->free(*secret);

  *secret=NULL;
}

static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (!text)
    return;

  /* free sensitive info */
  free_secret(utils,&(text->username));
  free_secret(utils,&(text->password));

  utils->free(text);
}

static void mech_free(void *global_context, sasl_utils_t *utils)
{
  utils->free(global_context);  
}

/* fills in password; remember to free password and wipe it out correctly */
static
int verify_password(sasl_server_params_t *params, 
		    const char *user, const char *pass, const char **errstr)
{
    const char *mech;
    int result;
    
    params->utils->getopt(params->utils->getopt_context, "LOGIN",
			  "pwcheck_method", &mech, NULL);

    /* if it's null, checkpass will default */
    result = params->utils->checkpass(params->utils->conn,
				      mech, params->service, 
				      user, pass, errstr);
    
    return result;
}

static int
server_continue_step (void *conn_context,
		      sasl_server_params_t *params,
		      const char *clientin,
		      int clientinlen,
		      char **serverout,
		      int *serveroutlen,
		      sasl_out_params_t *oparams,
		      const char **errstr)
{
  context_t *text;
  text=conn_context;

  if (errstr) { *errstr = NULL; }

  oparams->mech_ssf=0;

  oparams->maxoutbuf = 0;
  
  oparams->encode = NULL;
  oparams->decode = NULL;

  oparams->user = NULL;
  oparams->authid = NULL;

  oparams->realm = NULL;
  oparams->param_version = 0;

  /* nothing more to do; authenticated */

  VL (("Login: server state #%i\n",text->state));

  if (text->state == 1) {

      /* Check inlen, possibly we have already the user name */
      /* In this case fall through to state 2 */
      if (clientinlen > 0) {
	  text->state = 2;
      } else {
	  /* get username */
	  
	  VL (("out=%s len=%i\n",USERNAME,strlen(USERNAME)));
  
	  *serveroutlen = strlen(USERNAME);
	  *serverout = params->utils->malloc(*serveroutlen);
	  if (! *serverout) return SASL_NOMEM;
	  memcpy(*serverout,USERNAME,*serveroutlen);
	  
	  text->state = 2;
	  
	  return SASL_CONTINUE;
      }
  }

  if (text->state == 2) {
    char *username;

    VL (("in=%s len=%i\n",clientin,clientinlen));
    /* get username */
    username = params->utils->malloc (clientinlen + 1);
    if (! username) {
      return SASL_NOMEM;
    }

    strncpy(username,clientin,clientinlen);
    username[clientinlen] = '\0';

    VL (("Got username: %s\n",username));

    /* remember username */

    text->username = (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t)+clientinlen+1);
    if (! text->username) return SASL_NOMEM;

    text->username->len = clientinlen;
    strcpy(text->username->data,username);

    /* Request password */

    VL (("out=%s len=%i\n",PASSWORD,strlen(PASSWORD)));
    *serveroutlen = strlen(PASSWORD);
    *serverout = params->utils->malloc(*serveroutlen);
    if (! *serverout) return SASL_NOMEM;
    memcpy(*serverout,PASSWORD,*serveroutlen);

    text->state = 3;

    return SASL_CONTINUE;
  }

  if (text->state == 3) {
    char *password;
    unsigned long password_len;
    int result;
    char *mem;

    /* get password */

    password = params->utils->malloc (clientinlen + 1);
    if (! password) {
      return SASL_NOMEM;
    }

    strncpy(password,clientin,clientinlen);
    password[clientinlen] = '\0';
    password_len = clientinlen;

    /* verify_password - return sasl_ok on success */

    VL (("Verifying password...\n"));
    result = verify_password(params, text->username->data, password, errstr);

    if (result != SASL_OK)
      return result;

    VL (("Password OK"));

    mem = params->utils->malloc(text->username->len + 1);
    if (! mem) return SASL_NOMEM;
    strcpy(mem, text->username->data);
    oparams->user = mem;

    mem = params->utils->malloc(text->username->len + 1);
    if (! mem) return SASL_NOMEM;
    strcpy(mem, text->username->data);
    oparams->authid = mem;

    if (params->serverFQDN) {
      mem = params->utils->malloc(strlen(params->serverFQDN) + 1);
      if (! mem) return SASL_NOMEM;
      strcpy(mem, params->serverFQDN);
      oparams->realm = mem;
    } else oparams->realm = NULL;

    if (params->transition)
    {
	params->transition(params->utils->conn,
			   password, password_len);
    }
    
    *serverout = params->utils->malloc(1);
    if (! *serverout) return SASL_NOMEM;
    (*serverout)[0] = '\0';
    *serveroutlen = 0;

    text->state++; /* so fails if called again */

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "LOGIN",
    0,
    SASL_SEC_NOANONYMOUS,
    NULL,
    &start,
    &server_continue_step,
    &dispose,
    &mech_free,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
  }
};

int sasl_server_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<LOGIN_VERSION)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=LOGIN_VERSION;

  return SASL_OK;
}

/* put in sasl_wrongmech */
static int c_start(void *glob_context __attribute__((unused)),
		   sasl_client_params_t *params,
		   void **conn)
{
  context_t *text;

  VL (("Client start\n"));
  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;  
  text->username = NULL;
  text->password = NULL;
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
		      char **userid,
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
      /* copy it */
      *userid=params->utils->malloc(strlen(prompt->result)+1);
      if ((*userid)==NULL) return SASL_NOMEM;
	
      strcpy(*userid, prompt->result);
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
    if (! id)
      return SASL_BADPARAM;
    *userid = params->utils->malloc(strlen(id) + 1);
    if (! *userid)
      return SASL_NOMEM;
    strcpy(*userid, id);
  }

  return result;
}

static int get_authid(sasl_client_params_t *params,
		      char **authid,
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
    /* copy it */
    *authid=params->utils->malloc(strlen(prompt->result)+1);
    if ((*authid)==NULL) return SASL_NOMEM;

    strcpy(*authid, prompt->result);
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
    if (! id)
      return SASL_BADPARAM;
    *authid = params->utils->malloc(strlen(id) + 1);
    if (! *authid)
      return SASL_NOMEM;
    strcpy(*authid, id);
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
	
    if (! prompt->result)
      return SASL_FAIL;

    /* copy what we got into a secret_t */
    *password = (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t)+
						       prompt->len+1);
    if (! *password) return SASL_NOMEM;

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

static void free_prompts(sasl_client_params_t *params,
			 sasl_interact_t *prompts)
{
  sasl_interact_t *ptr=prompts;
  if (ptr==NULL) return;

  do
  {
    /* xxx might be freeing static memory. is this ok? */
    if (ptr->result!=NULL)
      params->utils->free(ptr->result);

    ptr++;
  } while(ptr->id!=SASL_CB_LIST_END);

  params->utils->free(prompts);
  prompts=NULL;
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

  if (num==1) return SASL_FAIL;

  prompts=params->utils->malloc(sizeof(sasl_interact_t)*(num+1));
  if ((prompts) ==NULL) return SASL_NOMEM;
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



static int client_continue_step (void *conn_context,
				 sasl_client_params_t *params,
				 const char *serverin __attribute__((unused)),
				 int serverinlen __attribute__((unused)),
				 sasl_interact_t **prompt_need,
				 char **clientout,
				 int *clientoutlen,
				 sasl_out_params_t *oparams)
{
  int result;

  context_t *text;
  text=conn_context;

  VL(("Login step #%i\n",text->state));

  if (text->state==1)
  {
    int user_result=SASL_OK;
    int auth_result=SASL_OK;
    int pass_result=SASL_OK;

    /* check if sec layer strong enough */
    if (params->props.min_ssf>0)
      return SASL_TOOWEAK;

    /* try to get the userid */
    if (oparams->user==NULL)
    {
      VL (("Trying to get userid\n"));
      user_result=get_userid(params,
			     &oparams->user,
			     prompt_need);

      if ((user_result!=SASL_OK) && (user_result!=SASL_INTERACT))
	return user_result;
    }

    /* try to get the authid */    
    if (oparams->authid==NULL)
    {
      VL (("Trying to get authid\n"));
      auth_result=get_authid(params,
			     &oparams->authid,
			     prompt_need);

      if ((auth_result!=SASL_OK) && (auth_result!=SASL_INTERACT))
	return auth_result;
    }			

    /* try to get the password */
    if (text->password==NULL)
    {
      VL (("Trying to get password\n"));
      pass_result=get_password(params,
			       &text->password,
			       prompt_need);
      
      if ((pass_result!=SASL_OK) && (pass_result!=SASL_INTERACT))
	return pass_result;
    }

    
    /* free prompts we got */
    if (prompt_need)
      free_prompts(params,*prompt_need);

    /* if there are prompts not filled in */
    if ((user_result==SASL_INTERACT) || (auth_result==SASL_INTERACT) ||
	(pass_result==SASL_INTERACT))
    {
      /* make the prompt list */
      result=make_prompts(params,prompt_need,
			  user_result, auth_result, pass_result);
      if (result!=SASL_OK) return result;
      
      VL(("returning prompt(s)\n"));
      return SASL_INTERACT;
    }
    
    if (!oparams->authid || !text->password)
      return SASL_BADPARAM;

    VL (("Got username, authid, and password\n"));

    if (clientout) {
	/* watch out for no initial client-send */
	*clientout = params->utils->malloc(1);
	if (! *clientout) return SASL_NOMEM;
	(*clientout)[0] = '\0';
	*clientoutlen = 0;
    }

    /* set oparams */
    oparams->mech_ssf=0;
    oparams->maxoutbuf = 0;
    oparams->encode=NULL;
    oparams->decode=NULL;
    if (! oparams->user) {
      oparams->user = params->utils->malloc(strlen(oparams->authid) + 1);
      if (! oparams->user)
	return SASL_NOMEM;
      strcpy(oparams->user, oparams->authid);
    }

    if (params->serverFQDN) {
      oparams->realm = params->utils->malloc(strlen(params->serverFQDN) + 1);
      if (! oparams->realm)
	return SASL_NOMEM;
      strcpy(oparams->realm, params->serverFQDN);
    }

    oparams->param_version = 0;

    text->state = 2;

    return SASL_CONTINUE;
  }

  if (text->state == 2) {
    char *in;

    /* server should have sent request for username */

    in = params->utils->malloc(serverinlen + 1);
    if (! in) return SASL_NOMEM;
    memcpy(in, serverin, serverinlen);
    in[serverinlen] = 0;

    if (strcmp(USERNAME,in)) {
      params->utils->free(in);
      return SASL_BADPROT;
    }

    *clientoutlen = strlen(oparams->user);

    *clientout = params->utils->malloc(*clientoutlen);
    if (! *clientout) return SASL_NOMEM;
    memcpy(*clientout, oparams->user, *clientoutlen);

    text->state = 3;

    return SASL_CONTINUE;
  }

  if (text->state == 3) {
    char *in;

    /* server should have sent request for password */

    in = params->utils->malloc(serverinlen + 1);
    if (! in) return SASL_NOMEM;
    memcpy(in, serverin, serverinlen);
    in[serverinlen] = 0;

    if (strcmp(PASSWORD,in)) {
      params->utils->free(in);
      return SASL_BADPROT;
    }

    *clientoutlen = text->password->len;

    *clientout = params->utils->malloc(*clientoutlen);
    if (! *clientout) return SASL_NOMEM;
    memcpy(*clientout, text->password->data, *clientoutlen);

    /* set oparams */
    oparams->mech_ssf=0;
    oparams->maxoutbuf = 0;
    oparams->encode=NULL;
    oparams->decode=NULL;
    if (! oparams->user) {
      oparams->user = params->utils->malloc(strlen(oparams->authid) + 1);
      if (! oparams->user)
	return SASL_NOMEM;
      strcpy(oparams->user, oparams->authid);
    }

    if (params->serverFQDN) {
      oparams->realm = params->utils->malloc(strlen(params->serverFQDN) + 1);
      if (! oparams->realm)
	return SASL_NOMEM;
      strcpy(oparams->realm, params->serverFQDN);
    }

    oparams->param_version = 0;

    text->state = 99;

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "LOGIN",
    0,
    SASL_SEC_NOANONYMOUS,
    NULL,
    NULL,
    &c_start,
    &client_continue_step,
    &dispose,
    &mech_free,
    NULL,
    NULL
  }
};

int sasl_client_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<LOGIN_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=LOGIN_VERSION;

  return SASL_OK;
}

