/* Plain SASL plugin
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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#ifndef SASL_MINIMAL_SERVER
#include <pwd.h>
#endif /* SASL_MINIMAL_SERVER */
#include <sasl.h>
#include <saslplug.h>

#ifdef WIN32
/* This must be after sasl.h */
# include "saslPLAIN.h"
#endif /* WIN32 */

extern char *crypt(const char *, const char *);

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define PLAIN_VERSION (3)

typedef struct context {
  int state;
  char *userid;			/* userid to log in as -- authorization */
  char *authid;			/* authentication name */
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

  text->userid = NULL;
  text->authid = NULL;
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

  utils->free(*secret);

  *secret=NULL;
}

static void free_string(sasl_utils_t *utils,
			char **str)
{
  size_t lup;
  int len;
  VL(("Freeing string\n"));

  if (str==NULL) return;
  if (*str==NULL) return;

  len=strlen(*str);

  /* overwrite the memory */
  for (lup=0;lup<len;lup++)
    (*str)[lup]='X';

  utils->free(*str);

  *str=NULL;
}

static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  /* free sensetive info */
  free_string(utils,&(text->userid));
  free_string(utils,&(text->authid));
  free_secret(utils,&(text->password));

  utils->free(text);
}

static void mech_free(void *global_context, sasl_utils_t *utils)
{
  utils->free(global_context);  
}

#ifdef SASL_MINIMAL_SERVER

static int server_continue_step (void *conn_context,
	      sasl_server_params_t *params,
	      const char *clientin,
	      int clientinlen,
	      char **serverout,
	      int *serveroutlen,
	      sasl_out_params_t *oparams,
	      const char **errstr)
{
  return SASL_FAIL;
}

#else /* SASL_MINIMAL_SERVER */

/* fills in password  remember to free password and wipe it out correctly */
static int verify_password(sasl_server_params_t *sparams,
			   const char *userid,
			   const char *password)
{
  /*struct passwd *pwd;
  char *salt;
  char *crypted;

  pwd=getpwnam(userid);
  if (pwd==NULL) return SASL_NOUSER;

  salt = pwd->pw_passwd;

  crypted=(char *) crypt(password, salt);

  if (strcmp(crypted, pwd->pw_passwd)!=0)
    return SASL_BADAUTH;

    return SASL_OK;*/

  /* Let's check against the CRAM secret for now */

  int result;
  sasl_server_getsecret_t *getsecret;
  void *getsecret_context;
  sasl_secret_t *sec=NULL;

  /* get callback so we can request the secret */
  result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_GETSECRET,
					 &getsecret,
					 &getsecret_context);
    if (result != SASL_OK)
    {
      VL(("result = %i trying to get secret callback\n",result));
      return result;
    }

    if (! getsecret)
    {
      VL(("Received NULL getsecret callback\n"));
      return SASL_FAIL;
    }

    /* We use the user's SCRAM secret */
    /* Request secret */
    result = getsecret(getsecret_context, "CRAM-MD5", userid, &sec);
    if (result != SASL_OK)
    {
      VL(("error %i in getsecret\n",result));
      return result;
    }

    if (! sec)
    {
      VL(("Received NULL sec from getsecret\n"));
      return SASL_FAIL;
    }

    VL(("password=[%s]\n",sec->data));

    if (strncmp(sec->data,password,sec->len)!=0)
    {
      VL(("Passwords don't match\n"));
      return SASL_FAIL;
    }

    free_secret(sparams->utils, &sec);

    return SASL_OK;
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

  if (errstr)
    *errstr = NULL;

  oparams->mech_ssf=1;

  oparams->maxoutbuf=0; /* no clue what this should be */
  
  oparams->encode=NULL;
  oparams->decode=NULL;

  oparams->user=NULL;
  oparams->authid=NULL;

  oparams->realm=NULL;
  oparams->param_version=0;

  /*nothing more to do; authenticated */
  oparams->doneflag=1;

  if (text->state==1)
  {
    const char *author;
    const char *authen;
    const char *password;
    size_t password_len;
    int lup=0;
    char *mem;
    int result;

    /* should have received author-id NUL authen-id NUL password */

    VL (("in=%s len=%i\n",clientin,clientinlen));

    /* get author */
    author = clientin;
    while ((lup<clientinlen) && (clientin[lup]!=0))
      ++lup;

    if (lup==clientinlen) return -99; /*SASL_FAIL;      */

    /* get authen */
    ++lup;
    authen = clientin + lup;
    while ((lup<clientinlen) && (clientin[lup]!=0))
      ++lup;

    if (lup==clientinlen) return -98; /* SASL_FAIL;      */

    /* get password */
    lup++;
    password = clientin + lup;
    while ((lup<clientinlen) && (clientin[lup]!=0))
      ++lup;

    password_len=clientin + lup - password;

    if (lup != clientinlen)
      return -89; /*SASL_BADAUTH;*/

    /* verify password - return sasl_ok on success*/    
    result=verify_password(params,
			   authen,
			   password);
    if (result!=SASL_OK) return -97; /*result;*/

    /* verify authorization */
    if (author && strcmp(author, authen)) {
      sasl_authorize_t *authorize;
      void *context;
      const char *user;
      const char *errstr;
      if (params->utils->getcallback(params->utils->conn,
				     SASL_CB_PROXY_POLICY,
				     &authorize,
				     &context) != SASL_OK)
	return SASL_NOAUTHZ;
      result = authorize(context, authen, author, &user, &errstr);
      if (result != SASL_OK)
	return -96; /*result;*/
      if (user)
	author = user;
    }

    if (! author)
      author = authen;

    mem = params->utils->malloc(strlen(author) + 1);
    if (! mem) return SASL_NOMEM;
    strcpy(mem, author);
    oparams->user = mem;

    mem = params->utils->malloc(strlen(authen) + 1);
    if (! mem) return SASL_NOMEM;
    strcpy(mem, authen);
    oparams->authid = mem;

   

    if (params->transition)
    {
      VL(("Trying to transition\n"));
      /* xxx segfaulting
	 params->transition(params->utils->conn,
	 password, password_len); */
      VL(("Transitioned\n"));
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
#endif /* SASL_MINIMAL_SERVER */

static const sasl_server_plug_t plugins[] = 
{
  {
    "PLAIN",
    0,
    0,
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
  if (maxversion<PLAIN_VERSION)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=PLAIN_VERSION;

  return SASL_OK;
}

/* put in sasl_wrongmech */
static int c_start(void *glob_context __attribute__((unused)),
		   sasl_client_params_t *params,
		   void **conn)
{
  context_t *text;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;  
  text->userid = NULL;
  text->authid = NULL;
  text->password = NULL;
  *conn=text;

  return SASL_OK;
}

/* 
 * Trys to find the prompt with the lookingfor id in the prompt list
 * Returns it if found. NULL otherwise
 */

static sasl_interact_t *find_prompt(sasl_interact_t *promptlist,
				    unsigned int lookingfor)
{
  if (promptlist==NULL) return NULL;

  while (promptlist->id!=SASL_CB_LIST_END)
  {
    if (promptlist->id==lookingfor)
      return promptlist;

    promptlist+=sizeof(sasl_interact_t);
  }

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

  /* see if we were given the userid in the prompt */
  prompt=find_prompt(*prompt_need,SASL_CB_USER);
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
  switch (result)
    {
    case SASL_INTERACT:
      return SASL_INTERACT;
    case SASL_OK:
      if (! getuser_cb)
	return SASL_FAIL;
      result = getuser_cb(getuser_context,
			  SASL_CB_USER,
			  (const char **) userid,
			  NULL);
      if (result != SASL_OK)
	return result;

      break;
    default:
      /* sucess */
      break;
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

  /* see if we were given the authname in the prompt */
  prompt=find_prompt(*prompt_need,SASL_CB_AUTHNAME);
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
  switch (result)
    {
    case SASL_INTERACT:
      return SASL_INTERACT;
    case SASL_OK:
      if (! getauth_cb)
	return SASL_FAIL;
      result = getauth_cb(getauth_context,
			  SASL_CB_AUTHNAME,
			  (const char **)authid,
			  NULL);
      if (result != SASL_OK)
	return result;

      break;
    default:
      /* sucess */
      break;
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
  prompt=find_prompt(*prompt_need,SASL_CB_PASS);
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

  switch (result)
    {
    case SASL_INTERACT:      
      return SASL_INTERACT;
    case SASL_OK:
      if (! getpass_cb)
	return SASL_FAIL;
      result = getpass_cb(params->utils->conn,
			  getpass_context,
			  SASL_CB_PASS,
			  password);
      if (result != SASL_OK)
	return result;

      break;
    default:
      /* sucess */
      break;
    }

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

    ptr+=sizeof(sasl_interact_t);
  } while(ptr->id!=SASL_CB_LIST_END);

  params->utils->free(prompts);
  prompts=NULL;
}

/*
 * Make the necessary prompts
 */

static int make_prompts(sasl_client_params_t *params,
			sasl_interact_t **prompts_res,
			context_t *text,
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

  prompts=params->utils->malloc(sizeof(sasl_interact_t)*num);
  if ((prompts) ==NULL) return SASL_NOMEM;
  *prompts_res=prompts;

  if (user_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_USER;
    (prompts)->challenge="Userid";
    (prompts)->prompt="Please enter your userid";
    (prompts)->defresult=text->authid;

    prompts+=sizeof(sasl_interact_t);
  }

  if (auth_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_AUTHNAME;
    (prompts)->challenge="Authentication Name";
    (prompts)->prompt="Please enter your authentication name";
    (prompts)->defresult=text->userid;

    prompts+=sizeof(sasl_interact_t);
  }


  if (pass_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_PASS;
    (prompts)->challenge="Password";
    (prompts)->prompt="Please enter your password";
    (prompts)->defresult=NULL;

    prompts+=sizeof(sasl_interact_t);
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

  VL(("Plain step #%i\n",text->state));

  /* doesn't really matter how the server responds */

  if (text->state==1)
  {
    int user_result=SASL_OK;
    int auth_result=SASL_OK;
    int pass_result=SASL_OK;


    /* check if sec layer strong enough */
    if (params->props.min_ssf>0)
      return SASL_TOOWEAK;


    /* try to get the userid */
    if (text->userid==NULL)
    {
      VL (("Trying to get userid\n"));
      user_result=get_userid(params,
			&text->userid,
			prompt_need);

      if ((user_result!=SASL_OK) && (user_result!=SASL_INTERACT))
	return user_result;

    }

    /* try to get the authid */    
    if (text->authid==NULL)
    {
      VL (("Trying to get authid\n"));
      auth_result=get_authid(params,
			&text->authid,
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
    free_prompts(params,*prompt_need);

    /* if there are prompts not filled in */
    if ((user_result==SASL_INTERACT) || (auth_result==SASL_INTERACT) ||
	(pass_result==SASL_INTERACT))
    {
      /* make the prompt list */
      result=make_prompts(params,prompt_need, text, 
			  user_result, auth_result, pass_result);
      if (result!=SASL_OK) return result;
      
      VL(("returning prompt(s)\n"));
      return SASL_INTERACT;
    }
    

    /* Ok I think we got everything now... */
    VL (("Got username, authid, and password\n"));

    /* send authorized id NUL authentication id NUL password */
    {
      size_t userid_len, authid_len;

      /* xxx not sure why this is here? Server doesn't support it
       if (strcmp(text->userid, text->authid)==0)
	userid_len = strlen(text->userid);
      else
      userid_len = 0;*/

      userid_len = strlen(text->userid);
      authid_len = strlen(text->authid);

      *clientoutlen = (userid_len + 1
		       + authid_len + 1
		       + text->password->len);
      *clientout=params->utils->malloc(*clientoutlen);
      if (! *clientout) return SASL_NOMEM;
      memset(*clientout, 0, *clientoutlen);

      VL(("userid=[%s]\n",text->userid));
      VL(("authid=[%s]\n",text->authid));
      VL(("password=[%s]\n",text->password->data));

      memcpy(*clientout, text->userid, userid_len);
      memcpy(*clientout+userid_len+1, text->authid, authid_len);
      memcpy(*clientout+userid_len+authid_len+2,
	     text->password->data,
	     text->password->len);
    }

    /* set oparams */
    oparams->mech_ssf=1;
    oparams->maxoutbuf=0;
    oparams->encode=NULL;
    oparams->decode=NULL;
    oparams->user=text->userid;
    text->userid = NULL;
    oparams->authid=text->authid;
    text->authid = NULL;
    oparams->realm=NULL;
    oparams->param_version=0;

    text->state=99; /* so fail next time */

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const long client_required_prompts[] = {
  SASL_CB_USER,
  SASL_CB_AUTHNAME,
  SASL_CB_PASS,
  SASL_CB_LIST_END
};

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "PLAIN",
    0,
    0,
    client_required_prompts,
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
  if (maxversion<PLAIN_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=PLAIN_VERSION;

  return SASL_OK;
}
