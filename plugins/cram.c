/* CRAM-MD5 SASL plugin
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

#include <config.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sasl.h>
#include <saslplug.h>
#include <saslutil.h>

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslCRAM.h"
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define CRAM_MD5_VERSION (3)

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

typedef struct context {

  int state;    /* holds state are in */
  char *msgid;  /* timestamp used for md5 transforms */
  int msgidlen;

  int secretlen;

  char *authid;
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

  text= sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;
  text->msgid = NULL;
  text->authid = NULL;
  text->password = NULL;
  *conn=text;

  return SASL_OK;
}


static void free_secret(sasl_utils_t *utils,
			sasl_secret_t **secret)
{
  VL(("Freeing secret\n"));

  if (secret==NULL) return;
  if (*secret==NULL) return;

  /* overwrite the memory */
  memset(&(*secret)->data, 0, (*secret)->len);

  utils->free(*secret);

  *secret=NULL;
}

static void free_string(sasl_utils_t *utils,
			char **str)
{
  char *s;
  VL(("Freeing string\n"));

  if (str==NULL) return;
  if (*str==NULL) return;

  /* overwrite the memory */
  for (s = *str; *s; s++)
    *s = 'X';
  
  utils->free(*str);

  *str=NULL;
}

static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (!text)
    return;

  /* get rid of all sensetive info */
  free_string(utils,&(text->msgid));
  free_string(utils,&(text->authid));
  free_secret(utils,&(text->password));

  utils->free(text);
}

static void mech_free(void *global_context, sasl_utils_t *utils)
{

  utils->free(global_context);  
}

static int server_continue_step (void *conn_context,
				 sasl_server_params_t *sparams,
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

  if (text->state==1)
  {    
    unsigned len;

    VL(("CRAM-MD5 step 1\n"));

    *serveroutlen = 0;
    len = 128;			/* I happen to know that 128 is
				 * likely to work on the first try...  */
    *serverout = sparams->utils->malloc(len);
    if (! *serverout)
      return SASL_NOMEM;
    
    do {
      *serveroutlen = sparams->utils->mkchal(sparams->utils->conn,
					     *serverout,
					     len,
					     1);
      if (! *serveroutlen) {
	len *= 2;
	*serverout = sparams->utils->realloc(*serverout, len);
	if (! *serverout)
	  return SASL_NOMEM;
      }
    } while (! *serveroutlen);

    text->msgidlen=*serveroutlen;

    /* save nonce so we can check against it later */
    text->msgid=sparams->utils->malloc(*serveroutlen + 1);
    if (text->msgid==NULL) return SASL_NOMEM;
    strcpy(text->msgid, *serverout);

    VL(("nonce=[%s]\n",text->msgid));

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    /* verify digest */
    const char *client_secret = NULL;
    const char *s;
    sasl_secret_t *sec=NULL;
    int result;
    sasl_server_getsecret_t *getsecret;
    void *getsecret_context;
    HMAC_MD5_CTX ctx;
    UINT4 digest[4];
    char digest_str[33];

    VL(("CRAM-MD5 Step 2\n"));
    VL(("Clientin: %s\n",clientin));

    /* extract userid; everything before last space*/
    s = clientin;
    while (s - clientin < clientinlen
	   && *s != ' ')
      s++;
    if (clientinlen <= s - clientin)
      return SASL_BADPROT;

    /* s now points to the space after the userid.
     * s - clientin == number of chars in the userid */
    oparams->authid = sparams->utils->malloc(s - clientin + 1);
    if (! oparams->authid)
      return SASL_NOMEM;
    strncpy(oparams->authid, clientin, s - clientin);
    oparams->authid[s - clientin] = '\0';
    
    client_secret = s + 1;
    if (clientinlen - (client_secret - clientin) != 32) {
      VL(("Received incorrectly sized secret from client\n"));
      return SASL_BADPROT;
    }
    
    /* get callback so we can request the secret */
    result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_GETSECRET,
					 &getsecret,
					 &getsecret_context);
    if (result != SASL_OK)
    {
      VL(("result = %i trying to find getsecret callback\n",result));
      return result;
    }
    if (! getsecret)
    {
      VL(("Unable to find getsecret callback\n"));
      return SASL_FAIL;
    }

    /* Request secret */
    result = getsecret(getsecret_context, "CRAM-MD5", oparams->authid, &sec);
    if (result != SASL_OK)
    {
      VL(("userid=%s\n",oparams->authid));
      VL(("error %i in getsecret\n",result));
      return result;
    }

    if (! sec)
    {
      VL(("Unable to obtain user's secret\n"));
      return SASL_FAIL;
    }

    if (sec->len != sizeof(HMAC_MD5_STATE)) {
      VL(("User's secret is not the right size\n"));
      free_secret(sparams->utils, &sec);
      return SASL_FAIL;
    }

    /* load md5 context to check */
    sparams->utils->hmac_md5_import(&ctx,
				    (HMAC_MD5_STATE *) &sec->data);
    free_secret(sparams->utils, &sec);

    sparams->utils->MD5Update(&ctx.ictx,
			      (const unsigned char *)text->msgid,
			      text->msgidlen);

    sparams->utils->hmac_md5_final((unsigned char *)&digest, &ctx);
    memset(&ctx, 0, sizeof(ctx));
    sprintf(digest_str, "%08lx%08lx%08lx%08lx",
	    digest[0], digest[1], digest[2], digest[3]);
    memset(&digest, 0, sizeof(digest));

    VL(("Server digest: %s\n", digest_str));

    /* and do the check */
    if (memcmp(digest_str, client_secret, 32)) {
      VL(("Auth check failed\n"));
      memset(digest_str, 0, sizeof(digest_str));
      return SASL_BADAUTH;
    }
    memset(digest_str, 0, sizeof(digest_str));

    /* nothing more to do; authenticated 
     * set oparams information
     */
    oparams->doneflag=1;

    oparams->user=sparams->utils->malloc(strlen(oparams->authid) + 1);
    if (! oparams->user)
      return SASL_NOMEM;
    strcpy(oparams->user, oparams->authid);

    oparams->mech_ssf=0;

    oparams->maxoutbuf=1024; /* no clue what this should be */
  
    oparams->encode=NULL;
    oparams->decode=NULL;

    oparams->realm=sparams->utils->malloc(strlen(sparams->local_domain) + 1);
    if (! oparams->realm)
      return SASL_NOMEM;
    strcpy(oparams->realm, sparams->local_domain);

    oparams->param_version=0;

    *serverout = NULL;
    *serveroutlen = 0;

    text->state=3; /* if called again will fail */

    return SASL_OK;
  }


  return SASL_FAIL; /* should never get here */
}

static int
setpass(void *glob_context __attribute__((unused)),
	sasl_server_params_t *sparams,
	const char *user,
	const char *pass,
	unsigned passlen,
	int flags __attribute__((unused)),
	const char **errstr)
{
  int result;
  sasl_server_putsecret_t *putsecret;
  void *putsecret_context;
  char buf[sizeof(sasl_secret_t) + sizeof(HMAC_MD5_STATE)];
  sasl_secret_t *secret = (sasl_secret_t *)&buf;

  if (!sparams
      || !sparams->utils
      || !sparams->utils->conn
      || !sparams->utils->getcallback
      || !sparams->utils->hmac_md5_precalc
      || !user
      || !pass)
    return SASL_BADPARAM;

  if (errstr)
    *errstr = NULL;

  result = sparams->utils->getcallback(sparams->utils->conn,
				       SASL_CB_SERVER_PUTSECRET,
				       &putsecret,
				       &putsecret_context);
  if (result != SASL_OK)
    return result;

  sparams->utils->hmac_md5_precalc((HMAC_MD5_STATE *)&secret->data,
				   (const unsigned char *)pass,
				   passlen);
  
  secret->len = sizeof(HMAC_MD5_STATE);

  result=putsecret(putsecret_context,
		   "CRAM-MD5",
		   user,
		   secret);

  memset(buf, 0, sizeof(buf));

  return result;
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "CRAM-MD5",
    0,
    0,
    NULL,
    &start,
    &server_continue_step,
    &dispose,
    &mech_free,
    &setpass,
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
  if (maxversion<CRAM_MD5_VERSION)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=CRAM_MD5_VERSION;

  return SASL_OK;
}

/* put in sasl_wrongmech */
static int c_start(void *glob_context __attribute__((unused)), 
		 sasl_client_params_t *params,
		 void **conn)
{
  context_t *text;

/* should be no client data
   if there is then ignore it i guess */

  /* holds state are in */
  text= params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  memset(text, 0, sizeof(context_t));
  text->state=1;  
  text->authid=NULL;
  text->password=NULL;
  text->msgid = NULL;

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

  if (result == SASL_OK && getpass_cb) {
    result = getpass_cb(params->utils->conn,
			getpass_context,
			SASL_CB_PASS,
			password);
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
			int auth_res,
			int pass_res)
{
  int num=1;
  sasl_interact_t *prompts;

  if (auth_res==SASL_INTERACT) num++;
  if (pass_res==SASL_INTERACT) num++;

  if (num==1) return SASL_FAIL;

  prompts=params->utils->malloc(sizeof(sasl_interact_t)*num);
  if ((prompts) ==NULL) return SASL_NOMEM;
  *prompts_res=prompts;

  if (auth_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_AUTHNAME;
    (prompts)->challenge="Authorization Name";
    (prompts)->prompt="Please enter your authorization name";
    (prompts)->defresult=NULL;

    VL(("authid callback added\n"));
    prompts++;
  }

  if (pass_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_PASS;
    (prompts)->challenge="Password";
    (prompts)->prompt="Please enter your password";
    (prompts)->defresult=NULL;

    VL(("password callback added\n"));
    prompts++;
  }


  /* add the ending one */
  (prompts)->id=SASL_CB_LIST_END;
  (prompts)->challenge=NULL;
  (prompts)->prompt   =NULL;
  (prompts)->defresult=NULL;

  return SASL_OK;
}

static int c_continue_step (void *conn_context,
	      sasl_client_params_t *params,
	      const char *serverin,
	      int serverinlen,
	      sasl_interact_t **prompt_need,
	      char **clientout,
	      int *clientoutlen,
	      sasl_out_params_t *oparams)
{
  context_t *text;
  text=conn_context;

  oparams->mech_ssf=0;
  oparams->maxoutbuf=1024; /* no clue what this should be */
  oparams->encode=NULL;
  oparams->decode=NULL;
  oparams->user=NULL; /* set username */
  oparams->authid=NULL;
  oparams->realm=NULL;
  oparams->param_version=0;

  /* doesn't really matter how the server responds */

  if (text->state==1)
  {     
    sasl_security_properties_t secprops;
    int external;

    text->msgid=params->utils->malloc(1);
    if (text->msgid==NULL) return SASL_NOMEM;
    text->msgid[0] = '\0';
    text->msgidlen=0;
    *clientout=NULL;
    *clientoutlen=0;

    /* check if sec layer strong enough */
    secprops=params->props;
    external=params->external_ssf;

    if (secprops.min_ssf>0)
      return SASL_TOOWEAK;

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    int auth_result=SASL_OK;
    int pass_result=SASL_OK;
    UINT4 digest[4];

    /* try to get the userid */
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
    if (prompt_need)
      free_prompts(params,*prompt_need);

    /* if there are prompts not filled in */
    if ((auth_result==SASL_INTERACT) ||
	(pass_result==SASL_INTERACT))
    {
      /* make the prompt list */
      int result=make_prompts(params,prompt_need,
			      auth_result, pass_result);
      if (result!=SASL_OK) return result;
      
      VL(("returning prompt(s)\n"));
      return SASL_INTERACT;
    }

    /* username
     * space
     * digest (keyed md5 where key is passwd)
     */

    /* make nonce */
    params->utils->hmac_md5((unsigned char *) serverin, serverinlen,
			    (unsigned char *) text->password->data,
			    text->password->len,
			    (unsigned char *)&digest);

    *clientout=params->utils->malloc(strlen(text->authid) + 34);
    if ((*clientout) == NULL) return SASL_NOMEM;

    sprintf(*clientout,
	    "%s %08lx%08lx%08lx%08lx",
	    text->authid,
	    digest[0], digest[1], digest[2], digest[3]);
    
    *clientoutlen=strlen(*clientout);

    /*nothing more to do; authenticated */
    oparams->doneflag=1;

    oparams->user = params->utils->malloc(strlen(text->authid) + 1);
    if (! oparams->user)
      return SASL_NOMEM;
    strcpy(oparams->user, text->authid);

    oparams->authid = params->utils->malloc(strlen(text->authid) + 1);
    if (! oparams->authid)
      return SASL_NOMEM;
    strcpy(oparams->authid, text->authid);

    VL(("clientout looks like=%s %i\n",*clientout,*clientoutlen));

    text->state++; /* fail if called again */

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "CRAM-MD5",
    0,
    0,
    NULL,
    NULL,
    &c_start,
    &c_continue_step,
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
  if (maxversion<CRAM_MD5_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;
  *plugcount=1;
  *out_version=CRAM_MD5_VERSION;

  return SASL_OK;
}
