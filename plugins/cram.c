/* CRAM-MD5 SASL plugin
 * Rob Siemborski
 * Tim Martin 
 * $Id: cram.c,v 1.65 2002/04/18 18:19:30 rjs3 Exp $
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <config.h>
#include <time.h>
#ifndef macintosh
#include <sys/stat.h>
#endif
#include <fcntl.h>

#include <sasl.h>
#include <saslplug.h>
#include <saslutil.h>

#include "plugin_common.h"

#ifdef macintosh
#include <sasl_cram_plugin_decl.h>
#endif

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslCRAM.h"
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (1)
#endif

typedef struct context {

    int state;    /* holds state are in */
    char *msgid;  /* timestamp used for md5 transforms */
    int msgidlen;

    int secretlen;

    char *authid;
    sasl_secret_t *password;

    char *out_buf;
    unsigned out_buf_len;

} context_t;

static int crammd5_server_mech_new(void *glob_context __attribute__((unused)),
				   sasl_server_params_t *sparams,
				   const char *challenge __attribute__((unused)),
				   unsigned challen __attribute__((unused)),
				   void **conn)
{
  context_t *text;

  text= sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) {
      MEMERROR( sparams->utils );
      return SASL_NOMEM;
  }

  memset(text, 0, sizeof(context_t));

  text->state=1;

  *conn=text;

  return SASL_OK;
}

static void crammd5_both_mech_dispose(void *conn_context,
				      const sasl_utils_t *utils)
{
  context_t *text=(context_t *)conn_context;

  if(!text) return;

  if(text->out_buf) utils->free(text->out_buf);

  /* get rid of all sensetive info */
  _plug_free_string(utils,&(text->msgid));
  _plug_free_string(utils,&(text->authid));
  _plug_free_secret(utils,&(text->password));

  utils->free(text);
}

static void crammd5_both_mech_free(void *global_context,
				   const sasl_utils_t *utils)
{
    if(global_context) utils->free(global_context);  
}

static char * randomdigits(sasl_server_params_t *sparams)
{
  unsigned int num;
  char *ret;
  unsigned char temp[5]; /* random 32-bit number */

  sparams->utils->rand(sparams->utils->rpool,(char *) temp,4);
  num=(temp[0] * 256 * 256 * 256) +
      (temp[1] * 256 * 256) +
      (temp[2] * 256) +
      (temp[3] );

  ret = sparams->utils->malloc(15); /* there's no way an unsigned can be longer than this right? */
  if (ret == NULL) return NULL;
  sprintf(ret, "%u", num);

  return ret;
}

/* returns the realm we should pretend to be in */
static int parseuser(const sasl_utils_t *utils,
		     char **user, char **realm, const char *user_realm, 
		     const char *serverFQDN, const char *input)
{
    int ret;
    char *r;

    if(!user || !realm || !serverFQDN || !input) {
	PARAMERROR( utils );
	return SASL_BADPARAM;
    }

    if (!user_realm) {
	ret = _plug_strdup(utils, serverFQDN, realm, NULL);
	if (ret == SASL_OK) {
	    ret = _plug_strdup(utils, input, user, NULL);
	}
    } else if (user_realm[0]) {
	ret = _plug_strdup(utils, user_realm, realm, NULL);
	if (ret == SASL_OK) {
	    ret = _plug_strdup(utils, input, user, NULL);
	}
    } else {
	/* otherwise, we gotta get it from the user */
	r = strchr(input, '@');
	if (!r) {
	    /* hmmm, the user didn't specify a realm */
	    /* we'll default to the serverFQDN */
	    ret = _plug_strdup(utils, serverFQDN, realm, NULL);
	    if (ret == SASL_OK) {
		ret = _plug_strdup(utils, input, user, NULL);
	    }
	} else {
	    int i;

	    r++;
	    ret = _plug_strdup(utils, r, realm, NULL);
	    *user = utils->malloc(r - input + 1);
	    if (*user) {
		for (i = 0; input[i] != '@'; i++) {
		    (*user)[i] = input[i];
		}
		(*user)[i] = '\0';
	    } else {
		MEMERROR( utils );
		ret = SASL_NOMEM;
	    }
	}
    }

    return ret;
}

/*
 * Returns the current time (or part of it) in string form
 *  maximum length=15
 */
static char *gettime(sasl_server_params_t *sparams)
{
  char *ret;
  time_t t;

  t=time(NULL);
  ret= sparams->utils->malloc(15);
  if (ret==NULL) return NULL;
  
  /* the bottom bits are really the only random ones so if
     we overflow we don't want to loose them */
  snprintf(ret,15,"%lu",t%(0xFFFFFF));
  
  return ret;
}

/* convert a string of 8bit chars to it's representation in hex
 * using lowercase letters
 */
static char *convert16(unsigned char *in, int inlen, const sasl_utils_t *utils)
{
  static char hex[]="0123456789abcdef";
  int lup;
  char *out;
  out=utils->malloc(inlen*2+1);
  if (out==NULL) return NULL;

  for (lup=0;lup<inlen;lup++)
  {
    out[lup*2]=  hex[  in[lup] >> 4 ];
    out[lup*2+1]=hex[  in[lup] & 15 ];
  }
  out[lup*2]=0;
  return out;
}

static char *make_hashed(sasl_secret_t *sec, char *nonce, int noncelen, 
			 const sasl_utils_t *utils)
{
  char secret[65];
  unsigned char digest[24];  
  int lup;
  char *in16;

  if (sec==NULL) return NULL;

  if (sec->len<64)
  {
    memcpy(secret, sec->data, sec->len);

    /* fill in rest with 0's */
    for (lup= sec->len ;lup<64;lup++)
      secret[lup]='\0';

  } else {
    memcpy(secret, sec->data, 64);
  }

  /* do the hmac md5 hash output 128 bits */
  utils->hmac_md5((unsigned char *) nonce,noncelen,
		  (unsigned char *) secret,64,digest);

  /* convert that to hex form */
  in16=convert16(digest,16,utils);
  if (in16==NULL) return NULL;

  return in16;
}


static int crammd5_server_mech_step (void *conn_context,
				     sasl_server_params_t *sparams,
				     const char *clientin,
				     unsigned clientinlen,
				     const char **serverout,
				     unsigned *serveroutlen,
				     sasl_out_params_t *oparams)
{
  context_t *text;
  text=conn_context;

  /* this should be well more than is ever needed */
  if (clientinlen > 1024) {
	SETERROR(sparams->utils, "CRAM-MD5 input longer than 1024 bytes");
	return SASL_BADPROT;
  }

  if (text->state==1)
  {    
    char *time, *randdigits;
    int result;
    
    /* we shouldn't have received anything */
    if (clientinlen!=0)
    {
	SETERROR(sparams->utils, "CRAM-MD5 does not accpet inital data");
	return SASL_BADPROT;
    }

    /* get time and a random number for the nonce */
    time=gettime(sparams);
    randdigits=randomdigits(sparams);
    if ((time==NULL) || (randdigits==NULL)) {
	MEMERROR( sparams->utils );
	return SASL_NOMEM;
    }

    /* allocate some space for the nonce */
    result = _plug_buf_alloc(sparams->utils, &(text->out_buf),
			     &(text->out_buf_len), 200+1);
    if(result != SASL_OK) return result;

    /* create the nonce */
    snprintf(text->out_buf,200,"<%s.%s@%s>",randdigits,time,
	    sparams->serverFQDN);

    *serverout = text->out_buf;
    *serveroutlen=strlen(*serverout);
    
    /* free stuff */
    sparams->utils->free(time);    
    sparams->utils->free(randdigits);    
    
    text->msgidlen=*serveroutlen;

    /* save nonce so we can check against it later */
    text->msgid=sparams->utils->malloc((*serveroutlen)+1);
    if (text->msgid==NULL) {
	MEMERROR(sparams->utils);
	return SASL_NOMEM;
    }
    
    memcpy(text->msgid,*serverout,*serveroutlen);
    text->msgid[ *serveroutlen ] ='\0';

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    /* verify digest */
    char *userid = NULL;
    char *realm = NULL;
    char *authstr = NULL;
    sasl_secret_t *sec = NULL;
    int lup,pos,len;
    int result = SASL_FAIL;
    const char *password_request[] = { SASL_AUX_PASSWORD,
				       "*cmusaslsecretCRAM-MD5",
				       NULL };
    struct propval auxprop_values[3];
    HMAC_MD5_CTX tmphmac;
    HMAC_MD5_STATE md5state;
    int clear_md5state = 0;
    char *digest_str = NULL;
    UINT4 digest[4];

    /* extract userid; everything before last space*/
    pos=clientinlen-1;
    while ((pos>0) && (clientin[pos]!=' ')) {
	pos--;
    }
    if (pos<=0) {
        SETERROR( sparams->utils,"need authentication name");
	return SASL_BADPROT;
    }

    authstr=(char *) sparams->utils->malloc(pos+1);
    if (authstr == NULL) {
	MEMERROR( sparams->utils);
	return SASL_NOMEM;
    }
    
    /* copy authstr out */
    for (lup = 0; lup < pos; lup++) {
	authstr[lup] = clientin[lup];
    }
    authstr[lup] = '\0';

    result = parseuser(sparams->utils, &userid, &realm, sparams->user_realm,
	      sparams->serverFQDN, authstr);
    sparams->utils->free(authstr);
    if (result != SASL_OK) goto done;

    result = sparams->utils->prop_request(sparams->propctx, password_request);
    if (result != SASL_OK) goto done;

    /* this will trigger the getting of the aux properties */
    result = sparams->canon_user(sparams->utils->conn,
				 userid, 0, SASL_CU_AUTHID | SASL_CU_AUTHZID,
				 oparams);
    if(result != SASL_OK) goto done;

    result = sparams->utils->prop_getnames(sparams->propctx, password_request,
					   auxprop_values);
    if(result < 0 ||
       ((!auxprop_values[0].name || !auxprop_values[0].values) &&
	(!auxprop_values[1].name || !auxprop_values[1].values))) {
	/* We didn't find this username */
	sparams->utils->seterror(sparams->utils->conn,0,
				 "no secret in database");
	result = SASL_NOUSER;
	goto done;
    }

    if(auxprop_values[0].name && auxprop_values[0].values) {
	len = strlen(auxprop_values[0].values[0]);
	if (len == 0) {
	    sparams->utils->seterror(sparams->utils->conn,0,
				     "empty secret");
	    result = SASL_FAIL;
	    goto done;
	}
	
	sec = sparams->utils->malloc(sizeof(sasl_secret_t) + len);
	if(!sec) goto done;
	
	sec->len = len;
	strncpy(sec->data, auxprop_values[0].values[0], len + 1);   

	clear_md5state = 1;
	/* Do precalculation on plaintext secret */
	sparams->utils->hmac_md5_precalc(&md5state, /* OUT */
					 sec->data,
					 sec->len);
    } else if (auxprop_values[1].name && auxprop_values[1].values) {
	/* We have a precomputed secret */
	memcpy(&md5state, auxprop_values[1].values[0], sizeof(HMAC_MD5_STATE));
    } else {
	sparams->utils->seterror(sparams->utils->conn, 0,
				 "Have neither type of secret");
	return SASL_FAIL;
    }    
    
    /* ok this is annoying:
       so we have this half-way hmac transform instead of the plaintext
       that means we half to:
       -import it back into a md5 context
       -do an md5update with the nonce 
       -finalize it
    */
    sparams->utils->hmac_md5_import(&tmphmac, (HMAC_MD5_STATE *) &md5state);
    sparams->utils->MD5Update(&(tmphmac.ictx),
			      (const unsigned char *)text->msgid,
			      text->msgidlen);
    sparams->utils->hmac_md5_final((unsigned char *)&digest, &tmphmac);

    /* convert to base 16 with lower case letters */
    digest_str = convert16((unsigned char *) digest, 4, sparams->utils);

    /* if same then verified 
     *  - we know digest_str is null terminated but clientin might not be
     */
    if (strncmp(digest_str,clientin+pos+1,strlen(digest_str))!=0) {
	sparams->utils->seterror(sparams->utils->conn, 0,
				 "incorrect digest response");
	result = SASL_BADAUTH;
	goto done;
    }

    /* nothing more to do; authenticated 
     * set oparams information (canon_user was called before) 
     */
    oparams->doneflag=1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;

    *serverout = NULL;
    *serveroutlen = 0;

    result = SASL_OK;
  done:

    if (userid) sparams->utils->free(userid);
    if (realm)  sparams->utils->free(realm);
    if (sec) {
	memset(sec->data, 0, sec->len);
	sparams->utils->free(sec);
    }
    if (digest_str)  sparams->utils->free(digest_str);
    if (clear_md5state) memset(&md5state, 0, sizeof(md5state));
    
    text->state = 3; /* if called again will fail */

    return result;
  }

  SETERROR( sparams->utils, "Reached unreachable point in CRAM plugin");
  return SASL_FAIL; /* should never get here */
}

static sasl_server_plug_t crammd5_server_plugins[] = 
{
  {
    "CRAM-MD5",
    0,
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
    SASL_FEAT_SERVER_FIRST,
    NULL,
    &crammd5_server_mech_new,
    &crammd5_server_mech_step,
    &crammd5_both_mech_dispose,
    &crammd5_both_mech_free,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
  }
};

int crammd5_server_plug_init(const sasl_utils_t *utils,
				 int maxversion,
				 int *out_version,
				 sasl_server_plug_t **pluglist,
				 int *plugcount)
{
    if (maxversion<SASL_SERVER_PLUG_VERSION) {
	SETERROR( utils, "CRAM version mismatch");
	return SASL_BADVERS;
    }

    /* make sure there is a cram entry */
    
    *pluglist=crammd5_server_plugins;

    *plugcount=1;  
    *out_version=SASL_SERVER_PLUG_VERSION;
    
    return SASL_OK;
}

static int crammd5_client_mech_new(void *glob_context __attribute__((unused)), 
				   sasl_client_params_t *params,
				   void **conn)
{
    context_t *text;

    /* holds state are in */
    text= params->utils->malloc(sizeof(context_t));
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

static sasl_interact_t *find_prompt(sasl_interact_t *promptlist,
				    unsigned int lookingfor)
{
  if (promptlist==NULL) return NULL;

  while (promptlist->id!=SASL_CB_LIST_END)
  {
    if (promptlist->id==lookingfor)
      return promptlist;

    promptlist++;
  }

  return NULL;
}

static int get_authid(sasl_client_params_t *params,
		      char **authid,
		      sasl_interact_t **prompt_need)
{

  int result;
  sasl_getsimple_t *getauth_cb;
  void *getauth_context;
  sasl_interact_t *prompt = NULL;
  const char *ptr;

  /* see if we were given the authname in the prompt */
  if (prompt_need) prompt = find_prompt(*prompt_need,SASL_CB_AUTHNAME);
  if (prompt!=NULL)
  {
    /* copy it */
    *authid=params->utils->malloc(prompt->len+1);
    if ((*authid)==NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    strncpy(*authid, prompt->result, prompt->len+1);
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
	if (! getauth_cb){
	    SETERROR(params->utils, "no getauth_cb in CRAM plugin");
	    return SASL_FAIL;
	}
	
	result = getauth_cb(getauth_context,
			    SASL_CB_AUTHNAME,
			    (const char **)&ptr,
			    NULL);
	if (result != SASL_OK)
	    return result;

	*authid=params->utils->malloc(strlen(ptr)+1);
	if ((*authid)==NULL) {
	    MEMERROR( params->utils );
	    return SASL_NOMEM;
	}
	
	strcpy(*authid, ptr);
	break;

    default:
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
  sasl_interact_t *prompt = NULL;

  /* see if we were given the password in the prompt */
  if (prompt_need) prompt=find_prompt(*prompt_need,SASL_CB_PASS);
  if (prompt!=NULL)
  {
    /* We prompted, and got.*/
	
      if (! prompt->result) {
	  SETERROR(params->utils, "no prompt->result in CRAM plugin");
	  return SASL_FAIL;
      }

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
	if (! getpass_cb) {
	    SETERROR(params->utils, "No getpass_cb in CRAM plugin");
	    return SASL_FAIL;
	}
	
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

/*
 * Make the necessary prompts
 */
static int make_prompts(sasl_client_params_t *params,
			sasl_interact_t **prompts_res,
			int auth_res,
			int pass_res)
{
  int num=1;
  int alloc_size;
  sasl_interact_t *prompts;

  if (auth_res==SASL_INTERACT) num++;
  if (pass_res==SASL_INTERACT) num++;

  if (num==1) {
      SETERROR(params->utils, "no prompts to make in CRAM make_prompts");
      return SASL_FAIL;
  }

  alloc_size = sizeof(sasl_interact_t)*num;
  prompts=params->utils->malloc(alloc_size);
  if (!prompts) {
      MEMERROR( params->utils );
      return SASL_NOMEM;
  }
  memset(prompts, 0, alloc_size);
   
  
  *prompts_res=prompts;

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

static int crammd5_client_mech_step(void *conn_context,
				    sasl_client_params_t *params,
				    const char *serverin,
				    unsigned serverinlen,
				    sasl_interact_t **prompt_need,
				    const char **clientout,
				    unsigned *clientoutlen,
				    sasl_out_params_t *oparams)
{
  context_t *text;
  text=conn_context;

  /* doesn't really matter how the server responds */
  if (text->state == 1)
  {     
    sasl_security_properties_t secprops;
    unsigned int external;
    char *in16;
    int result;
    int auth_result=SASL_OK;
    int pass_result=SASL_OK;
    int maxsize;

    *clientout=NULL;
    *clientoutlen=0;

    /* check if sec layer strong enough */
    secprops=params->props;
    external=params->external_ssf;

    if (secprops.min_ssf>0+external) {
	SETERROR( params->utils,
		  "whoops! looks like someone wanted SSF out of the CRAM plugin");
	return SASL_TOOWEAK;
    }

    /* try to get the userid */
    if (text->authid==NULL)
    {
      auth_result=get_authid(params,
			     &text->authid,
			     prompt_need);

      if ((auth_result!=SASL_OK) && (auth_result!=SASL_INTERACT))
	return auth_result;
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
    if (prompt_need && *prompt_need) params->utils->free(*prompt_need);

    /* if there are prompts not filled in */
    if ((auth_result==SASL_INTERACT) ||
	(pass_result==SASL_INTERACT))
    {
      /* make the prompt list */
      int result=make_prompts(params,prompt_need,
			      auth_result, pass_result);
      if (result!=SASL_OK) return result;
      
      return SASL_INTERACT;
    }

    /* username
     * space
     * digest (keyed md5 where key is passwd)
     */

    /* First check for absurd lengths */
    if(serverinlen > 1024) {
	params->utils->seterror(params->utils->conn, 0,
				"CRAM-MD5 input longer than 1024 bytes");
	return SASL_BADPROT;
    }

    in16=make_hashed(text->password,(char *) serverin, serverinlen,
		     params->utils);

    if (in16==NULL) {
	SETERROR(params->utils, "whoops, make_hashed failed us this time");
	return SASL_FAIL;
    }

    maxsize=32+1+strlen(text->authid)+30;
    result = _plug_buf_alloc(params->utils, &(text->out_buf),
			     &(text->out_buf_len), maxsize);
    if(result != SASL_OK) return result;

    snprintf(text->out_buf, maxsize, "%s %s", text->authid, in16);

    /* get rid of private information */
    _plug_free_string(params->utils, &in16);

    *clientout = text->out_buf;
    *clientoutlen = strlen(*clientout);

    /*nothing more to do; authenticated */
    oparams->doneflag=1;

    /* Canonicalize the username */
    result = params->canon_user(params->utils->conn, text->authid, 0,
				SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if(result != SASL_OK) return result;

    text->state++; /* fail if called again */

    oparams->mech_ssf=0;
    oparams->maxoutbuf=0;
    oparams->encode=NULL;
    oparams->decode=NULL;
    oparams->param_version=0;

    return SASL_OK;
  }

  SETERROR(params->utils, "CRAM-MD5 says: \"WERT\"");
  return SASL_FAIL; /* should never get here */
}

static sasl_client_plug_t crammd5_client_plugins[] = 
{
  {
    "CRAM-MD5",
    0,
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
    SASL_FEAT_SERVER_FIRST,
    NULL,
    NULL,
    &crammd5_client_mech_new,
    &crammd5_client_mech_step,
    &crammd5_both_mech_dispose,
    &crammd5_both_mech_free,
    NULL,
    NULL,
    NULL
  }
};

int crammd5_client_plug_init(const sasl_utils_t *utils,
				 int maxversion,
				 int *out_version,
				 sasl_client_plug_t **pluglist,
				 int *plugcount)
{
    if (maxversion<SASL_CLIENT_PLUG_VERSION) {
	SETERROR( utils, "CRAM version mismatch");
	return SASL_BADVERS;
    }

    *pluglist=crammd5_client_plugins;
    *plugcount=1;
    *out_version=SASL_CLIENT_PLUG_VERSION;

    return SASL_OK;
}
