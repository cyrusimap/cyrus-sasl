/* OTP SASL plugin
 * Ken Murchison
 * $Id: otp.c,v 1.13 2002/04/25 14:26:09 ken3 Exp $
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
#include <ctype.h>
#include <time.h>
#include <assert.h>

#include <openssl/evp.h>

#include <sasl.h>
#if OPENSSL_VERSION_NUMBER < 0x00907000L
#define MD5_H  /* suppress internal MD5 */
#endif
#include <saslplug.h>

#include "plugin_common.h"
#include "../sasldb/sasldb.h"

#ifdef HAVE_OPIE
#include <opie.h>

#ifndef OPIE_KEYFILE
#define OPIE_KEYFILE "/etc/opiekeys"
#endif
#endif /* HAVE_OPIE */

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

#define OTP_SEQUENCE_MAX	9999
#define OTP_SEQUENCE_DEFAULT	499
#define OTP_SEQUENCE_REINIT	490
#define OTP_SEED_MIN		1
#define OTP_SEED_MAX		16
#define OTP_HASH_SIZE		8		/* 64 bits */
#define OTP_CHALLENGE_MAX	100
#define OTP_RESPONSE_MAX	100
#define OTP_HEX_TYPE		"hex:"
#define OTP_WORD_TYPE		"word:"
#define OTP_INIT_HEX_TYPE	"init-hex:"
#define OTP_INIT_WORD_TYPE	"init-word:"

typedef struct algorithm_option_s {
    const char *name;		/* name used in challenge/response */
    int swab;			/* number of bytes to swab (0, 1, 2, 4, 8) */
    const char *evp_name;	/* name used for lookup in EVP table */
} algorithm_option_t;

static algorithm_option_t algorithm_options[] = {
    {"md4",	0,	"md4"},
    {"md5",	0,	"md5"},
    {"sha1",	4,	"sha1"},
    {NULL,	0,	NULL}
};

typedef struct context {
    int state;
    char *authid;
    sasl_secret_t *password;
    sasl_secret_t *password_free;
    int locked;				/* is the user's secret locked? */
    algorithm_option_t *alg;
#ifdef HAVE_OPIE
    struct opie opie;
#else
    char *realm;
    unsigned seq;
    char seed[OTP_SEED_MAX+1];
    unsigned char otp[OTP_HASH_SIZE];
    time_t timestamp;			/* time we locked the secret */
#endif /* HAVE_OPIE */
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

  if (text->authid)           _plug_free_string(utils,&(text->authid));
  if (text->password_free)    _plug_free_secret(utils, &(text->password_free));
  
  if (text->out_buf)          utils->free(text->out_buf);

  utils->free(text);
}

static void otp_both_mech_free(void *global_context,
			       const sasl_utils_t *utils)
{
    if(global_context) utils->free(global_context);  

    EVP_cleanup();
}

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
	  SETERROR(params->utils, "OTP: Unexpectedly missing a prompt result");
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

static int get_password(context_t *text,
			sasl_client_params_t *params,
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
	  SETERROR(params->utils, "OTP: Unexpectedly missing a prompt result");
	  return SASL_FAIL;
      }
      
      /* copy what we got into a secret_t */
      text->password_free = text->password =
	  (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t)+
						  prompt->len+1);
      if (!text->password) {
	  MEMERROR( params->utils );
	  return SASL_NOMEM;
      }
      
      text->password->len=prompt->len;
      memcpy(text->password->data, prompt->result, prompt->len);
      text->password->data[text->password->len]=0;

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
			&(text->password));

  return result;
}

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
  int alloc_size;
  sasl_interact_t *prompts;
  context_t *text;

  text=conn_context;

  if (user_res==SASL_INTERACT) num++;
  if (auth_res==SASL_INTERACT) num++;
  if (echo_res==SASL_INTERACT) num++;
  if (pass_res==SASL_INTERACT) num++;

  if (num==1) {
      SETERROR(params->utils,
	       "OTP: make_prompts called with no actual prompts" );
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
    (prompts)->challenge=text->out_buf;
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


/* Convert the binary data into ASCII hex */
void bin2hex(unsigned char *bin, int binlen, char *hex)
{
    int i;
    unsigned char c;

    for (i = 0; i < binlen; i++) {
	c = (bin[i] >> 4) & 0xf;
	hex[i*2] = (c > 9) ? ('a' + c - 10) : ('0' + c);
	c = bin[i] & 0xf;
	hex[i*2+1] = (c > 9) ? ('a' + c - 10) : ('0' + c);
    }
    hex[i*2] = '\0';
}

/*
 * Hash the data using the given algorithm and fold it into 64 bits,
 * swabbing bytes if necessary.
 */
static void otp_hash(const EVP_MD *md, char *in, int inlen,
		     unsigned char *out, int swab)
{
    EVP_MD_CTX mdctx;
    char hash[EVP_MAX_MD_SIZE];
    int i, j, hashlen;

    EVP_DigestInit(&mdctx, md);
    EVP_DigestUpdate(&mdctx, in, inlen);
    EVP_DigestFinal(&mdctx, hash, &hashlen);

    /* Fold the result into 64 bits */
    for (i = OTP_HASH_SIZE; i < hashlen; i++) {
	hash[i % OTP_HASH_SIZE] ^= hash[i];
    }

    /* Swab bytes */
    if (swab) {
	for (i = 0; i < OTP_HASH_SIZE;) {
	    for (j = swab-1; j > -swab; i++, j-=2)
		out[i] = hash[i+j];
	}
    }
    else
	memcpy(out, hash, OTP_HASH_SIZE);
}

static int generate_otp(const sasl_utils_t *utils,
			algorithm_option_t *alg, unsigned seq, char *seed,
			char *secret, char *otp)
{
    const EVP_MD *md;
    char *key;

    if (!(md = EVP_get_digestbyname(alg->evp_name))) {
	utils->seterror(utils->conn, 0,
			"OTP algorithm %s is not available", alg->evp_name);
	return SASL_FAIL;
    }

    if ((key = utils->malloc(strlen(seed) + strlen(secret) + 1)) == NULL) {
	SETERROR(utils, "cannot allocate OTP key");
	return SASL_NOMEM;
    }

    /* initial step */
    strcpy(key, seed);
    strcat(key, secret);
    otp_hash(md, key, strlen(key), otp, alg->swab);

    /* computation step */
    while (seq-- > 0)
	otp_hash(md, otp, OTP_HASH_SIZE, otp, alg->swab);

    utils->free(key);

    return SASL_OK;
}

static int parse_challenge(const sasl_utils_t *utils,
			   char *chal, algorithm_option_t **alg,
			   unsigned *seq, char *seed, int is_init)
{
    char *c;
    algorithm_option_t *opt;
    int n;

    c = chal;

    /* eat leading whitespace */
    while (*c && isspace((int) *c)) c++;

    if (!is_init) {
	/* check the prefix */
	if (!*c || strncmp(c, "otp-", 4)) {
	    SETERROR(utils, "not a OTP challenge");
	    return SASL_BADPROT;
	}

	/* skip the prefix */
	c += 4;
    }

    /* find the algorithm */
    opt = algorithm_options;
    while (opt->name) {
	if (!strncmp(c, opt->name, strlen(opt->name))) {
	    break;
	}
	opt++;
    }

    /* didn't find the algorithm in our list */
    if (!opt->name) {
	utils->seterror(utils->conn, 0, "OTP algorithm '%s' not supported", c);
	return SASL_BADPROT;
    }

    /* skip algorithm name */
    c += strlen(opt->name);
    *alg = opt;

    /* eat whitespace */
    if (!isspace((int) *c)) {
	SETERROR(utils, "no whitespace between OTP algorithm and sequence");
	return SASL_BADPROT;
    }
    while (*c && isspace((int) *c)) c++;

    /* grab the sequence */
    if ((*seq = strtoul(c, &c, 10)) > OTP_SEQUENCE_MAX) {
	utils->seterror(utils->conn, 0, "sequence > %u", OTP_SEQUENCE_MAX);
	return SASL_BADPROT;
    }

    /* eat whitespace */
    if (!isspace((int) *c)) {
	SETERROR(utils, "no whitespace between OTP sequence and seed");
	return SASL_BADPROT;
    }
    while (*c && isspace((int) *c)) c++;

    /* grab the seed, converting to lowercase as we go */
    n = 0;
    while (*c && isalnum((int) *c) && (n < OTP_SEED_MAX))
	seed[n++] = tolower((int) *c++);
    if (n > OTP_SEED_MAX) {
	utils->seterror(utils->conn, 0, "OTP seed length > %u", OTP_SEED_MAX);
	return SASL_BADPROT;
    }
    else if (n < OTP_SEED_MIN) {
	utils->seterror(utils->conn, 0, "OTP seed length < %u", OTP_SEED_MIN);
	return SASL_BADPROT;
    }
    seed[n] = '\0';

    if (!is_init) {
	/* eat whitespace */
	if (!isspace((int) *c)) {
	    SETERROR(utils, "no whitespace between OTP seed and extensions");
	    return SASL_BADPROT;
	}
	while (*c && isspace((int) *c)) c++;

	/* make sure this is an extended challenge */
	if (strncmp(c, "ext", 3) ||
	    (*(c+=3) &&
	     !(isspace((int) *c) || (*c == ',') ||
	       (*c == '\r') || (*c == '\n')))) {
	    SETERROR(utils, "not an OTP extended challenge");
	    return SASL_BADPROT;
	}
    }

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
    char challenge[OTP_CHALLENGE_MAX+1];
    char *response = NULL;

    if (serverinlen > OTP_CHALLENGE_MAX) {
	SETERROR(params->utils, "OTP challenge too long");
	return SASL_BADPROT;
    }

    /* we can't assume that challenge is null-terminated */
    strncpy(challenge, serverin, serverinlen);
    challenge[serverinlen] = '\0';

    /* try to get the one-time password */
    echo_result=get_otpassword(params, challenge,
			       (const char **) &response, prompt_need);

    if ((echo_result!=SASL_OK) && (echo_result!=SASL_INTERACT)) {
	/*
	 * try to get the secret pass-phrase
	 */
	pass_result=get_password(text, params, prompt_need);
      
	if ((pass_result!=SASL_OK) && (pass_result!=SASL_INTERACT))
	    return pass_result;
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }

    /* if there are prompts not filled in */
    if ((echo_result==SASL_INTERACT) || (pass_result==SASL_INTERACT))
    {
	char *temp = text->out_buf;
	text->out_buf = challenge; /* use out_buf to pass the challenge */

	/* make the prompt list */
	result=make_prompts(text, params, prompt_need, user_result,
			    auth_result, echo_result, pass_result);
	text->out_buf = temp;

	if (result!=SASL_OK) return result;

	return SASL_INTERACT;
    }

    /* the application provided us with a one-time password so use it */
    if (response) {
	text->state = 3;
	if (text->out_buf)  params->utils->free(text->out_buf);
	text->out_buf = response;
	text->out_buf_len = strlen(response)+1;
	*clientout = text->out_buf;
	*clientoutlen = strlen(text->out_buf);
	return SASL_OK;
    }

    /* generate our own response using the user's secret pass-phrase */
    else {
	algorithm_option_t *alg;
	unsigned seq;
	char seed[OTP_SEED_MAX+1];
	char otp[OTP_HASH_SIZE];
	int init_done = 0;

	/* parse challenge */
	result = parse_challenge(params->utils,
				 challenge, &alg, &seq, seed, 0);

	if (result != SASL_OK) {
	    /* parse_challenge() takes care of error message */
	    goto done;
	}

	if (!text->password) {
	    PARAMERROR(params->utils);
	    result = SASL_BADPARAM;
	    goto done;
	}

	if (seq < 1) {
	    SETERROR(params->utils, "OTP has expired (sequence < 1)");
	    result = SASL_EXPIRED;
	    goto done;
	}

	/* generate otp */
	result = generate_otp(params->utils, alg, seq, seed,
			      text->password->data, otp);
	if (result != SASL_OK) {
	    /* generate_otp() takes care of error message */
	    *clientout = NULL;
	    *clientoutlen = 0;
	    goto done;
	}

	result = _plug_buf_alloc(params->utils, &(text->out_buf),
				 &(text->out_buf_len), OTP_RESPONSE_MAX+1);
	if (result != SASL_OK) goto done;;

	if (seq < OTP_SEQUENCE_REINIT) {
	    unsigned short randnum;
	    char new_seed[OTP_SEED_MAX+1];
	    char new_otp[OTP_HASH_SIZE];

	    /* try to reinitialize */

	    /* make sure we have a different seed */
	    do {
		params->utils->rand(params->utils->rpool,
				    (char*) &randnum, sizeof(randnum));
		sprintf(new_seed, "%.2s%04u", params->serverFQDN,
			(randnum % 9999) + 1);
	    } while (!strcasecmp(seed, new_seed));

	    result = generate_otp(params->utils, alg, OTP_SEQUENCE_DEFAULT,
				  new_seed, text->password->data, new_otp);

	    if (result == SASL_OK) {
		/* create an init-hex response */
		strcpy(text->out_buf, OTP_INIT_HEX_TYPE);
		bin2hex(otp, OTP_HASH_SIZE,
			text->out_buf+strlen(text->out_buf));
		sprintf(text->out_buf+strlen(text->out_buf), ":%s %u %s:",
			alg->name, OTP_SEQUENCE_DEFAULT, new_seed);
		bin2hex(new_otp, OTP_HASH_SIZE,
			text->out_buf+strlen(text->out_buf));
		init_done = 1;
	    }
	    else {
		/* just do a regular response */
	    }
	}

	if (!init_done) {
	    /* created hex response */
	    strcpy(text->out_buf, OTP_HEX_TYPE);
	    bin2hex(otp, OTP_HASH_SIZE, text->out_buf+strlen(text->out_buf));
	}

	*clientout = text->out_buf;
	*clientoutlen = strlen(text->out_buf);
	result = SASL_OK;

      done:
	text->state = 3;

	return result;
    }
  }

  return SASL_FAIL; /* should never get here */
}

static sasl_client_plug_t otp_client_plugins[] = 
{
  {
    "OTP",
    0,
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS | SASL_SEC_FORWARD_SECRECY,
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

    /* Add all digests */
    OpenSSL_add_all_digests();

    return SASL_OK;
}

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

#ifdef HAVE_OPIE
/*
 * The OPIE specific server side of the OTP plugin.
 */
static void opie_server_mech_dispose(void *conn_context,
				    const sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (!text)
    return;

  /* if we created a challenge, but bailed before the verification of the
     response, do a verify here to release the lock on the user key */
  if (text->locked) opieverify(&text->opie, "");

  otp_both_mech_dispose(conn_context, utils);
}

static int opie_server_mech_step(void *conn_context,
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

    oparams->param_version = 0;

  if (text->state == 1) {
    const char *authzid;
    const char *authid;
    size_t authid_len;
    unsigned lup=0;
    int result;

    /* should have received authzid NUL authid */

    /* get authzid */
    authzid = clientin;
    while ((lup < clientinlen) && (clientin[lup] != 0))
      ++lup;

    if (lup >= clientinlen)
    {
	SETERROR(params->utils, "Can only find OTP authzid (no authid)");
	return SASL_BADPROT;
    }

    /* get authid */
    ++lup;
    authid = clientin + lup;
    while ((lup < clientinlen) && (clientin[lup] != 0))
      ++lup;

    authid_len = clientin + lup - authid;

    if (lup != clientinlen) {
	SETERROR(params->utils,
		 "Got more data than we were expecting in the OTP plugin\n");
	return SASL_BADPROT;
    }
    
    text->authid = params->utils->malloc(authid_len + 1);    
    if (text->authid == NULL) {
	MEMERROR(params->utils);
	return SASL_NOMEM;
    }

    /* we can't assume that authen is null-terminated */
    strncpy(text->authid, authid, authid_len);
    text->authid[authid_len] = '\0';

    result = params->canon_user(params->utils->conn,
				text->authid, 0,
				SASL_CU_AUTHID, oparams);
    if (result != SASL_OK) goto fail;

    result = params->canon_user(params->utils->conn,
				strlen(authzid) ? authzid : text->authid, 0,
				SASL_CU_AUTHZID, oparams);
    if (result != SASL_OK) goto fail;

    result = _plug_buf_alloc(params->utils, &(text->out_buf),
			     &(text->out_buf_len), OTP_CHALLENGE_MAX+1);
    if (result != SASL_OK) goto fail;

    /* create challenge - return sasl_continue on success */
    result = opiechallenge(&text->opie, text->authid, text->out_buf);

    switch (result) {
    case 0:
	text->locked = 1;
	*serverout = text->out_buf;
	*serveroutlen = strlen(text->out_buf);
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

  fail:    
    *serverout = NULL;
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
    text->locked = 0;

    switch (result) {
    case 0:
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
    
    *serverout = NULL;
    *serveroutlen = 0;
    text->state = 3; /* so fails if called again */
    return result;
  }

  SETERROR( params->utils,
	    "Unexpected State Reached in OTP plugin");
  return SASL_FAIL; /* should never get here */
}

static int opie_mech_avail(void *glob_context __attribute__((unused)),
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
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS | SASL_SEC_FORWARD_SECRECY,
    SASL_FEAT_WANT_CLIENT_FIRST,
    NULL,
    &otp_server_mech_new,
    &opie_server_mech_step,
    &opie_server_mech_dispose,
    &otp_both_mech_free,
    NULL,
    NULL,
    NULL,
    &opie_mech_avail,
    NULL
  }
};
#else /* HAVE_OPIE */

#include "otp.h"

#define OTP_MDA_DEFAULT		"md5"
#define OTP_LOCK_TIMEOUT	5 * 60		/* 5 minutes */

static int make_secret(const sasl_utils_t *utils,
		       const char *alg, unsigned seq, char *seed, char *otp,
		       time_t timeout, sasl_secret_t **secret)
{
    unsigned sec_len;
    unsigned char *data;

    /*
     * secret is stored as:
     *
     * <alg> \0 <seq> \0 <seed> \0 <otp> <timeout>
     *
     * <timeout> is used as a "lock" when an auth is in progress
     * we just set it to zero here (no lock)
     */
    sec_len = strlen(alg)+1+4+1+strlen(seed)+1+OTP_HASH_SIZE+sizeof(time_t);
    *secret = utils->malloc(sizeof(sasl_secret_t)+sec_len);
    if (!*secret) {
	return SASL_NOMEM;
    }

    (*secret)->len = sec_len;
    data = (*secret)->data;
    memcpy(data, alg, strlen(alg)+1);
    data += strlen(alg)+1;
    sprintf(data, "%04u", seq);
    data += 5;
    memcpy(data, seed, strlen(seed)+1);
    data += strlen(seed)+1;
    memcpy(data, otp, OTP_HASH_SIZE);
    data += OTP_HASH_SIZE;
    memcpy(data, &timeout, sizeof(time_t));

    return SASL_OK;
}

static void otp_server_mech_dispose(void *conn_context,
				    const sasl_utils_t *utils)
{
  context_t *text = (context_t*) conn_context;
  sasl_secret_t *sec;
  int r;

  if (!text)
    return;

  /* if we created a challenge, but bailed before the verification of the
     response, release the lock on the user key */
  if (text->locked && (time(0) < text->timestamp + OTP_LOCK_TIMEOUT)) {
      r = make_secret(utils, text->alg->name, text->seq,
		      text->seed, text->otp, 0, &sec);
      if (r != SASL_OK) {
	  SETERROR(utils, "error making OTP secret");
	  if (sec) utils->free(sec);
	  sec = NULL;
      }

      /* do the store */
      r = (*_sasldb_putdata)(utils, utils->conn,
			     text->authid, text->realm, "cmusaslsecretOTP",
			     (sec ? sec->data : NULL), (sec ? sec->len : 0));

      if (r) {
	  SETERROR(utils, "Error putting OTP secret");
      }

      if (sec) utils->free(sec);
  }

  if (text->realm)    _plug_free_string(utils,&(text->realm));

  otp_both_mech_dispose(conn_context, utils);
}

static int parse_secret(const sasl_utils_t *utils,
			char *secret, size_t seclen,
			char *alg, unsigned *seq, char *seed,
			unsigned char *otp,
			time_t *timeout)
{
    unsigned char *c;

    /*
     * secret is stored as:
     *
     * <alg> \0 <seq> \0 <seed> \0 <otp> <timeout>
     *
     */

    if (seclen < (3+1+1+1+OTP_SEED_MIN+1+OTP_HASH_SIZE+sizeof(time_t))) {
	SETERROR(utils, "OTP secret too short");
	return SASL_FAIL;
    }

    c = secret;

    strcpy(alg, (char*) c);
    c += strlen(alg)+1;

    *seq = strtoul(c, NULL, 10);
    c += 5;

    strcpy(seed, (char*) c);
    c += strlen(seed)+1;

    memcpy(otp, c, OTP_HASH_SIZE);
    c += OTP_HASH_SIZE;

    memcpy(timeout, c, sizeof(time_t));

    return SASL_OK;
}

/* returns the realm we should pretend to be in */
static int parseuser(const sasl_utils_t *utils,
		     char **user, char **realm, const char *user_realm, 
		     const char *serverFQDN, const char *input)
{
    int ret;
    char *r;

    assert(user);
    assert(realm);
    assert(serverFQDN);
    assert(input);

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
		ret = SASL_NOMEM;
	    }
	}
    }

    return ret;
}

/* Convert the ASCII hex into binary data */
int hex2bin(char *hex, unsigned char *bin, int binlen)
{
    int i;
    char *c;
    unsigned char msn, lsn;

    memset(bin, 0, binlen);

    for (c = hex, i = 0; i < binlen; c++) {
	 /* whitespace */
	if (isspace((int) *c))
	    continue;
	/* end of string, or non-hex char */
	if (!*c || !*(c+1) || !isxdigit((int) *c))
	    break;

	msn = (*c > '9') ? tolower((int) *c) - 'a' + 10 : *c - '0';
	c++;
	lsn = (*c > '9') ? tolower((int) *c) - 'a' + 10 : *c - '0';

	bin[i++] = (unsigned char) (msn << 4) | lsn;
    }

    return (i < binlen) ? SASL_BADAUTH : SASL_OK;
}

/* Compare two string pointers */
static int strptrcasecmp(const void *arg1, const void *arg2)
{
    return (strcasecmp(*((char**) arg1), *((char**) arg2)));
}

/* Convert the 6 words into binary data */
static int word2bin(const sasl_utils_t *utils,
		    char *words, unsigned char *bin, const EVP_MD *md)
{
    int i, j;
    char *c, *word, buf[OTP_RESPONSE_MAX+1];
    void *base;
    int nmemb;
    long x = 0;
    unsigned char bits[OTP_HASH_SIZE+1]; /* 1 for checksum */
    unsigned char chksum;
    int bit, fbyte, lbyte;
    const char **str_ptr;
    int alt_dict = 0;

    /* this is a destructive operation, so make a work copy */
    strcpy(buf, words);
    memset(bits, 0, 9);

    for (c = buf, bit = 0, i = 0; i < 6; i++, c++, bit+=11) {
	while (*c && isspace((int) *c)) c++;
	word = c;
	while (*c && isalpha((int) *c)) c++;
	if (!*c && i < 5) break;
	*c = '\0';
	if (strlen(word) < 1 || strlen(word) > 4) {
	    utils->log(NULL, SASL_LOG_DEBUG,
		       "incorrect word length '%s'", word);
	    return SASL_BADAUTH;
	}

	/* standard dictionary */
	if (!alt_dict) {
	    if (strlen(word) < 4) {
		base = otp_std_dict;
		nmemb = OTP_4LETTER_OFFSET;
	    }
	    else {
		base = otp_std_dict + OTP_4LETTER_OFFSET;
		nmemb = OTP_STD_DICT_SIZE - OTP_4LETTER_OFFSET;
	    }

	    str_ptr = (const char**) bsearch((void*) &word, base, nmemb,
					     sizeof(const char*),
					     strptrcasecmp);
	    if (str_ptr) {
		x = str_ptr - otp_std_dict;
	    }
	    else if (i == 0) {
		/* couldn't find first word, try alternate dictionary */
		alt_dict = 1;
	    }
	    else {
		utils->log(NULL, SASL_LOG_DEBUG,
			   "word '%s' not found in dictionary", word);
		return SASL_BADAUTH;
	    }
	}

	/* alternate dictionary */
	if (alt_dict) {
	    EVP_MD_CTX mdctx;
	    char hash[EVP_MAX_MD_SIZE];
	    int hashlen;

	    EVP_DigestInit(&mdctx, md);
	    EVP_DigestUpdate(&mdctx, word, strlen(word));
	    EVP_DigestFinal(&mdctx, hash, &hashlen);

	    /* use lowest 11 bits */
	    x = ((hash[hashlen-2] & 0x7) << 8) | hash[hashlen-1];
	}

	/* left align 11 bits on byte boundary */
	x <<= (8 - ((bit+11) % 8));
	/* first output byte containing some of our 11 bits */
	fbyte = bit / 8;
	/* last output byte containing some of our 11 bits */
	lbyte = (bit+11) / 8;
	/* populate the output bytes with the 11 bits */
	for (j = lbyte; j >= fbyte; j--, x >>= 8)
	    bits[j] |= (unsigned char) (x & 0xff);
    }

    if (i < 6) {
	utils->log(NULL, SASL_LOG_DEBUG, "not enough words (%d)", i);
	return SASL_BADAUTH;
    }

    /* see if the 2-bit checksum is correct */
    for (chksum = 0, i = 0; i < 8; i++) {
	for (j = 0; j < 4; j++) {
	    chksum += ((bits[i] >> (2 * j)) & 0x3);
	}
    }
    chksum <<= 6;

    if (chksum != bits[8]) {
	utils->log(NULL, SASL_LOG_DEBUG, "incorrect parity");
	return SASL_BADAUTH;
    }

    memcpy(bin, bits, OTP_HASH_SIZE);

    return SASL_OK;
}

static int verify_response(context_t *text, const sasl_utils_t *utils,
			   char *response)
{
    const EVP_MD *md;
    char *c;
    int do_init = 0;
    unsigned char cur_otp[OTP_HASH_SIZE], prev_otp[OTP_HASH_SIZE];
    int r;

    /* find the MDA */
    if (!(md = EVP_get_digestbyname(text->alg->evp_name))) {
	utils->seterror(utils->conn, 0,
			"OTP algorithm %s is not available",
			text->alg->evp_name);
	return SASL_FAIL;
    }

    /* eat leading whitespace */
    c = response;
    while (isspace((int) *c)) c++;

    if (strchr(c, ':')) {
	if (!strncasecmp(c, OTP_HEX_TYPE, strlen(OTP_HEX_TYPE))) {
	    r = hex2bin(c+strlen(OTP_HEX_TYPE), cur_otp, OTP_HASH_SIZE);
	}
	else if (!strncasecmp(c, OTP_WORD_TYPE, strlen(OTP_WORD_TYPE))) {
	    r = word2bin(utils, c+strlen(OTP_WORD_TYPE), cur_otp, md);
	}
	else if (!strncasecmp(c, OTP_INIT_HEX_TYPE,
			      strlen(OTP_INIT_HEX_TYPE))) {
	    do_init = 1;
	    r = hex2bin(c+strlen(OTP_INIT_HEX_TYPE), cur_otp, OTP_HASH_SIZE);
	}
	else if (!strncasecmp(c, OTP_INIT_WORD_TYPE,
			      strlen(OTP_INIT_WORD_TYPE))) {
	    do_init = 1;
	    r = word2bin(utils, c+strlen(OTP_INIT_WORD_TYPE), cur_otp, md);
	}
	else {
	    SETERROR(utils, "unknown OTP extended response type");
	    r = SASL_BADAUTH;
	}
    }
    else {
	/* standard response, try word first, and then hex */
	r = word2bin(utils, c, cur_otp, md);
	if (r != SASL_OK)
	    r = hex2bin(c, cur_otp, OTP_HASH_SIZE);
    }

    if (r == SASL_OK) {
	/* do one more hash (previous otp) and compare to stored otp */
	otp_hash(md, cur_otp, OTP_HASH_SIZE, prev_otp, text->alg->swab);

	if (!memcmp(prev_otp, text->otp, OTP_HASH_SIZE)) {
	    /* update the secret with this seq/otp */
	    memcpy(text->otp, cur_otp, OTP_HASH_SIZE);
	    text->seq--;
	    r = SASL_OK;
	}
	else
	    r = SASL_BADAUTH;
    }

    /* if this is an init- attempt, let's check it out */
    if (r == SASL_OK && do_init) {
	char *new_chal = NULL, *new_resp = NULL;
	algorithm_option_t *alg;
	unsigned seq;
	char seed[OTP_SEED_MAX+1];
	unsigned char new_otp[OTP_HASH_SIZE];

	/* find the challenge and response fields */
	new_chal = strchr(c+strlen(OTP_INIT_WORD_TYPE), ':');
	if (new_chal) {
	    *new_chal++ = '\0';
	    new_resp = strchr(new_chal, ':');
	    if (new_resp)
		*new_resp++ = '\0';
	}

	if (!(new_chal && new_resp))
	    return SASL_BADAUTH;

	if ((r = parse_challenge(utils, new_chal, &alg, &seq, seed, 1))
	    != SASL_OK) {
	    return r;
	}

	if (seq < 1 || !strcasecmp(seed, text->seed))
	    return SASL_BADAUTH;
    
	/* find the MDA */
	if (!(md = EVP_get_digestbyname(alg->evp_name))) {
	    utils->seterror(utils->conn, 0,
			    "OTP algorithm %s is not available",
			    alg->evp_name);
	    return SASL_BADAUTH;
	}

	if (!strncasecmp(c, OTP_INIT_HEX_TYPE, strlen(OTP_INIT_HEX_TYPE))) {
	    r = hex2bin(new_resp, new_otp, OTP_HASH_SIZE);
	}
	else if (!strncasecmp(c, OTP_INIT_WORD_TYPE,
			      strlen(OTP_INIT_WORD_TYPE))) {
	    r = word2bin(utils, new_resp, new_otp, md);
	}

	if (r == SASL_OK) {
	    /* setup for new secret */
	    text->alg = alg;
	    text->seq = seq;
	    strcpy(text->seed, seed);
	    memcpy(text->otp, new_otp, OTP_HASH_SIZE);
	}
    }

    return r;
}

static int otp_server_mech_step(void *conn_context,
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

    oparams->param_version = 0;

  if (text->state == 1) {
    const char *authzid;
    const char *authidp;
    char *authid;
    size_t authid_len;
    unsigned lup=0;
    int r, n;
    const char *secret_request[] = { "*cmusaslsecretOTP",
				     NULL };
    struct propval auxprop_values[2];
    char mda[10];
    time_t timeout;
    sasl_secret_t *sec = NULL;

    /* should have received authzid NUL authid */

    /* get authzid */
    authzid = clientin;
    while ((lup < clientinlen) && (clientin[lup] != 0))
      ++lup;

    if (lup >= clientinlen)
    {
	SETERROR(params->utils, "Can only find OTP authzid (no authid)");
	return SASL_BADPROT;
    }

    /* get authid */
    ++lup;
    authidp = clientin + lup;
    while ((lup < clientinlen) && (clientin[lup] != 0))
      ++lup;

    authid_len = clientin + lup - authidp;

    if (lup != clientinlen) {
	SETERROR(params->utils,
		 "Got more data than we were expecting in the OTP plugin\n");
	return SASL_BADPROT;
    }

    authid = params->utils->malloc(authid_len + 1);    
    if (authid == NULL) {
	MEMERROR(params->utils);
	return SASL_NOMEM;
    }

    /* we can't assume that authid is null-terminated */
    strncpy(authid, authidp, authid_len);
    authid[authid_len] = '\0';

    /* Get the realm */
    r = parseuser(params->utils, &text->authid, &text->realm,
		  params->user_realm,
    		  params->serverFQDN, authid);

    params->utils->free(authid);
    if (r) {
	params->utils->seterror(params->utils->conn, 0, 
				"OTP: Error getting realm");
	return SASL_FAIL;
    }

    n = 0;
    do {
	/* Get user secret */
	r = params->utils->prop_request(params->propctx, secret_request);
	if (r != SASL_OK) goto fail;

	/* this will trigger the getting of the aux properties */
	r = params->canon_user(params->utils->conn, text->authid, 0,
			       SASL_CU_AUTHID, oparams);
	if (r != SASL_OK) goto fail;

	r = params->canon_user(params->utils->conn,
			       strlen(authzid) ? authzid : text->authid, 0,
			       SASL_CU_AUTHZID, oparams);
	if (r != SASL_OK) goto fail;

	r = params->utils->prop_getnames(params->propctx, secret_request,
					 auxprop_values);
	if (r < 0 ||
	    (!auxprop_values[0].name || !auxprop_values[0].values)) {
	    /* We didn't find this username */
	    params->utils->seterror(params->utils->conn,0,
				    "no OTP secret in database");
	    r = SASL_NOUSER;
	    goto fail;
	}

	if (auxprop_values[0].name && auxprop_values[0].values) {
	    r = parse_secret(params->utils,
			     (char*) auxprop_values[0].values[0],
			     auxprop_values[0].valsize,
			     mda, &text->seq, text->seed, text->otp, &timeout);

	    if (r) {
		goto fail;
	    }
	} else {
	    params->utils->seterror(params->utils->conn, 0,
				    "don't have a OTP secret");
	    r = SASL_FAIL;
	    goto fail;
	}

	params->utils->prop_clear(params->propctx, 1);

	text->timestamp = time(0);
    }
    /*
     * check lock timeout
     *
     * we try 10 times in 1 second intervals in order to give the other
     * auth attempt time to finish
     */
    while ((text->timestamp < timeout) && (n++ < 10) && !sleep(1));

    if (text->timestamp < timeout) {
	SETERROR(params->utils,
		 "simultaneous OTP authentications not permitted");
	r = SASL_TRYAGAIN;
	goto fail;
    }

    /* check sequence number */
    if (text->seq <= 1) {
	SETERROR(params->utils, "OTP has expired (sequence <= 1)");
	r = SASL_EXPIRED;
	goto fail;
    }

    /* find algorithm */
    text->alg = algorithm_options;
    while (text->alg->name) {
	if (!strcasecmp(text->alg->name, mda))
	    break;

	text->alg++;
    }

    if (!text->alg->name) {
	params->utils->seterror(params->utils->conn, 0,
				"unknown OTP algorithm '%s'", mda);
	r = SASL_FAIL;
	goto fail;
    }

    /* remake the secret with a timeout */
    r = make_secret(params->utils, text->alg->name, text->seq, text->seed,
		    text->otp, text->timestamp + OTP_LOCK_TIMEOUT, &sec);
    if (r != SASL_OK) {
	SETERROR(params->utils, "error making OTP secret");
	goto fail;
    }

    /* do the store */
    r = (*_sasldb_putdata)(params->utils, params->utils->conn,
			   text->authid, text->realm, "cmusaslsecretOTP",
			   sec->data, sec->len);

    if (sec) params->utils->free(sec);

    if (r) {
	SETERROR(params->utils, "Error putting OTP secret");
	goto fail;
    }

    text->locked = 1;

    r = _plug_buf_alloc(params->utils, &(text->out_buf),
			&(text->out_buf_len), OTP_CHALLENGE_MAX+1);
    if (r != SASL_OK) goto fail;

    /* create challenge */
    sprintf(text->out_buf, "otp-%s %u %s ext",
	    text->alg->name, text->seq-1, text->seed);

    *serverout = text->out_buf;
    *serveroutlen = strlen(text->out_buf);
    text->state = 2;

    return SASL_CONTINUE;

  fail:
    *serverout = NULL;
    *serveroutlen = 0;
    text->state = 3; /* so fails if called again */
    return r;
  }

  if (text->state == 2) {
    char response[OTP_RESPONSE_MAX+1];
    int r, result;
    sasl_secret_t *sec = NULL;

    *serverout = NULL;
    *serveroutlen = 0;
    text->state = 3; /* so fails if called again */

    if (clientinlen > OTP_RESPONSE_MAX) {
	SETERROR(params->utils, "OTP response too long");
	return SASL_BADPROT;
    }

    /* we can't assume that the response is null-terminated */
    strncpy(response, clientin, clientinlen);
    response[clientinlen] = '\0';

    /* check timeout */
    if (time(0) > text->timestamp + OTP_LOCK_TIMEOUT) {
	SETERROR(params->utils, "OTP: server timed out");
	return SASL_UNAVAIL;
    }

    /* verify response */
    result = verify_response(text, params->utils, response);

    /* make the new secret */
    r = make_secret(params->utils, text->alg->name, text->seq,
		    text->seed, text->otp, 0, &sec);
    if (r != SASL_OK) {
	SETERROR(params->utils, "error making OTP secret");
	if (sec) params->utils->free(sec);
	sec = NULL;
    }

    /* do the store */
    r = (*_sasldb_putdata)(params->utils, params->utils->conn,
			   text->authid, text->realm, "cmusaslsecretOTP",
			   (sec ? sec->data : NULL), (sec ? sec->len : 0));

    if (r) {
	params->utils->seterror(params->utils->conn, 0, 
				"Error putting OTP secret");
    }

    text->locked = 0;

    if (sec) params->utils->free(sec);

    oparams->doneflag = 1;

    return result;
  }

  SETERROR( params->utils,
	    "Unexpected State Reached in OTP plugin");
  return SASL_FAIL; /* should never get here */
}

static int otp_setpass(void *glob_context __attribute__((unused)),
		       sasl_server_params_t *sparams,
		       const char *userstr,
		       const char *pass,
		       unsigned passlen __attribute__((unused)),
		       const char *oldpass __attribute__((unused)),
		       unsigned oldpasslen __attribute__((unused)),
		       unsigned flags)
{
    int r;
    char *user = NULL;
    char *realm = NULL;
    sasl_secret_t *sec;

    /* Do we have database support? */
    /* Note that we can use a NULL sasl_conn_t because our
     * sasl_utils_t is "blessed" with the global callbacks */
    if(_sasl_check_db(sparams->utils, NULL) != SASL_OK) {
	SETERROR(sparams->utils, "OTP: No database support");
	return SASL_NOMECH;
    }

    r = parseuser(sparams->utils, &user, &realm, sparams->user_realm,
		       sparams->serverFQDN, userstr);
    if (r) {
      sparams->utils->seterror(sparams->utils->conn, 0, 
			       "OTP: Error parsing user");
      return r;
    }

    if ((flags & SASL_SET_DISABLE) || pass == NULL) {
	sec = NULL;
    } else {
	algorithm_option_t *algs;
	const char *mda;
	unsigned int len;
	unsigned short randnum;
	char seed[OTP_SEED_MAX+1];
	char otp[OTP_HASH_SIZE];

	sparams->utils->getopt(sparams->utils->getopt_context,
			       "OTP", "otp_mda", &mda, &len);
	if (!mda) mda = OTP_MDA_DEFAULT;

	algs = algorithm_options;
	while (algs->name) {
	    if (!strcasecmp(algs->name, mda) ||
		!strcasecmp(algs->evp_name, mda))
		break;

	    algs++;
	}

	if (!algs->name) {
	    sparams->utils->seterror(sparams->utils->conn, 0,
				     "unknown OTP algorithm '%s'", mda);
	    r = SASL_FAIL;
	    goto cleanup;
	}

	sparams->utils->rand(sparams->utils->rpool,
			     (char*) &randnum, sizeof(randnum));
	sprintf(seed, "%.2s%04u", sparams->serverFQDN, (randnum % 9999) + 1);

	r = generate_otp(sparams->utils, algs, OTP_SEQUENCE_DEFAULT,
			 seed, (char*) pass, otp);
	if (r != SASL_OK) {
	    /* generate_otp() takes care of error message */
	    goto cleanup;
	}

	r = make_secret(sparams->utils, algs->name, OTP_SEQUENCE_DEFAULT,
			seed, otp, 0, &sec);
	if (r != SASL_OK) {
	    SETERROR(sparams->utils, "error making OTP secret");
	    goto cleanup;
	}
    }

    /* do the store */
    r = (*_sasldb_putdata)(sparams->utils, sparams->utils->conn,
			   user, realm, "cmusaslsecretOTP",
			   (sec ? sec->data : NULL), (sec ? sec->len : 0));

    if (r) {
      sparams->utils->seterror(sparams->utils->conn, 0, 
			       "Error putting OTP secret");
      goto cleanup;
    }

    sparams->utils->log(NULL, SASL_LOG_DEBUG, "Setpass for OTP successful\n");

 cleanup:

    if (user) 	sparams->utils->free(user);
    if (realm) 	sparams->utils->free(realm);
    if (sec)    sparams->utils->free(sec);

    return r;
}

static int otp_mech_avail(void *glob_context __attribute__((unused)),
	  	          sasl_server_params_t *sparams,
		          void **conn_context __attribute__((unused))) 
{
    /* Do we have database support? */
    /* Note that we can use a NULL sasl_conn_t because our
     * sasl_utils_t is "blessed" with the global callbacks */
    if(_sasl_check_db(sparams->utils, NULL) != SASL_OK) {
	SETERROR(sparams->utils, "OTP: No database support");
	return SASL_NOMECH;
    }

    return SASL_OK;
}

static sasl_server_plug_t otp_server_plugins[] = 
{
  {
    "OTP",
    0,
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS | SASL_SEC_FORWARD_SECRECY,
    SASL_FEAT_WANT_CLIENT_FIRST,
    NULL,
    &otp_server_mech_new,
    &otp_server_mech_step,
    &otp_server_mech_dispose,
    &otp_both_mech_free,
    &otp_setpass,
    NULL,
    NULL,
    &otp_mech_avail,
    NULL
  }
};
#endif /* HAVE_OPIE */

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

    /* Add all digests */
    OpenSSL_add_all_digests();

    return SASL_OK;
}
