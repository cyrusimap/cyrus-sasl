/* CRAM-MD5 SASL plugin
 * Tim Martin 
 * $Id: cram.c,v 1.55 2001/02/19 19:01:54 leg Exp $
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#ifdef WIN32
/* # include "winconfig.h" */
#include <config.h>
#include <stdio.h>		/* for sprintf, snprinft */
#endif /* WIN32 */
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sasl.h>
#include <saslplug.h>
#include <saslutil.h>
#include <assert.h>

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslCRAM.h"
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define CRAM_MD5_VERSION (3)

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (1)
#endif

/* global: if we've already set a pass entry */
static int mydb_initialized = 0;

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

  /* not used on server side */
  text->authid=NULL;
  text->password=NULL;
  text->msgid = NULL;
  
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

/* copy a string */
static int
cram_strdup(sasl_utils_t * utils, const char *in, char **out, int *outlen)
{
  size_t len = strlen(in);

  if (outlen!=NULL) {
      *outlen = len;
  }

  *out = utils->malloc(len + 1);
  if (!*out) {
      return SASL_NOMEM;
  }

  strcpy((char *) *out, in);
  return SASL_OK;
}

static void free_string(sasl_utils_t *utils,
			char **str)
{
  size_t lup;
  size_t len;
  VL(("Freeing string\n"));

  if (str==NULL) return;
  if (*str==NULL) return;

  len=strlen(*str);

  /* overwrite the memory */
  for (lup=0;lup<len;lup++)
    (*str)[lup]='\0';

  utils->free(*str);

  *str=NULL;
}

static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

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
static int parseuser(sasl_utils_t *utils,
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
	ret = cram_strdup(utils, serverFQDN, realm, NULL);
	if (ret == SASL_OK) {
	    ret = cram_strdup(utils, input, user, NULL);
	}
    } else if (user_realm[0]) {
	ret = cram_strdup(utils, user_realm, realm, NULL);
	if (ret == SASL_OK) {
	    ret = cram_strdup(utils, input, user, NULL);
	}
    } else {
	/* otherwise, we gotta get it from the user */
	r = strchr(input, '@');
	if (!r) {
	    /* hmmm, the user didn't specify a realm */
	    /* we'll default to the serverFQDN */
	    ret = cram_strdup(utils, serverFQDN, realm, NULL);
	    if (ret == SASL_OK) {
		ret = cram_strdup(utils, input, user, NULL);
	    }
	} else {
	    int i;

	    r++;
	    ret = cram_strdup(utils, r, realm, NULL);
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
static char *convert16(unsigned char *in, int inlen, sasl_utils_t *utils)
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
			 void *inparams)
{
  char secret[65];
  unsigned char digest[24];  
  int lup;
  char *in16;

  sasl_server_params_t *params=(sasl_server_params_t *) inparams;

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

  VL(("secret=[%s] %lu\n",secret,sec->len));
  VL(("nonce=[%s] %i\n",nonce, noncelen));

  /* do the hmac md5 hash output 128 bits */
  params->utils->hmac_md5((unsigned char *) nonce,noncelen,
			  (unsigned char *) secret,64,digest);

  /* convert that to hex form */
  in16=convert16(digest,16,params->utils);
  if (in16==NULL) return NULL;

  return in16;
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

  if (errstr) *errstr = NULL;
  if (clientinlen < 0) return SASL_BADPARAM;

  if (text->state==1)
  {    
    char *time, *randdigits;
    /* arbitrary string of random digits 
     * time stamp
     * primary host
     */
    VL(("CRAM-MD5 step 1\n"));

    /* we shouldn't have received anything */
    if (clientinlen!=0)
    {
	if (errstr)
	    *errstr = "CRAM-MD5 does not accpet inital data";
	return SASL_FAIL;
    }

    /* get time and a random number for the nonce */
    time=gettime(sparams);
    randdigits=randomdigits(sparams);
    if ((time==NULL) || (randdigits==NULL)) return SASL_NOMEM;

    /* allocate some space for the nonce */
    *serverout=sparams->utils->malloc(200+1);
    if (*serverout==NULL) return SASL_NOMEM;

    /* create the nonce */
    snprintf((char *)*serverout,200,"<%s.%s@%s>",randdigits,time,
	    sparams->serverFQDN);

    /* free stuff */
    sparams->utils->free(time);    
    sparams->utils->free(randdigits);    
    
    *serveroutlen=strlen(*serverout);
    text->msgidlen=*serveroutlen;

    /* save nonce so we can check against it later */
    text->msgid=sparams->utils->malloc((*serveroutlen)+1);
    if (text->msgid==NULL) return SASL_NOMEM;
    memcpy(text->msgid,*serverout,*serveroutlen);
    text->msgid[ *serveroutlen ] ='\0';

    VL(("nonce=[%s]\n",text->msgid));

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    /* verify digest */
    char *userid = NULL;
    char *realm = NULL;
    char *authstr = NULL;
    sasl_secret_t *sec=NULL;
    int lup,pos;
    int result = SASL_FAIL;
    sasl_server_getsecret_t *getsecret;
    void *getsecret_context;

    HMAC_MD5_CTX tmphmac;
    char *digest_str = NULL;
    UINT4 digest[4];

    VL(("CRAM-MD5 Step 2\n"));
    VL(("Clientin: %s\n",clientin));

    /* extract userid; everything before last space*/
    pos=clientinlen-1;
    while ((pos>0) && (clientin[pos]!=' ')) {
	pos--;
    }
    if (pos<=0) {
	if (errstr) *errstr = "need authentication name";
	return SASL_BADPROT;
    }

    authstr=(char *) sparams->utils->malloc(pos+1);
    if (authstr == NULL) return SASL_NOMEM;
    /* copy authstr out */
    for (lup = 0; lup < pos; lup++) {
	authstr[lup] = clientin[lup];
    }
    authstr[lup] = '\0';

    result = parseuser(sparams->utils, &userid, &realm, sparams->user_realm,
	      sparams->serverFQDN, authstr);
    sparams->utils->free(authstr);
    if (result != SASL_OK) {
	goto done;
    }

    /* get callback so we can request the secret */
    result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_GETSECRET,
					 &getsecret,
					 &getsecret_context);
    if (result != SASL_OK) {
	VL(("result = %i trying to get secret callback\n",result));
	goto done;
    }
    if (! getsecret) {
	VL(("Received NULL getsecret callback\n"));
	result = SASL_FAIL;
	goto done;
    }

    /* We use the user's CRAM secret which is kinda 1/2 way thru the
       hmac */
    /* Request secret */
    result = getsecret(getsecret_context, "CRAM-MD5", userid, realm, &sec);
    if (result == SASL_NOUSER || !sec) {
      if (errstr) *errstr = "no secret in database";
      result = SASL_NOUSER;
      goto done;
    }
    if (result != SASL_OK) {
	goto done;
    }

    if (sec->len != sizeof(HMAC_MD5_STATE)) {
      if (errstr) *errstr = "secret database corruption";
      result = SASL_FAIL;
      goto done;
    }

    /* ok this is annoying:
       so we stored this half-way hmac transform instead of the plaintext
       that means we half to:
       -import it back into the md5 context
       -do an md5update with the nonce 
       -finalize it
    */
    sparams->utils->hmac_md5_import(&tmphmac, (HMAC_MD5_STATE *) sec->data);
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
	if (errstr) {
	    *errstr = "incorrect digest response";
	}	
	result = SASL_BADAUTH;
	goto done;
    }
    VL(("Succeeded!\n"));

    /* nothing more to do; authenticated 
     * set oparams information
     */
    oparams->doneflag=1;

    oparams->user = userid; /* set username */
    userid = NULL; /* set to null so we don't free */
    oparams->realm = realm;
    realm = NULL; /* set to null so we don't free */
    
    result = cram_strdup(sparams->utils, oparams->user, &(oparams->authid), NULL);
    if (result!=SASL_OK) {
	goto done;
    }

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
    if (sec) free_secret(sparams->utils, &sec);
    if (digest_str)  sparams->utils->free(digest_str);

    text->state = 3; /* if called again will fail */

    return result;
  }


  return SASL_FAIL; /* should never get here */
}

/*
 * See if there's at least one CRAM secret in the database
 *
 * Note: this function is duplicated in multiple plugins. If you fix
 * something here please update the other files
 */

static int mechanism_db_filled(char *mech_name, sasl_utils_t *utils)
{
  sasl_secret_t *sec=NULL;
  int result;
  sasl_server_getsecret_t *getsecret;
  void *getsecret_context;
  long version = -1;

  /* get callback so we can request the secret */
  result = utils->getcallback(utils->conn,
				       SASL_CB_SERVER_GETSECRET,
				       &getsecret,
				       &getsecret_context);
  if (result != SASL_OK) {
    VL(("result = %i trying to get secret callback\n",result));
    return result;
  }

  if (! getsecret) {
    VL(("Received NULL getsecret callback\n"));
    return SASL_FAIL;
  }

  /* Request "magic" secret */
  result = getsecret(getsecret_context, mech_name, "", "", &sec);
  if (result == SASL_NOUSER || result == SASL_FAIL) {
      return result;
  }

  /* check version */
  if (sec != NULL) {
      if (sec->len >= 4) {
	  memcpy(&version, sec->data, 4); 
	  version = ntohl(version);
      }
      free(sec);
  }

  if (version != CRAM_MD5_VERSION) {
      utils->log(utils->conn,
		 0,
		 mech_name,
		 SASL_FAIL,
		 0,
		 "CRAM-MD5 secrets database has incompatible version (%ld). My version (%d)",
		 version, CRAM_MD5_VERSION);

      return SASL_FAIL;
  }

  mydb_initialized = 1;

  return SASL_OK;
}

/*
 * Put a DUMMY entry in the db to show that there is at least one CRAM entry in the db
 *
 * Note: this function is duplicated in multiple plugins. If you fix
 * something here please update the other files
 */
static int mechanism_fill_db(char *mech_name, sasl_server_params_t *sparams)
{
  int result;
  sasl_server_putsecret_t *putsecret;
  void *putsecret_context;
  sasl_secret_t *sec = NULL;
  long version;

  /* don't do this again if it's already set */
  if (mydb_initialized == 1)
  {
      return SASL_OK;
  }

  /* get the callback for saving to the password db */
  result = sparams->utils->getcallback(sparams->utils->conn,
				       SASL_CB_SERVER_PUTSECRET,
				       &putsecret,
				       &putsecret_context);
  if (result != SASL_OK) {
    return result;
  }

  /* allocate a secret structure that we're going to save to disk */  
  sec=(sasl_secret_t *) sparams->utils->malloc(sizeof(sasl_secret_t)+
					       4);
  if (sec == NULL) {
    result = SASL_NOMEM;
    return result;
  }
  
  /* set the size */
  sec->len = 4;

  /* and insert the data */
  version = htonl(CRAM_MD5_VERSION);
  memcpy(sec->data, &version, 4);

  /* do the store */
  result = putsecret(putsecret_context,
		     mech_name, 
		     "",
		     "",
		     sec);

  if (result == SASL_OK)
  {
      mydb_initialized = 1;
  }

  return result;
}

static int
setpass(void *glob_context __attribute__((unused)),
	sasl_server_params_t *sparams,
	const char *userstr,
	const char *pass,
	unsigned passlen,
	int flags __attribute__((unused)),
	const char **errstr)
{
    int result;
    sasl_server_putsecret_t *putsecret;
    void *putsecret_context;
    char *user = NULL;
    char *realm = NULL;

    /* These need to be zero'ed out at the end */
    HMAC_MD5_STATE *md5state = NULL;
    sasl_secret_t *sec = NULL;

    if (errstr) {
	*errstr = NULL;
    }

    result = parseuser(sparams->utils, &user, &realm, sparams->user_realm,
		       sparams->serverFQDN, userstr);
    if (result != SASL_OK) {
	return result;
    }

    if ((flags & SASL_SET_DISABLE) || pass == NULL) {
	sec = NULL;
    } else {
	/* allocate the struct for the precalculation */
	md5state = (HMAC_MD5_STATE *) 
	    sparams->utils->malloc(sizeof(HMAC_MD5_STATE));
	if (md5state == NULL) {
	    result = SASL_NOMEM;
	    goto cleanup;
	}

	/* do the precalculation. this is what we're going to save to disk */
	sparams->utils->hmac_md5_precalc(md5state, /* OUT */
					 (const unsigned char *) pass,     /* IN */
					 passlen); /* IN */
	
	/* allocate a secret structure that we're going to save to disk */  
	sec=(sasl_secret_t *) sparams->utils->malloc(sizeof(sasl_secret_t)+
						     sizeof(HMAC_MD5_STATE));
	if (sec == NULL) {
	    result = SASL_NOMEM;
	    goto cleanup;
	}
      
	/* set the size */
	sec->len = sizeof(HMAC_MD5_STATE);
	/* and insert the data */
	memcpy(sec->data,md5state, sizeof(HMAC_MD5_STATE));
    }

    /* get the callback for saving to the password db */
    result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_PUTSECRET,
					 &putsecret,
					 &putsecret_context);
    if (result != SASL_OK) {
	goto cleanup;
    }

    /* do the store */
    result = putsecret(putsecret_context,
		       "CRAM-MD5", 
		       user,
		       realm,
		       sec);

    if (result != SASL_OK) {
	goto cleanup;
    }

    /* put entry in db to say we have at least one user */
    result = mechanism_fill_db("CRAM-MD5", sparams);

 cleanup:
    if (sec) {
	memset(sec, 0, sizeof(sasl_secret_t) + sizeof(HMAC_MD5_STATE));
	sparams->utils->free(sec);
    }
    if (md5state) {
	memset(md5state, 0, sizeof(md5state));
	sparams->utils->free(md5state);
    }
    if (user) 	sparams->utils->free(user);
    if (realm) 	sparams->utils->free(realm);
    return result;
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "CRAM-MD5",
    0,
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
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

int sasl_server_plug_init(sasl_utils_t *utils,
			  int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<CRAM_MD5_VERSION)
    return SASL_BADVERS;

  /* make sure there is a cram entry */

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=CRAM_MD5_VERSION;

  if ( mechanism_db_filled("CRAM-MD5",utils) != SASL_OK)
    return SASL_NOUSER;

  return SASL_OK;
}


static int c_start(void *glob_context __attribute__((unused)), 
		 sasl_client_params_t *params,
		 void **conn)
{
  context_t *text;

  /* holds state are in */
    text= params->utils->malloc(sizeof(context_t));
    if (text==NULL) return SASL_NOMEM;
    text->state=1;  
    text->authid=NULL;
    text->password=NULL;
    text->msgid=NULL;

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
    if ((*authid)==NULL) return SASL_NOMEM;

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
      if (! getauth_cb)
	  return SASL_FAIL;
      result = getauth_cb(getauth_context,
			  SASL_CB_AUTHNAME,
			  (const char **)&ptr,
			  NULL);
      if (result != SASL_OK)
	  return result;

      *authid=params->utils->malloc(strlen(ptr)+1);
      if ((*authid)==NULL) return SASL_NOMEM;
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
    (prompts)->challenge="Authentication Name";
    (prompts)->prompt="Please enter your authentication name";
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
  oparams->maxoutbuf=0; /* no clue what this should be */
  oparams->encode=NULL;
  oparams->decode=NULL;
  oparams->user=NULL;
  oparams->authid=NULL;
  oparams->realm=NULL;
  oparams->param_version=0;

  /* doesn't really matter how the server responds */

  if (text->state==1)
  {     
    sasl_security_properties_t secprops;
    unsigned int external;

    /*    text->msgid=params->utils->malloc(1);
    if (text->msgid==NULL) return SASL_NOMEM;
    text->msgidlen=0;

    text->msgid[0]='\0';*/

    if (clientout) {
	*clientout=NULL;
	*clientoutlen=0;
    }

    /* check if sec layer strong enough */
    secprops=params->props;
    external=params->external_ssf;

    if (secprops.min_ssf>0+external)
      return SASL_TOOWEAK;

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    char *in16;
    int auth_result=SASL_OK;
    int pass_result=SASL_OK;
    int maxsize;

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
    if (prompt_need) free_prompts(params,*prompt_need);

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

    in16=make_hashed(text->password,(char *) serverin, serverinlen, params);

    if (in16==NULL) return SASL_FAIL;

    VL(("authid=[%s]\n",text->authid));
    VL(("in16=[%s]\n",in16));

    maxsize=32+1+strlen(text->authid)+30;
    *clientout=params->utils->malloc(maxsize);
    if ((*clientout) == NULL) return SASL_NOMEM;

    snprintf((char *)*clientout,maxsize ,"%s %s",text->authid,in16);

    /* get rid of private information */
    free_string(params->utils, &in16);

    *clientoutlen=strlen(*clientout);

    /*nothing more to do; authenticated */
    oparams->doneflag=1;
    oparams->mech_ssf = 0;

    if (cram_strdup(params->utils, text->authid, &(oparams->authid), NULL)!=SASL_OK)
	return SASL_NOMEM;

    if (cram_strdup(params->utils, text->authid, &(oparams->user), NULL)!=SASL_OK)
	return SASL_NOMEM;

    VL(("clientout looks like=%s %i\n",*clientout,*clientoutlen));

    text->state++; /* fail if called again */

    return SASL_CONTINUE;
  }

  if (text->state == 3)
  {
      *clientout = NULL;
      *clientoutlen = 0;
      VL(("Verify we're done step"));
      text->state++;
      return SASL_OK;      
  }

  return SASL_FAIL; /* should never get here */
}

static const long client_required_prompts[] = {
  SASL_CB_AUTHNAME,
  SASL_CB_PASS,
  SASL_CB_LIST_END
};

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "CRAM-MD5",
    0,
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
    client_required_prompts,
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
