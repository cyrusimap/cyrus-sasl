/* Plain SASL plugin
 * Tim Martin 
 * $Id: plain.c,v 1.9 1998/12/09 06:56:11 tmartin Exp $
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
#if HAVE_UNISTD_H
# include <sys/types.h>
# include <unistd.h>
#endif
#if STDC_HEADERS
# include <string.h>
#else
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
char *strchr(), *strrchr();
# ifndef HAVE_MEMCPY
#  define memcpy(d, s, n) bcopy ((s), (d), (n))
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# endif
#endif
#include <sasl.h>
#include <saslplug.h>

#ifdef WIN32
/* This must be after sasl.h */
# include "saslPLAIN.h"
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define PLAIN_VERSION 2;

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


static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (text->userid)
    utils->free(text->userid);
  if (text->authid)
    utils->free(text->authid);
  if (text->password) {
    memset(text->password->data,
	   0,
	   text->password->len);
    utils->free(text->password);
  }
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
static int verify_password(const char *userid,
			   const char *password)
{
  struct passwd *pwd;
  char *salt;
  char *crypted;

  pwd=getpwnam(userid);
  if (pwd==NULL) return SASL_NOUSER;

  salt = pwd->pw_passwd;

  crypted=(char *) crypt(password, salt);

  if (strcmp(crypted, pwd->pw_passwd)!=0)
    return SASL_BADAUTH;

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
    result=verify_password(authen,
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
      params->transition(params->utils->conn,
			 password, password_len);

    *serverout = params->utils->malloc(1);
    if (! *serverout) return SASL_NOMEM;
    **serverout = '\0';
    *serveroutlen = 0;

    text->state++; /* so fails if called again */

    return -199; /*SASL_OK;*/
  }

  return -93;

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
    NULL
  }
};

int sasl_server_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<1)
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
  unsigned len;

  printf("in plain!\n");

  text=conn_context;

  /* doesn't really matter how the server responds */

  if (text->state==1)
  {
    /* check if sec layer strong enough */
    if (params->props.min_ssf>0)
      return SASL_TOOWEAK;

    if (! text->userid) {
      /* need to get the userid */
      sasl_getsimple_t *getit;
      void *context;

      if (*prompt_need
	  && (*prompt_need)->id == SASL_CB_USER) {
	/* We prompted, and got.*/
	size_t len;
	if (! (*prompt_need)->result)
	  return SASL_FAIL;
	len = strlen((*prompt_need)->result);
	text->userid = params->utils->malloc(len + 1);
	if (! text->userid)
	  return SASL_NOMEM;
	strcpy(text->userid, (*prompt_need)->result);
	free(*prompt_need);
	*prompt_need = NULL;
      } else {
	const char *userid;
	if (params->utils->getcallback(params->utils->conn,
				       SASL_CB_USER,
				       &getit,
				       &context) != SASL_OK) {
	  /* We weren't able to get the userid; let's try a SASL_INTERACT */
	  *prompt_need=params->utils->malloc(sizeof(sasl_interact_t));
	  if ((*prompt_need) ==NULL) return SASL_NOMEM;
	  (*prompt_need)->id=SASL_CB_USER;
	  (*prompt_need)->challenge="User Id";
	  (*prompt_need)->prompt="Please enter your user id";
	  (*prompt_need)->defresult=getenv("USER");
	  return SASL_INTERACT;
	}
	result = getit(context, SASL_CB_USER, &userid, &len);
	if (result != SASL_OK)
	  return result;
	text->userid = params->utils->malloc(strlen(userid) + 1);
	if (! text->userid)
	  return SASL_NOMEM;
	strcpy(text->userid, userid);
      }
    }

    if (! text->authid) {
      /* need to get the password */
      sasl_getsimple_t *getit;
      void *context;

      if (*prompt_need
	  && (*prompt_need)->id == SASL_CB_AUTHNAME) {
	/* We prompted, and got.*/
	size_t len;
	if (! (*prompt_need)->result)
	  return SASL_FAIL;
	len = strlen((*prompt_need)->result);
	text->authid = params->utils->malloc(len + 1);
	printf("trying to allocate %i\n",len+1);
	if (! text->authid)
	  return SASL_NOMEM;
	strcpy(text->authid, (*prompt_need)->result);
	free(*prompt_need);
	*prompt_need = NULL;
      } else {
	const char *authid;
	if (params->utils->getcallback(params->utils->conn,
				       SASL_CB_AUTHNAME,
				       &getit,
				       &context) != SASL_OK) {
	  /* We weren't able to get the authid; let's try a SASL_INTERACT */
	  *prompt_need=params->utils->malloc(sizeof(sasl_interact_t));
	  if ((*prompt_need) ==NULL) return SASL_NOMEM;
	  (*prompt_need)->id=SASL_CB_AUTHNAME;
	  (*prompt_need)->challenge="Authentication Id";
	  (*prompt_need)->prompt="Please enter your authentication id";
	  (*prompt_need)->defresult=getenv("USER");
	  return SASL_INTERACT;
	}
	result = getit(context, SASL_CB_AUTHNAME, &authid, &len);
	if (result != SASL_OK)
	  return result;
	text->authid = params->utils->malloc(strlen(authid) + 1);
	if (! text->authid)
	  return SASL_NOMEM;
	strcpy(text->authid, authid);
      }
    }
    printf("password!\n");
    if (! text->password) {
      /* need to get the password */
      sasl_getsecret_t *getit;
      void *context;
      

      if (*prompt_need
	  && (*prompt_need)->id == SASL_CB_PASS) {
	/* We prompted, and got.*/
	char *passstr;
	int passlen;
	
	if (! (*prompt_need)->result)
	  return SASL_FAIL;
	printf("fsdf\n");
	passstr = (char *) (*prompt_need)->result; 
	printf("fsdf\n");
	passlen = (*prompt_need)->len;

	text->password = (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t)+
								 passlen+1);

	if (! text->password)
	  return SASL_NOMEM;
	text->password->len = passlen;
	memcpy(text->password->data, passstr, passlen);
	memset(passstr, 0, passlen);
	free(*prompt_need);
	*prompt_need = NULL;
      } else {
	printf("making callback\n");
	if (params->utils->getcallback(params->utils->conn,
				       SASL_CB_PASS,
				       &getit,
				       &context) != SASL_OK) {
	  /* We weren't able to get the callback; let's try a SASL_INTERACT */
	  *prompt_need=params->utils->malloc(sizeof(sasl_interact_t));
	  if ((*prompt_need) ==NULL) return SASL_NOMEM;
	  (*prompt_need)->id=SASL_CB_PASS;
	  (*prompt_need)->challenge="Password";
	  (*prompt_need)->prompt="Please enter your password";
	  (*prompt_need)->defresult=NULL;
	  return SASL_INTERACT;
	}
	result = getit(params->utils->conn, context, SASL_CB_PASS,
		       &text->password);
	if (result != SASL_OK)
	  return result;
      }
    }

    /* send authorized id NUL authentication id NUL password */
    {
      size_t userid_len, authid_len;

      if (strcmp(text->userid, text->authid))
	userid_len = strlen(text->userid);
      else
	userid_len = 0;
      authid_len = strlen(text->authid);

      *clientoutlen = (userid_len + 1
		       + authid_len + 1
		       + text->password->len);
      *clientout=params->utils->malloc(*clientoutlen);
      if (! *clientout) return SASL_NOMEM;
      memset(*clientout, 0, *clientoutlen);

      printf("userid=[%s]\n",text->userid);
      printf("userid=[%s]\n",text->authid);
      printf("userid=[%s]\n",text->password->data);

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

    text->state++; /* so fail next time */

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "PLAIN",
    0,
    0,
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
  if (maxversion<1)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=PLAIN_VERSION;

  return SASL_OK;
}
