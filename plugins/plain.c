/* Plain SASL plugin
 * Tim Martin 
 * $Id: plain.c,v 1.4 1998/11/17 19:28:47 rob Exp $
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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <pwd.h>
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

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define PLAIN_VERSION 2;

typedef struct context {
  int state;
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

  *conn=text;

  return SASL_OK;
}


static void dispose(void *conn_context, sasl_utils_t *utils)
{
  utils->free(conn_context);
}

static void mech_free(void *global_context, sasl_utils_t *utils)
{
  utils->free(global_context);  
}

/* fills in password  remember to free password and wipe it out correctly */
static int verify_password(char *userid,
			   int useridlen,
			   sasl_utils_t *utils,
			   char *password)
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

static int server_continue_step (void *conn_context,
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

  oparams->maxoutbuf=1024; /* no clue what this should be */
  
  oparams->encode=NULL;
  oparams->decode=NULL;

  oparams->user="anonymous"; /* set username */
  oparams->authid="anonymous";

  oparams->realm=NULL;
  oparams->param_version=0;

  /*nothing more to do; authenticated */
  oparams->doneflag=1;

  if (text->state==1)
  {
    char author[64];
    char authen[64];
    int authen_len;
    char password[64];
    int password_len;
    int pos=0;
    int lup=0;
    char *mem;
    int result;
    /* should have received author-id NUL authen-id NUL password */

    memset(author,   0, 64);
    memset(authen,   0, 64);
    memset(password, 0, 64);

    /* get author */
    while ((lup<clientinlen) && (clientin[lup]!=0))
    {
      author[pos]=clientin[lup];
      pos++;
      lup++;
    }
    if (lup==clientinlen) return SASL_FAIL;      

    /* get authen */
    lup++;
    pos=0;
    while ((lup<clientinlen) && (clientin[lup]!=0))
    {
      authen[pos]=clientin[lup];
      lup++;
      pos++;
    }
    if (lup==clientinlen) return SASL_FAIL;      
    authen_len=pos;

    /* get password */
    lup++;
    pos=0;
    while ((lup<clientinlen) && (clientin[lup]!=0))
    {
      password[pos]=clientin[lup];
      lup++;
      pos++;
    }
    password_len=pos;

    memcpy(password, clientin+lup, clientinlen-lup);

    /* verify password - return sasl_ok on success*/    
    result=verify_password(authen,
			   authen_len,
			   params->utils,
			   password);
    if (result!=SASL_OK) return result;

    mem = params->utils->malloc(authen_len + 1);
    if (! mem) return SASL_NOMEM;
    memcpy(mem, authen, authen_len);
    oparams->user = mem;

    mem = params->utils->malloc(authen_len + 1);
    if (! mem) return SASL_NOMEM;
    memcpy(mem, authen, authen_len);
    oparams->authid = mem;

    if (params->transition)
      params->transition(params->utils->conn,
			 authen,
			 authen_len);

    *serverout = params->utils->malloc(1);
    if (! *serverout) return SASL_NOMEM;
    **serverout = '\0';
    *serveroutlen = 0;

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

const sasl_server_plug_t plugins[] = 
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

int sasl_server_plug_init(sasl_utils_t *utils, int maxversion,
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
static int c_start(void *glob_context, 
		 sasl_client_params_t *params,
		 void **conn)
{
  context_t *text;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;  
  *conn=text;

  return SASL_OK;
}

static int client_continue_step (void *conn_context,
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



  /* doesn't really matter how the server responds */

  if (text->state==1)
  {
    char *authorid="";
    int author_len=0;
    char *authenid;
    int authen_len;
    char *password;
    int password_len;


    /* check if sec layer strong enough */
    if (params->props.min_ssf>0)
      return SASL_TOOWEAK;


    /* need to prompt for password */
    if (*prompt_need==NULL)
    {
      *prompt_need=params->utils->malloc(sizeof(sasl_interact_t));
      if ((*prompt_need) ==NULL) return SASL_NOMEM;
      (*prompt_need)->id=1;
      (*prompt_need)->challenge="password";
      (*prompt_need)->prompt="Please enter your password";
      (*prompt_need)->defresult="a";

      return SASL_INTERACT;
    }

    password_len=(*prompt_need)->len;
    password=params->utils->malloc(password_len);
    if (password==NULL) return SASL_NOMEM;
    memcpy(password, (*prompt_need)->result, password_len);

    params->utils->free((void *) (*prompt_need)->result);
    params->utils->free((*prompt_need));


    /* send authorized id NUL authentication id NUL password */

    params->utils->getprop(params->utils->conn, SASL_USERNAME, (void **)&authenid);
    authen_len=strlen(authenid);

    *clientoutlen= authen_len + 1 +author_len + 1 + password_len;
    *clientout=params->utils->malloc( *clientoutlen);
    if (! *clientout) return SASL_NOMEM;
    memset(*clientout, 0, *clientoutlen);

    memcpy(*clientout, authorid, author_len);
    memcpy(*clientout+author_len+1, authenid, authen_len);
    memcpy(*clientout+author_len+authen_len+2, password, password_len);

    params->utils->free(password);

    /* set oparams */
    oparams->mech_ssf=1;
    oparams->maxoutbuf=1024; /* no clue what this should be */
    oparams->encode=NULL;
    oparams->decode=NULL;
    oparams->user="anonymous"; /* set username */
    oparams->authid="anonymous";
    oparams->realm=NULL;
    oparams->param_version=0;

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

const sasl_client_plug_t client_plugins[] = 
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

int sasl_client_plug_init(sasl_utils_t *utils, int maxversion,
			  int *out_version, const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<1)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=PLAIN_VERSION;

  return SASL_OK;
}
