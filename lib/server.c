/* SASL server API implementation
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

/* local functions/structs don't start with sasl
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#ifdef WIN32
# include "winconfig.h"
#endif /* WIN32 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "sasl.h"
#include "saslint.h"
#include "saslutil.h"

#ifdef sun
/* gotta define gethostname ourselves on suns */
extern int gethostname(char *, int);
#endif


static int
external_server_new(void *glob_context __attribute__((unused)),
		    sasl_server_params_t *sparams,
		    const char *challenge __attribute__((unused)),
		    int challen __attribute__((unused)),
		    void **conn_context,
		    const char **errstr)
{
  if (!conn_context
      || !errstr
      || !sparams
      || !sparams->utils
      || !sparams->utils->conn)
    return SASL_BADPARAM;
  if (!sparams->utils->conn->external.auth_id)
    return SASL_NOMECH;
  *conn_context = NULL;
  *errstr = NULL;
  return SASL_OK;
}

static int
external_server_step(void *conn_context __attribute__((unused)),
		     sasl_server_params_t *sparams,
		     const char *clientin,
		     int clientinlen,
		     char **serverout,
		     int *serveroutlen,
		     sasl_out_params_t *oparams,
		     const char **errstr)
{
  int result;
  
  if (!sparams
      || !sparams->utils
      || !sparams->utils->conn
      || !sparams->utils->getcallback
      || !serverout
      || !serveroutlen
      || !oparams
      || !errstr)
    return SASL_BADPARAM;

  if (!sparams->utils->conn->external.auth_id)
    return SASL_BADPROT;
  
  if (! clientin) {
    /* No initial data; we're in a protocol which doesn't support it.
     * So we let the server app know that we need some... */
    *serverout = NULL;
    *serveroutlen = 0;
    return SASL_CONTINUE;
  }

  if (clientinlen		/* if we have a non-zero authorization id */
      && strcmp(clientin,	/* and it's not the same as the auth_id */
		sparams->utils->conn->external.auth_id)) {
    /* The user's trying to authorize as someone they didn't
     * authenticate as; we need to ask the application if this is
     * kosher. */
    int (*authorize_cb)(void *context,
			const char *auth_identity,
			const char *requested_user,
			char **user,
			const char **errstr);
    void *authorize_context;

    if ((sparams->utils->getcallback(sparams->utils->conn,
				     SASL_CB_PROXY_POLICY,
				     (int (**)()) &authorize_cb,
				     &authorize_context)
	 != SASL_OK)
	|| ! authorize_cb)
      return SASL_NOAUTHZ;

    if (authorize_cb(authorize_context,
		     sparams->utils->conn->external.auth_id,
		     clientin,
		     &oparams->user,
		     errstr)
	!= SASL_OK) {
      return SASL_NOAUTHZ;
    }
  } else {
    result = _sasl_strdup(sparams->utils->conn->external.auth_id,
			  &oparams->user,
			  NULL);
    if (result != SASL_OK)
      return result;
  }
  
  result = _sasl_strdup(sparams->utils->conn->external.auth_id,
			&oparams->authid,
			NULL);
  if (result != SASL_OK) {
    sasl_FREE(oparams->user);
    return result;
  }

  oparams->doneflag = 1;
  oparams->mech_ssf = 0;
  oparams->maxoutbuf = 0;
  oparams->encode_context = NULL;
  oparams->encode = NULL;
  oparams->getmic = NULL;
  oparams->decode_context = NULL;
  oparams->decode = NULL;
  oparams->verifymic = NULL;
  oparams->realm = NULL;
  oparams->param_version = 0;
  *errstr = NULL;

  return SASL_OK;
}

static const sasl_server_plug_t external_server_mech = {
  "EXTERNAL",			/* mech_name */
  0,				/* max_ssf */
  SASL_SEC_NOPLAINTEXT
  | SASL_SEC_NODICTIONARY,	/* security_flags */
  NULL,				/* glob_context */
  &external_server_new,		/* mech_new */
  &external_server_step,	/* mech_step */
  NULL,				/* mech_dispose */
  NULL,				/* mech_free */
  NULL,				/* setpass */
  NULL,				/* user_query */
  NULL				/* idle */
};

static int
external_server_init(sasl_utils_t *utils,
		     int max_version,
		     int *out_version,
		     const sasl_server_plug_t **pluglist,
		     int *plugcount)
{
  if (!utils || !out_version || !pluglist || !plugcount)
    return SASL_BADPARAM;
  if (max_version != SASL_SERVER_PLUG_VERSION)
    return SASL_BADVERS;
  *out_version = SASL_SERVER_PLUG_VERSION;
  *pluglist = &external_server_mech;
  *plugcount = 1;
  return SASL_OK;
}

typedef struct mechanism
{
  int version;
  const sasl_server_plug_t *plug;
  struct mechanism *next;
  void *library;
} mechanism_t;


typedef struct mech_list {
  sasl_utils_t *utils;  /* gotten from plug_init */

  void *mutex;            /* mutex for this data */ 
  mechanism_t *mech_list; /* list of mechanisms */
  int mech_length;       /* number of mechanisms */

} mech_list_t;

typedef struct sasl_server_conn {
  sasl_conn_t base; /* parts common to server + client */

  char *local_domain;
  char *user_domain;

  int authenticated;
  mechanism_t *mech; /* mechanism trying to use */
  /* data for mechanism to use so can "remember" challenge thing
   * for example kerberos sends a random integer
   */ 
  union mech_data  
  {
    int Idata;  
    double Fdata;  
    char *Sdata;  
  } mech_data_t;

  sasl_server_params_t *sparams;

} sasl_server_conn_t;

static mech_list_t *mechlist; /* global var which holds the list */

static sasl_global_callbacks_t global_callbacks;

/* Contains functions:
 * 
 * sasl_server_init
 * sasl_server_new
 * sasl_listmech
 * sasl_server_start
 * sasl_server_step
 * sasl_checkpass NTI
 * sasl_userexists NTI
 * sasl_setpass
 */

int sasl_setpass(sasl_conn_t *conn,
		 const char *user,
		 const char *pass,
		 unsigned passlen,
		 int flags,
		 const char **errstr)
{
  int result=SASL_OK, tmpresult;
  mechanism_t *m;

  /* XXX flag could be disable! */

  /* Zowie -- we have the user's plaintext password.
   * Let's tell all our mechanisms about it...
   */

  if (! conn || ! pass)
    return SASL_FAIL;

  if (! mechlist)		/* if haven't init'ed yet */
    return SASL_FAIL;

  VL(("Setting password for \"%s\" to \"%*s\" (len is %d)\n",
      user, passlen, pass, passlen));

  for (m = mechlist->mech_list;
       m;
       m = m->next)
    if (m->plug->setpass)
    {
      /* TODO: Log something if this fails */
      VL(("Setting it for mech %s\n", m->plug->mech_name));
      tmpresult=m->plug->setpass(m->plug->glob_context,
			   ((sasl_server_conn_t *)conn)->sparams,
			   user,
			   pass,
			   passlen,
			   flags,
			   errstr);
      if (tmpresult!=SASL_OK)
      {
	VL(("%s returned %i\n",m->plug->mech_name, tmpresult));
	result = SASL_FAIL;
      } else {
	VL(("%s suceeded!\n",m->plug->mech_name));
      }
    }

  return result;
}



/* local mechanism which disposes of server */
static void server_dispose(sasl_conn_t *pconn)
{
  sasl_server_conn_t *s_conn=  (sasl_server_conn_t *) pconn;

  if (s_conn->mech && s_conn->mech->plug->mech_dispose)
    s_conn->mech->plug->mech_dispose(s_conn->base.context,
				     s_conn->sparams->utils);

  if (s_conn->local_domain)
    sasl_FREE(s_conn->local_domain);

  if (s_conn->user_domain)
    sasl_FREE(s_conn->user_domain);

  _sasl_free_utils(&s_conn->sparams->utils);

  if (s_conn->sparams)
    sasl_FREE(s_conn->sparams);

  if (s_conn->base.oparams.credentials)
  {
    /* xxx    s_conn->mech->plug->dispose_credentials(s_conn->base.context,
       s_conn->base.oparams.credentials);*/
  }

  _sasl_conn_dispose(pconn);
}

static int init_mechlist(void)
{
  /* set util functions - need to do rest*/
  mechlist->utils=_sasl_alloc_utils(NULL, &global_callbacks);

  if (mechlist->utils==NULL)
    return SASL_NOMEM;

  return SASL_OK;
}

static int add_plugin(void *p, void *library) {
  int plugcount;
  const sasl_server_plug_t *pluglist;
  mechanism_t *mech;
  sasl_server_plug_init_t *entry_point;
  int result;
  int version;
  int lupe;

  entry_point = (sasl_server_plug_init_t *)p;

  result = entry_point(mechlist->utils, SASL_SERVER_PLUG_VERSION, &version,
		       &pluglist, &plugcount);
  if (version != SASL_SERVER_PLUG_VERSION)
  {
    VL(("Version mismatch\n"));
    result = SASL_FAIL;
  }
  if (result != SASL_OK)
  {
    VL(("entry_point error %i\n",result));
    return result;
  }

  for (lupe=0;lupe< plugcount ;lupe++)
    {
      mech = sasl_ALLOC(sizeof(mechanism_t));
      if (! mech) return SASL_NOMEM;

      mech->plug=pluglist++;
      mech->version = version;
      if (lupe==0)
	mech->library=library;
      else
	mech->library=NULL;
      mech->next = mechlist->mech_list;
      mechlist->mech_list = mech;

      mechlist->mech_length++;
    }

  return SASL_OK;
}

static void server_done(void) {
  mechanism_t *m;
  mechanism_t *prevm;
  m=mechlist->mech_list; /* m point to begging of the list */

  while (m!=NULL)
  {
    prevm=m;
    m=m->next;
    
    if (prevm->plug->glob_context!=NULL)
      sasl_FREE(prevm->plug->glob_context);
    if (prevm->library!=NULL)
      _sasl_done_with_plugin(prevm->library);
    sasl_FREE(prevm);    
  }
  _sasl_free_utils(&mechlist->utils);
  sasl_FREE(mechlist);
}

static int
server_idle(sasl_conn_t *conn)
{
  mechanism_t *m;
  if (! mechlist)
    return 0;

  for (m = mechlist->mech_list;
       m;
       m = m->next)
    if (m->plug->idle
	&&  m->plug->idle(m->plug->glob_context,
			  conn,
			  conn ? ((sasl_server_conn_t *)conn)->sparams : NULL))
      return 1;
  return 0;
}

int sasl_server_init(const sasl_callback_t *callbacks,
		     const char *appname)
{
  int ret;

  _sasl_server_cleanup_hook = &server_done;
  _sasl_server_idle_hook = &server_idle;

  _sasl_server_getsecret_hook = _sasl_db_getsecret;
  _sasl_server_putsecret_hook = _sasl_db_putsecret;

  global_callbacks.callbacks = callbacks;
  global_callbacks.appname = appname;

  mechlist=sasl_ALLOC(sizeof(mech_list_t));
  if (mechlist==NULL) return SASL_NOMEM;

  /* load plugins */
  ret=init_mechlist();
  if (ret!=SASL_OK)
    return ret;
  mechlist->mech_list=NULL;
  mechlist->mech_length=0;

  add_plugin((void *)&external_server_init, NULL);

  ret=_sasl_get_mech_list("sasl_server_plug_init",
			  _sasl_find_getpath_callback(callbacks),
			  &add_plugin);

  return ret;
}

static int
_sasl_transition(sasl_conn_t * conn,
		 const char * pass,
		 int passlen)
{
  int result = 0;
  mechanism_t *m;

  /* Zowie -- we have the user's plaintext password.
   * Let's tell all our mechanisms about it...
   */

  if (! conn || ! pass)
    return SASL_FAIL;

  if (! mechlist)		/* *shouldn't* ever happen... */
    return SASL_FAIL;

  if (! conn->oparams.authid)
    return SASL_NOTDONE;

  for (m = mechlist->mech_list;
       m;
       m = m->next)
    if (m->plug->setpass)
      /* TODO: Log something if this fails */
      if (m->plug->setpass(m->plug->glob_context,
			   ((sasl_server_conn_t *)conn)->sparams,
			   conn->oparams.authid,
			   pass,
			   passlen,
			   0,
			   NULL) == SASL_OK)
	result = 1;
  return result;
}

int sasl_server_new(const char *service,
		    const char *local_domain,
		    const char *user_domain,
		    const sasl_callback_t *callbacks,
		    int secflags,
		    sasl_conn_t **pconn)
{
  int result;
  sasl_server_conn_t *serverconn;

  if (! pconn) return SASL_FAIL;
  if (! service) return SASL_FAIL;

  *pconn=sasl_ALLOC(sizeof(sasl_server_conn_t));
  if (*pconn==NULL) return SASL_NOMEM;

  (*pconn)->destroy_conn = &server_dispose;
  result = _sasl_conn_init(*pconn, service, secflags,
			   &server_idle, callbacks, &global_callbacks);
  if (result != SASL_OK) return result;

  serverconn = (sasl_server_conn_t *)*pconn;

  serverconn->mech = NULL;

  /* make sparams */
  serverconn->sparams=sasl_ALLOC(sizeof(sasl_server_params_t));
  if (serverconn->sparams==NULL) return SASL_NOMEM;

  /* set util functions - need to do rest*/
  serverconn->sparams->utils=_sasl_alloc_utils(*pconn, &global_callbacks);
  if (serverconn->sparams->utils==NULL)
    return SASL_NOMEM;

  serverconn->sparams->transition = &_sasl_transition;

  serverconn->sparams->props = serverconn->base.props;

  if (local_domain==NULL) {
    char name[MAXHOSTNAMELEN];
    memset(name, 0, sizeof(name));
    gethostname(name, MAXHOSTNAMELEN);
#ifdef HAVE_GETDOMAINNAME
    {
      char *dot = strchr(name, '.');
      if (! dot) {
	size_t namelen = strlen(name);
	name[namelen] = '.';
	getdomainname(name + namelen + 1, MAXHOSTNAMELEN - namelen - 1);
      }
    }
#endif /* HAVE_GETDOMAINNAME */
    result = _sasl_strdup(name, &serverconn->local_domain, NULL);
    if (result != SASL_OK) goto cleanup_conn;
  } else {
    result = _sasl_strdup(local_domain, &serverconn->local_domain, NULL);
    if (result != SASL_OK) goto cleanup_conn;
  }


  /* set some variables */

  if (user_domain==NULL)
    serverconn->user_domain=NULL;
  else {
    result = _sasl_strdup(user_domain, &serverconn->user_domain, NULL);
    if (result != SASL_OK) goto cleanup_localdomain;
  }

  return result;

cleanup_localdomain:
  sasl_FREE(serverconn->local_domain);

cleanup_conn:
  _sasl_conn_dispose(*pconn);
  sasl_FREE(*pconn);
  *pconn = NULL;
  return result;
}

static int mech_permitted(sasl_conn_t *conn,
			  const sasl_server_plug_t *plug)
{
  /* Can this plugin meet the application's security requirements? */
  if (! plug || ! conn)
    return 0;
  if (plug == &external_server_mech) {
    /* Special case for the external mechanism */
    if (conn->props.min_ssf < conn->external.ssf
	|| ! conn->external.auth_id)
      return 0;
  } else {
    /* Generic mechanism */
    if (plug->max_ssf < conn->props.min_ssf)
      return 0;
  }
  return 1;
}

int sasl_server_start(sasl_conn_t *conn,
		      const char *mech,
		      const char *clientin,
		      unsigned clientinlen,
		      char **serverout,
		      unsigned *serveroutlen,
		      const char **errstr)
{
  sasl_server_conn_t *s_conn=(sasl_server_conn_t *) conn;
  int result;

  /* make sure mech is valid mechanism
     if not return appropriate error */
  mechanism_t *m;
  m=mechlist->mech_list;

  if (errstr)
    *errstr = NULL;

  while (m!=NULL)
  {
    if ( strcasecmp(mech,m->plug->mech_name)==0)
    {
      break;
    }
    m=m->next;
  }
  
  if (m==NULL)
    return SASL_NOMECH;

  /* Make sure that we're willing to use this mech */
  if (! mech_permitted(conn, m->plug))
    return SASL_NOMECH;

  s_conn->mech=m;

  /* call the security layer given by mech */
  s_conn->sparams->local_domain=s_conn->local_domain;
  s_conn->sparams->service=conn->service;
  s_conn->sparams->user_domain=s_conn->user_domain;

  s_conn->mech->plug->mech_new(s_conn->mech->plug->glob_context,
			       s_conn->sparams,
			       NULL,
			       0,
			       &(conn->context),
			       errstr);


  result = s_conn->mech->plug->mech_step(conn->context,
				       s_conn->sparams,
				       clientin,
				       clientinlen,
				       serverout,
				       (int *) serveroutlen,
				       &conn->oparams,
				       errstr);
			     
  /* if returns SASL_OK check to make sure
   * is valid username and then
   * correct password using sasl_checkpass XXXXX
   */
  if (result == SASL_OK) {
    if (conn->oparams.user)
      sasl_setprop(conn, SASL_USERNAME, conn->oparams.user);
  }

  return result;
}

int sasl_server_step(sasl_conn_t *conn,
		     const char *clientin,
		     unsigned clientinlen,
		     char **serverout,
		     unsigned *serveroutlen,
		     const char **errstr)
{
  int result;
  sasl_server_conn_t *s_conn;
  s_conn= (sasl_server_conn_t *) conn;

  if (errstr)
    *errstr = NULL;

  result = s_conn->mech->plug->mech_step(conn->context,
					 s_conn->sparams,
					 clientin,
					 clientinlen,
					 serverout,
					 (int *) serveroutlen,
					 &conn->oparams,
					 errstr);

  if (result == SASL_OK) {
    if (conn->oparams.user)
      sasl_setprop(conn, SASL_USERNAME, conn->oparams.user);
  }

  return result;
  /* if returns SASL_OK check to make sure
   * is valid username and then
   * correct password using sasl_checkpass
   */
}


static unsigned mech_names_len()
{
  mechanism_t *listptr;
  unsigned result = 0;

  for (listptr = mechlist->mech_list;
       listptr;
       listptr = listptr->next)
    result += strlen(listptr->plug->mech_name);

  return result;
}

int sasl_listmech(sasl_conn_t *conn,
		  const char *user __attribute__((unused)),
		  const char *prefix,
		  const char *sep,
		  const char *suffix,
		  char **result,
		  unsigned *plen,
		  unsigned *pcount)
{
  int lup;
  mechanism_t *listptr;  
  int resultlen;

  if (! conn || ! result)
    return SASL_FAIL;

  if (plen!=NULL)
    *plen=0;
  if (pcount!=NULL)
    *pcount=0;

  if (! mechlist)
    return SASL_FAIL;

  if (mechlist->mech_length<=0)
    return SASL_NOMECH;

  resultlen = (prefix ? strlen(prefix) : 0)
            + (sep ? strlen(sep) : 1) * (mechlist->mech_length - 1)
	    + mech_names_len()
            + (suffix ? strlen(suffix) : 0)
	    + 1;
  *result=sasl_ALLOC(resultlen);
  if ((*result)==NULL) return SASL_NOMEM;

  if (prefix)
    strcpy (*result,prefix);
  else
    **result = '\0';

  listptr=mechlist->mech_list;  
   
  /* make list */
  for (lup=0;lup<mechlist->mech_length;lup++)
  {
    /* if user has rights add to list */
    /* XXX This should be done with a callback function */
    if (mech_permitted(conn, listptr->plug))
    {
      strcat(*result,listptr->plug->mech_name);
      if (pcount!=NULL)
	(*pcount)++;

      if (listptr->next!=NULL)
      {
	if (sep)
	  strcat(*result,sep);
	else
	  strcat(*result," ");
      }

    }

    listptr=listptr->next;
  }

  if (suffix)
    strcat(*result,suffix);

  if (plen!=NULL)
    *plen=resultlen - 1;	/* one for the null */

  return SASL_OK;
  
}

