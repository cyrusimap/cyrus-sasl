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
#include <config.h>
#include <errno.h>
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

#ifndef PATH_MAX
# ifdef _POSIX_PATH_MAX
#  define PATH_MAX _POSIX_PATH_MAX
# else
#  define PATH_MAX 1024		/* arbitrary; probably big enough */
# endif
#endif

/* Contains functions:
 * 
 * sasl_server_init
 * sasl_server_new
 * sasl_listmech
 * sasl_server_start
 * sasl_server_step
 * sasl_checkpass
 * sasl_userexists <= not yet implemented
 * sasl_setpass
 */


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
  NULL,				/* idle */
  NULL,				/* install_credentials */
  NULL,				/* uninstall_credentials */
  NULL				/* dispose_credentials */
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
  void *library; /* this a pointer to shared library returned by dlopen 
		    or some similar function on other platforms */
} mechanism_t;


typedef struct mech_list {
  sasl_utils_t *utils;  /* gotten from plug_init */

  void *mutex;            /* mutex for this data */ 
  mechanism_t *mech_list; /* list of mechanisms */
  int mech_length;       /* number of mechanisms */

} mech_list_t;

typedef struct sasl_server_conn {
  sasl_conn_t base; /* parts common to server + client */

  char *user_realm; /* domain the user authenticating is in This is
		      * usually simply their hostname */

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


/* set the password for a user
 *  conn        -- SASL connection
 *  user        -- user name
 *  pass        -- plaintext password, may be NULL to remove user
 *  passlen     -- length of password, 0 = strlen(pass)
 *  flags       -- see flags below
 *  errstr      -- optional more detailed error
 * 
 * returns:
 *  SASL_NOCHANGE  -- proper entry already exists
 *  SASL_NOMECH    -- no authdb supports password setting as configured
 *  SASL_DISABLED  -- account disabled
 *  SASL_PWLOCK    -- password locked
 *  SASL_FAIL      -- OS error
 *  SASL_BADPARAM  -- password too long
 *  SASL_OK        -- successful
 */

int sasl_setpass(sasl_conn_t *conn,
		 const char *user,
		 const char *pass,
		 unsigned passlen,
		 int flags,
		 const char **errstr)
{
  int result=SASL_OK, tmpresult;
  sasl_server_conn_t *s_conn=  (sasl_server_conn_t *) conn;
  mechanism_t *m;

  /* Zowie -- we have the user's plaintext password.
   * Let's tell all our mechanisms about it...
   */

  if (! conn || ! pass)
    return SASL_FAIL;

  if (! mechlist)		/* if haven't init'ed yet */
    return SASL_FAIL;

  VL(("Setting password for \"%s\" to \"%*s\" (len is %d)\n",
      user, passlen, pass, passlen));

  /* copy info into sparams */
  s_conn->sparams->serverFQDN=conn->serverFQDN;
  s_conn->sparams->service=conn->service;
  s_conn->sparams->user_realm=s_conn->user_realm;

  _sasl_log(conn,
	    SASL_LOG_WARNING,
	    NULL,
	    0, 0,
	    "Updating secrets for %s",
	    user);

  for (m = mechlist->mech_list;
       m;
       m = m->next)
    if (m->plug->setpass)
    {
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
	_sasl_log(conn,
		  SASL_LOG_WARNING,
		  m->plug->mech_name,
		  tmpresult, errno,
		  "Failed to set secret for %s: %z",
		  user);
      } else {
	VL(("%s succeeded!\n",m->plug->mech_name));
	_sasl_log(conn,
		 SASL_LOG_WARNING,
		  m->plug->mech_name,
		  0, 0,
		  "Set secret for %s",
		  user);
      }
    }

  return result;
}



/* local mechanism which disposes of server */
static void server_dispose(sasl_conn_t *pconn)
{
  sasl_server_conn_t *s_conn=  (sasl_server_conn_t *) pconn;

  if (pconn->oparams.credentials) {
    if (s_conn->mech
	&& s_conn->mech->plug->dispose_credentials)
      s_conn->mech->plug->dispose_credentials(pconn->context,
					      pconn->oparams.credentials);
    else
      sasl_FREE(pconn->oparams.credentials);
  }
  
  if (s_conn->mech
      && s_conn->mech->plug->mech_dispose)
    s_conn->mech->plug->mech_dispose(pconn->context,
				     s_conn->sparams->utils);

  if (s_conn->user_realm)
    sasl_FREE(s_conn->user_realm);

  _sasl_free_utils(&s_conn->sparams->utils);

  if (s_conn->sparams)
    sasl_FREE(s_conn->sparams);

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

/*
 * parameters:
 *  p - entry point
 *  library - shared library ptr returned by dlopen
 */
static int add_plugin(void *p, void *library) {
  int plugcount;
  const sasl_server_plug_t *pluglist;
  mechanism_t *mech;
  sasl_server_plug_init_t *entry_point;
  int result;
  int version;
  int lupe;

  entry_point = (sasl_server_plug_init_t *)p;

  /* call into the shared library asking for information about it */
  /* version is filled in with the version of the plugin */
  result = entry_point(mechlist->utils, SASL_SERVER_PLUG_VERSION, &version,
		       &pluglist, &plugcount);

  if (result != SASL_OK)
  {
    VL(("entry_point error %i\n",result));
    return result;
  }

  /* Make sure plugin is using the same SASL version as us */
  if (version > SASL_SERVER_PLUG_VERSION)
  {
    VL(("Version mismatch\n"));
    result = SASL_FAIL;
  }

  for (lupe=0;lupe < plugcount ;lupe++)
    {
      mech = sasl_ALLOC(sizeof(mechanism_t));
      if (! mech) return SASL_NOMEM;

      mech->plug=pluglist++;
      mech->version = version;

      /*
       * We want plugin library to close but we only
       * want to do this once per plugin regardless
       * of how many mechs are in a single plugin 
       */
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
       m!=NULL;
       m = m->next)
    if (m->plug->idle
	&&  m->plug->idle(m->plug->glob_context,
			  conn,
			  conn ? ((sasl_server_conn_t *)conn)->sparams : NULL))
      return 1;
  return 0;
}

static int load_config(const sasl_callback_t *verifyfile_cb)
{
  int result;
  char *path_to_config=NULL;
  char *config_filename=NULL;
  int len;
  const sasl_callback_t *getpath_cb=NULL;

  /* get the path to the plugins; for now the config file will reside there */
  getpath_cb=_sasl_find_getpath_callback( global_callbacks.callbacks );
  if (getpath_cb==NULL) return SASL_BADPARAM;

  /* getpath_cb->proc MUST be a sasl_getpath_t; if only c had a type
     system */
  result = ((sasl_getpath_t *)(getpath_cb->proc))(getpath_cb->context,
						  &path_to_config);
  if (result!=SASL_OK) return result;


  /* length = length of path + '/' + length of appname + ".conf" + 1
     for '\0' */
  len = strlen(path_to_config)+2+ strlen(global_callbacks.appname)+5+1;

  if (len > PATH_MAX ) return SASL_FAIL;

  /* construct the filename for the config file */
  config_filename = sasl_ALLOC(len);
  if (! config_filename) return SASL_NOMEM; 

  strcpy(config_filename, path_to_config);
  strcat(config_filename,"/");
  strcat(config_filename, global_callbacks.appname);
  strcat(config_filename, ".conf");


  /* Ask the application if it's safe to use this file */
  result = ((sasl_verifyfile_t *)(verifyfile_cb->proc))(verifyfile_cb->context,
							config_filename);	  
  /* returns continue if this file is to be skipped */
  
  /* returns SASL_CONTINUE if doesn't exist
   * if doesn't exist we can continue using default behavior
   */
  if (result==SASL_OK)
    result=sasl_config_init(config_filename);

  sasl_FREE(config_filename);

  return result;
}

/* initialize server drivers, done once per process
 *  callbacks      -- base callbacks for all server connections
 *  appname        -- name of calling application (for lower level logging)
 * results:
 *  state          -- server state
 * returns:
 *  SASL_OK        -- success
 *  SASL_BADPARAM  -- error in config file
 *  SASL_NOMEM     -- memory failure
 *  SASL_BADVERS   -- Mechanism version mismatch
 */

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

  /* load config file if applicable */
  ret=load_config(_sasl_find_verifyfile_callback(callbacks));
  if ((ret!=SASL_OK) && (ret!=SASL_CONTINUE)) return ret;

  /* load plugins */
  ret=init_mechlist();
  if (ret!=SASL_OK)
    return ret;
  mechlist->mech_list=NULL;
  mechlist->mech_length=0;

  add_plugin((void *)&external_server_init, NULL);

  ret=_sasl_get_mech_list("sasl_server_plug_init",
			  _sasl_find_getpath_callback(callbacks),
			  _sasl_find_verifyfile_callback(callbacks),
			  &add_plugin);

  return ret;
}

/*
 * Once we have the users plaintext password we 
 * may want to transition them. That is put entries
 * for them in the passwd database for other
 * stronger mechanism
 *
 * for example PLAIN -> CRAM-MD5
 */

static int
_sasl_transition(sasl_conn_t * conn,
		 const char * pass,
		 int passlen)
{
  if (! conn)
    return SASL_BADPARAM;

  if (! conn->oparams.authid)
    return SASL_NOTDONE;

  /* check if this is enabled: default to false */
  /*  if (sasl_config_getswitch("Transition",0)==0) return SASL_OK;*/

  return sasl_setpass(conn,
		      conn->oparams.authid,
		      pass,
		      passlen,
		      0,
		      NULL);
}


/* create context for a single SASL connection
 *  service        -- registered name of the service using SASL (e.g. "imap")
 *  serverFQDN     -- Fully qualified server domain name.  NULL means use
 *                    gethostbyname().  Useful for multi-homed servers.
 *  user_realm     -- permits multiple user domains on server, NULL = default
 *  callbacks      -- callbacks (e.g., authorization, lang, new getopt context)
 *  secflags       -- security flags (see above)
 * returns:
 *  pconn          -- new connection context
 *
 * returns:
 *  SASL_OK        -- success
 *  SASL_NOMEM     -- not enough memory
 */

int sasl_server_new(const char *service,
		    const char *serverFQDN,
		    const char *user_realm,
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
			   &server_idle,
			   serverFQDN,
			   callbacks, &global_callbacks);
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

  /* set some variables */
  if (user_realm==NULL)
    serverconn->user_realm=NULL;
  else {
    result = _sasl_strdup(user_realm, &serverconn->user_realm, NULL);
  }

  if (result!=SASL_OK)
  {
    _sasl_conn_dispose(*pconn);
    sasl_FREE(*pconn);
    *pconn = NULL;
  }

  return result;
}

/*
 * The rule is:
 * IF mech strength + external strength < min ssf THEN FAIL
 */

static int mech_permitted(sasl_conn_t *conn,
			  const sasl_server_plug_t *plug)
{
  /* Can this plugin meet the application's security requirements? */
  if (! plug || ! conn)
    return 0;
  if (plug == &external_server_mech) {
    /* Special case for the external mechanism */
    if (conn->props.min_ssf > conn->external.ssf
	|| ! conn->external.auth_id)
      return 0;
  } else {
    /* Generic mechanism */
    if (plug->max_ssf < conn->props.min_ssf)
      return 0;
  }
  return 1;
}

/* start a mechanism exchange within a connection context
 *  mech           -- the mechanism name client requested
 *  clientin       -- client initial response, NULL if empty
 *  clientinlen    -- length of initial response
 *  serverout      -- initial server challenge, NULL if done
 *  serveroutlen   -- length of initial server challenge
 * output:
 *  pconn          -- the connection negotiation state on success
 *  errstr         -- set to string to send to user on failure
 *
 * Same returns as sasl_server_step()
 */

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

  /* check parameters */
  if ((mech==NULL)    ||
      ((clientin==NULL) && (clientinlen>0)))
    return SASL_BADPARAM;

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
  s_conn->sparams->serverFQDN=conn->serverFQDN;
  s_conn->sparams->service=conn->service;
  s_conn->sparams->user_realm=s_conn->user_realm;
  s_conn->sparams->props=conn->props;

  result = s_conn->mech->plug->mech_new(s_conn->mech->plug->glob_context,
					s_conn->sparams,
					NULL,
					0,
					&(conn->context),
					errstr);
  if (result != SASL_OK)
    return result;

  return s_conn->mech->plug->mech_step(conn->context,
				       s_conn->sparams,
				       clientin,
				       clientinlen,
				       serverout,
				       (int *) serveroutlen,
				       &conn->oparams,
				       errstr);
}


/* perform one step of the SASL exchange
 *  inputlen & input -- client data
 *                      NULL on first step if no optional client step
 *  outputlen & output -- set to the server data to transmit
 *                        to the client in the next step
 *  errstr           -- set to a more text error message from
 *                    a lower level mechanism on failure
 *
 * returns:
 *  SASL_OK        -- exchange is complete.
 *  SASL_CONTINUE  -- indicates another step is necessary.
 *  SASL_TRANS     -- entry for user exists, but not for mechanism
 *                    and transition is possible
 *  SASL_BADPARAM  -- service name needed
 *  SASL_BADPROT   -- invalid input from client
 *  ...
 */

int sasl_server_step(sasl_conn_t *conn,
		     const char *clientin,
		     unsigned clientinlen,
		     char **serverout,
		     unsigned *serveroutlen,
		     const char **errstr)
{
  /* cast */
  sasl_server_conn_t *s_conn;
  s_conn= (sasl_server_conn_t *) conn;

  /* check parameters */
  if ((clientin==NULL) && (clientinlen>0))
    return SASL_BADPARAM;

  if (errstr)
    *errstr = NULL;

  return s_conn->mech->plug->mech_step(conn->context,
				       s_conn->sparams,
				       clientin,
				       clientinlen,
				       serverout,
				       (int *) serveroutlen,
				       &conn->oparams,
				       errstr);
}

/* returns the length of all the mechanisms
 * added up 
 */

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

/* This returns a list of mechanisms in a NUL-terminated string
 *  user          -- restricts mechanisms to those available to that user
 *                   (may be NULL)
 *  prefix        -- appended to beginning of result
 *  sep           -- appended between mechanisms
 *  suffix        -- appended to end of result
 * results:
 *  result        -- NUL terminated allocated result, caller must free
 *  plen          -- gets length of result (excluding NUL), may be NULL
 *  pcount        -- gets number of mechanisms, may be NULL
 *
 * returns:
 *  SASL_OK        -- success
 *  SASL_NOMEM     -- not enough memory
 *  SASL_NOMECH    -- no enabled mechanisms
 */

/*
 * The default behavior is to seperate with spaces if sep==NULL
 */

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
      if (pcount!=NULL)
	(*pcount)++;

      /* print seperator */      
      if (lup>0)
      {
	if (sep)
	  strcat(*result,sep);
	else
	  strcat(*result," "); /* if seperator is NULL give it space */
      }

      /* now print the mechanism name */
      strcat(*result,listptr->plug->mech_name);

    }

    listptr=listptr->next;
  }

  if (suffix)
    strcat(*result,suffix);

  if (plen!=NULL)
    *plen=strlen(*result);

  return SASL_OK;
  
}

/* check if a plaintext password is valid
 * if user is NULL, check if plaintext is enabled
 * inputs:
 *  user         -- user to query in current user_realm
 *  userlen      -- length of username, 0 = strlen(user)
 *  pass         -- plaintext password to check
 *  passlen      -- length of password, 0 = strlen(pass)
 * outputs:
 *  errstr       -- set to error message for use in protocols
 * returns 
 *  SASL_OK      -- success
 *  SASL_NOMECH  -- user found, but no verifier
 *  SASL_NOUSER  -- user not found
 */

/* xxx major overhaul this */

int sasl_checkpass(sasl_conn_t *conn,
		   const char *user,
		   unsigned userlen __attribute__((unused)),
		   const char *pass,
		   unsigned passlen,
		   const char **errstr)
{
  int result;
  int try_plain=1;
  int try_shadow=1;
  int try_krb=1;

  const char *mechs=NULL;

  mechs=sasl_config_getstring("plainmech",NULL); /* default to NULL */
  
  /* if that parameter exists then we only want to do one of the
     tests not all of them */
  if (mechs!=NULL)
  {
    try_plain=0;
    try_shadow=0;
    try_krb=0;

    if (strcmp(mechs,"KERBEROS_V4")==0)
      try_krb=1;
    
    if (strcmp(mechs,"PASSWD")==0)
      try_plain=1;
    
    if (strcmp(mechs,"SHADOW")==0)
      try_shadow=1;
  }

  result=SASL_FAIL;

  if (try_plain==1)
  {
    /* check against /etc/passwd */
    result=_sasl_passwd_verify_password(user, pass, errstr);

    if (result==SASL_OK) return SASL_OK;
  }

  if (try_shadow==1)
  {
    /* check against /etc/passwd */
    result=_sasl_shadow_verify_password(user, pass, errstr);

    if (result==SASL_OK) return SASL_OK;
  }

  if (try_krb==1)
  {
    /* check against krb */
    result=_sasl_kerberos_verify_password(user, pass, conn->service, errstr);

    if (result==SASL_OK)
    {
      result = _sasl_strdup(user,
			    &(conn->oparams.authid),
			    NULL);
      if (result != SASL_OK)  return result;
      
      _sasl_transition(conn,
		       pass,
		       passlen);
      return SASL_OK;
    }
  }

  return result;
}

