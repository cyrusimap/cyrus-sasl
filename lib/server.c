/* SASL server API implementation
 * Tim Martin
 * $Id: server.c,v 1.84 2001/02/06 20:54:28 leg Exp $
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
#include <ctype.h>

#define DEFAULT_PLAIN_MECHANISM "sasldb"

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

/* if we've initialized the server sucessfully */
static int _sasl_server_active = 0;

static int _sasl_checkpass(sasl_conn_t *conn,
			   const char *mech, const char *service, 
			   const char *user, const char *pass,
			   const char **errstr);

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
      || !oparams)
    return SASL_BADPARAM;

  if (errstr) {
      *errstr = NULL;
  }

  if (!sparams->utils->conn->external.auth_id)
    return SASL_BADPROT;

  if ((sparams->props.security_flags & SASL_SEC_NOANONYMOUS) &&
      (!strcmp(sparams->utils->conn->external.auth_id, "anonymous"))) {
      *errstr = "anonymous login not allowed";
      return SASL_NOAUTHZ;
  }
  
  if (! clientin) {
    /* No initial data; we're in a protocol which doesn't support it.
     * So we let the server app know that we need some... */
    *serverout = NULL;
    *serveroutlen = 0;
    return SASL_CONTINUE;
  }

  if (clientinlen) {		/* if we have a non-zero authorization id */
      /* The user's trying to authorize as someone they didn't
       * authenticate as */
      result = _sasl_strdup(clientin, &oparams->user, NULL);
      if (result != SASL_OK)
	  return result;
  } else {
      /* just copy the authid to the userid */
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

  return SASL_OK;
}

static const sasl_server_plug_t external_server_mech = {
  "EXTERNAL",			/* mech_name */
  0,				/* max_ssf */
  SASL_SEC_NOPLAINTEXT
  | SASL_SEC_NOANONYMOUS
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
    int condition; /* set to SASL_NOUSER if no available users;
		      set to SASL_CONTINUE if delayed plugn loading */
    const sasl_server_plug_t *plug;
    struct mechanism *next;
    union {
	void *library; /* this a pointer to shared library returned by dlopen 
			  or some similar function on other platforms */
	char *f;       /* where should i load the mechanism from? */
    } u;
} mechanism_t;

typedef struct mech_list {
  sasl_utils_t *utils;  /* gotten from plug_init */

  void *mutex;            /* mutex for this data */ 
  mechanism_t *mech_list; /* list of mechanisms */
  int mech_length;       /* number of mechanisms */
} mech_list_t;

typedef struct sasl_server_conn {
    sasl_conn_t base; /* parts common to server + client */
    
    char *user_realm; /* domain the user authenticating is in */
    int authenticated;
    mechanism_t *mech; /* mechanism trying to use */
    sasl_server_params_t *sparams;
} sasl_server_conn_t;

static mech_list_t *mechlist = NULL; /* global var which holds the list */

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
    sasl_server_conn_t *s_conn = (sasl_server_conn_t *) conn;
    mechanism_t *m;
    sasl_getopt_t *getopt;
    void *context;
     
    /* check params */
    if (errstr) { *errstr = NULL; }
    if (!conn) return SASL_BADPARAM;
     
    if (!mechlist) {
	if (errstr) *errstr = "No mechanisms available";
	return SASL_FAIL;
    }
    if (!(flags & SASL_SET_DISABLE) && passlen == 0) {
	if (errstr) *errstr = "Password must be at least one character long";
	return SASL_BADPARAM;
    }

    if ((flags & SASL_SET_CREATE) && (flags & SASL_SET_DISABLE)) {
	if (errstr) *errstr = "Can't both create and disable simultaneously";
	return SASL_BADPARAM;
    }

    /* set/create password for PLAIN usage */
    tmpresult = _sasl_sasldb_set_pass(conn, user, pass, passlen, 
				      s_conn->user_realm, flags, errstr);
    if (tmpresult != SASL_OK && tmpresult != SASL_NOCHANGE) {
	result = tmpresult;
	_sasl_log(conn, SASL_LOG_ERR, "PLAIN", tmpresult,
#ifndef WIN32
		  errno,
#else
		  GetLastError(),
#endif
		  "failed to set secret for %s: %z", user);
    } else {
	_sasl_log(conn, SASL_LOG_INFO, "PLAIN", 0, 0, 
		  "set secret for %s", user);
    }

    /* copy info into sparams */
    s_conn->sparams->serverFQDN = conn->serverFQDN;
    s_conn->sparams->service = conn->service;
    s_conn->sparams->user_realm = s_conn->user_realm;

    /* now we let the mechanisms set their secrets */
    for (m = mechlist->mech_list; m; m = m->next) {
	if (!m->plug->setpass) {
	    /* can't set pass for this mech */
	    continue;
	}
	tmpresult = m->plug->setpass(m->plug->glob_context,
				     ((sasl_server_conn_t *)conn)->sparams,
				     user,
				     pass,
				     passlen,
				     flags,
				     errstr);
	if (tmpresult == SASL_OK) {
	    _sasl_log(conn, SASL_LOG_INFO, m->plug->mech_name, 0, 0,
		      "set secret for %s", user);

	    m->condition = SASL_OK; /* if we previously thought the
				       mechanism didn't have any user secrets 
				       we now think it does */

	} else if (tmpresult == SASL_NOCHANGE) {
	    _sasl_log(conn, SASL_LOG_INFO, m->plug->mech_name, 0, 0,
		      "secret not changed for %s", user);
	} else {
	    result = tmpresult;
	    _sasl_log(conn, SASL_LOG_ERR, m->plug->mech_name, tmpresult,
#ifndef WIN32
		      errno,
#else
		      GetLastError(),
#endif
		      "failed to set secret for %s: %z", user);
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
    /* set util functions - need to do rest */
    mechlist->utils = _sasl_alloc_utils(NULL, &global_callbacks);
    if (mechlist->utils == NULL)
	return SASL_NOMEM;

    mechlist->utils->checkpass = &_sasl_checkpass;

    return SASL_OK;
}

/*
 * parameters:
 *  p - entry point
 *  library - shared library ptr returned by dlopen
 */
static int add_plugin(void *p, void *library) 
{
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

    if ((result != SASL_OK) && (result != SASL_NOUSER)) {
	VL(("entry_point error %i\n",result));
	return result;
    }

    /* Make sure plugin is using the same SASL version as us */
    if (version > SASL_SERVER_PLUG_VERSION)
    {
	_sasl_log(NULL, SASL_LOG_ERR, NULL, 0, 0,
		  "version mismatch on plugin");
	result = SASL_FAIL;
    }

    for (lupe=0;lupe < plugcount ;lupe++)
    {
	mech = sasl_ALLOC(sizeof(mechanism_t));
	if (! mech) return SASL_NOMEM;

	mech->plug=pluglist++;
	mech->version = version;
      
	/* wheather this mech actually has any users in it's db */
	mech->condition = result; /* SASL_OK or SASL_NOUSER */

	/*
	 * We want plugin library to close but we only
	 * want to do this once per plugin regardless
	 * of how many mechs are in a single plugin 
	 */
	if (lupe==0) {
	    mech->u.library=library;
 	} else {
	    mech->u.library=NULL;
	}

	mech->next = mechlist->mech_list;
	mechlist->mech_list = mech;

	mechlist->mech_length++;
    }

    return SASL_OK;
}

static void server_done(void) {
  mechanism_t *m;
  mechanism_t *prevm;

  if (mechlist != NULL)
  {
      m=mechlist->mech_list; /* m point to begging of the list */

      while (m!=NULL)
      {
	  prevm=m;
	  m=m->next;
    
	  if (prevm->plug->glob_context!=NULL)
	      sasl_FREE(prevm->plug->glob_context);
	  if (prevm->condition == SASL_OK && prevm->u.library != NULL)
	      _sasl_done_with_plugin(prevm->u.library);
	  sasl_FREE(prevm);    
      }
      _sasl_free_utils(&mechlist->utils);
      sasl_FREE(mechlist);
      mechlist = NULL;
  }

  /* no longer active. fail on listmech's etc. */
  _sasl_server_active = 0;
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
  char *path_to_config=NULL, *c;
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
  if (result!=SASL_OK) goto done;
  if (path_to_config == NULL) path_to_config = "";

  if ((c = strchr(path_to_config, ':'))) {
      *c = '\0';
  }

  /* length = length of path + '/' + length of appname + ".conf" + 1
     for '\0' */
  len = strlen(path_to_config)+2+ strlen(global_callbacks.appname)+5+1;

  if (len > PATH_MAX ) {
      result = SASL_FAIL;
      goto done;
  }

  /* construct the filename for the config file */
  config_filename = sasl_ALLOC(len);
  if (! config_filename) {
      result = SASL_NOMEM;
      goto done;
  }

  snprintf(config_filename, len, "%s/%s.conf", path_to_config, 
	   global_callbacks.appname);

  /* Ask the application if it's safe to use this file */
  result = ((sasl_verifyfile_t *)(verifyfile_cb->proc))(verifyfile_cb->context,
					config_filename, SASL_VRFY_CONF);

  /* returns continue if this file is to be skipped */
  
  /* returns SASL_CONTINUE if doesn't exist
   * if doesn't exist we can continue using default behavior
   */
  if (result==SASL_OK)
    result=sasl_config_init(config_filename);

 done:
  if (config_filename) sasl_FREE(config_filename);
  if ((path_to_config) && (*path_to_config)) { /* was path_to_config allocated? */
      sasl_FREE(path_to_config);
  }

  return result;
}

/*
 * Verify that all the callbacks are valid
 */
static int verify_server_callbacks(const sasl_callback_t *callbacks)
{
    if (callbacks == NULL) return SASL_OK;

    while (callbacks->id != SASL_CB_LIST_END) {
	if (callbacks->proc==NULL) return SASL_FAIL;

	callbacks++;
    }

    return SASL_OK;
}

char *grab_field(char *line, char **eofield)
{
    int d = 0;
    char *field;

    while (isspace((int) *line)) line++;

    /* find end of field */
    while (line[d] && !isspace(((int) line[d]))) d++;
    field = sasl_ALLOC(d + 1);
    if (!field) { return NULL; }
    memcpy(field, line, d);
    field[d] = '\0';
    *eofield = line + d;
    
    return field;
}

struct secflag_map_s {
    char *name;
    int value;
};

struct secflag_map_s secflag_map[] = {
    { "noplaintext", SASL_SEC_NOPLAINTEXT },
    { "noactive", SASL_SEC_NOACTIVE },
    { "nodictionary", SASL_SEC_NODICTIONARY },
    { "forward_secrecy", SASL_SEC_FORWARD_SECRECY },
    { "noanonymous", SASL_SEC_NOANONYMOUS },
    { "pass_credentials", SASL_SEC_PASS_CREDENTIALS },
    { NULL, 0x0 }
};


static int parse_mechlist_file(const char *mechlistfile)
{
    FILE *f;
    char buf[1024];
    char *t, *ptr;
    int r = 0;

    f = fopen(mechlistfile, "r");
    if (!f) return SASL_FAIL;

    r = SASL_OK;
    while (fgets(buf, sizeof(buf), f) != NULL) {
	mechanism_t *n = sasl_ALLOC(sizeof(mechanism_t));
	sasl_server_plug_t *nplug;

	if (n == NULL) { r = SASL_NOMEM; break; }
	n->version = SASL_SERVER_PLUG_VERSION;
	n->condition = SASL_CONTINUE;
	nplug = sasl_ALLOC(sizeof(sasl_server_plug_t));
	if (nplug == NULL) { r = SASL_NOMEM; break; }
	memset(nplug, 0, sizeof(sasl_server_plug_t));

	/* each line is:
	   plugin-file WS mech_name WS max_ssf *(WS security_flag) RET
	*/
	
	/* grab file */
	n->u.f = grab_field(buf, &ptr);

	/* grab mech_name */
	nplug->mech_name = grab_field(ptr, &ptr);

	/* grab max_ssf */
	nplug->max_ssf = strtol(ptr, &ptr, 10);

	/* grab security flags */
	while (*ptr != '\n') {
	    struct secflag_map_s *map;

	    /* read security flag */
	    t = grab_field(ptr, &ptr);
	    map = secflag_map;
	    while (map->name) {
		if (!strcasecmp(t, map->name)) {
		    nplug->security_flags |= map->value;
		    break;
		}
		map++;
	    }
	    if (!map->name) {
		_sasl_log(NULL, SASL_LOG_ERR, nplug->mech_name, 
			  SASL_FAIL, 0, "couldn't identify flag '%s'", t);

	    }
	    free(t);
	}

	/* insert mechanism into mechlist */
	n->plug = nplug;
	n->next = mechlist->mech_list;
	mechlist->mech_list = n;
	mechlist->mech_length++;
    }

    fclose(f);
    return r;
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
    const sasl_callback_t *vf;
    const char *pluginfile = NULL;
    sasl_getopt_t *getopt;
    void *context;

    /* we require the appname to be non-null */
    if (appname==NULL) return SASL_BADPARAM;

    _sasl_server_getsecret_hook = _sasl_db_getsecret;
    _sasl_server_putsecret_hook = _sasl_db_putsecret;

    _sasl_server_cleanup_hook = &server_done;

    /* verify that the callbacks look ok */
    ret = verify_server_callbacks(callbacks);
    if (ret != SASL_OK) return ret;

    global_callbacks.callbacks = callbacks;
    global_callbacks.appname = appname;

    /* allocate mechlist and set it to empty */
    mechlist = sasl_ALLOC(sizeof(mech_list_t));
    if (mechlist == NULL) return SASL_NOMEM;
    mechlist->mech_list = NULL;
    mechlist->mech_length = 0;
    ret = init_mechlist();
    if (ret != SASL_OK) return ret;

    vf = _sasl_find_verifyfile_callback(callbacks);

    /* load config file if applicable */
    ret = load_config(vf);
    if ((ret != SASL_OK) && (ret != SASL_CONTINUE)) {
	return ret;
    }

    /* check db */
    ret = _sasl_server_check_db(vf);

    /* load plugins */
    add_plugin((void *)&external_server_init, NULL);

    /* delayed loading of plugins? */
    if (_sasl_getcallback(NULL, SASL_CB_GETOPT, &getopt, &context) 
	   == SASL_OK) {
	getopt((void *) &global_callbacks, NULL, 
	       "plugin_list", &pluginfile, NULL);
    }
    if (pluginfile != NULL) {
	/* this file should contain a list of plugins available.
	   we'll load on demand. */

	/* Ask the application if it's safe to use this file */
	ret = ((sasl_verifyfile_t *)(vf->proc))(vf->context,
						pluginfile,
						SASL_VRFY_CONF);
	if (ret != SASL_OK) {
	    _sasl_log(NULL, SASL_LOG_ERR, NULL, ret, 0,
		      "unable to load plugin list %s: %z", pluginfile);
	}

	if (ret == SASL_OK) {
	    ret = parse_mechlist_file(pluginfile);
	}
    } else {
	/* load all plugins now */
	ret = _sasl_get_mech_list("sasl_server_plug_init",
				  _sasl_find_getpath_callback(callbacks),
				  _sasl_find_verifyfile_callback(callbacks),
				  &add_plugin);
    }

    if (ret == SASL_OK)	ret = _sasl_common_init();
  
    if (ret == SASL_OK) {
	/* _sasl_server_active shows if we're active or not. 
	   sasl_done() sets it back to 0 */
	_sasl_server_active = 1;
	_sasl_server_idle_hook = &server_idle;
    }

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
    const char *dotrans = "n";
    sasl_getopt_t *getopt;
    void *context;

    if (! conn)
	return SASL_BADPARAM;

    if (! conn->oparams.authid)
	return SASL_NOTDONE;

    /* check if this is enabled: default to false */
    if (_sasl_getcallback(conn, SASL_CB_GETOPT, &getopt, &context) == SASL_OK)
    {
	getopt(context, NULL, "auto_transition", &dotrans, NULL);
	if (dotrans == NULL) dotrans = "n";
    }

    if (*dotrans == '1' || *dotrans == 'y' ||
	(*dotrans == 'o' && dotrans[1] == 'n') || *dotrans == 't') {
	/* ok, it's on! */
	return sasl_setpass(conn,
			    conn->oparams.authid,
			    pass,
			    passlen,
			    0,
			    NULL);
    }

    return SASL_OK;
}


/* create context for a single SASL connection
 *  service        -- registered name of the service using SASL (e.g. "imap")
 *  serverFQDN     -- Fully qualified server domain name.  NULL means use
 *                    gethostname().  Useful for multi-homed servers.
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

  /* set util functions - need to do rest */
  serverconn->sparams->utils=_sasl_alloc_utils(*pconn, &global_callbacks);
  if (serverconn->sparams->utils==NULL)
    return SASL_NOMEM;
  serverconn->sparams->utils->checkpass = &_sasl_checkpass;

  serverconn->sparams->transition = &_sasl_transition;

  serverconn->sparams->props = serverconn->base.props;

  /* set some variables */
  if (user_realm==NULL) {
    serverconn->user_realm = NULL;
  } else {
    result = _sasl_strdup(user_realm, &serverconn->user_realm, NULL);
  }

  if (result!=SASL_OK) {
      _sasl_conn_dispose(*pconn);
      sasl_FREE(*pconn);
      *pconn = NULL;
  }

  return result;
}

/*
 * The rule is:
 * IF mech strength + external strength < min ssf THEN FAIL
 * We also have to look at the security properties and make sure
 * that this mechanism has everything we want
 */
static int mech_permitted(sasl_conn_t *conn,
			  mechanism_t *mech)
{
    const sasl_server_plug_t *plug = mech->plug;
    int myflags;

    /* Can this plugin meet the application's security requirements? */
    if (! plug || ! conn)
	return 0;

    if (plug == &external_server_mech) {
	/* Special case for the external mechanism */
	if (conn->props.min_ssf > conn->external.ssf
	    || ! conn->external.auth_id)
	    return 0;
    } else {
	sasl_ssf_t minssf;

	if (conn->props.min_ssf < conn->external.ssf) {
	    minssf = 0;
	} else {
	    minssf = conn->props.min_ssf - conn->external.ssf;
	}

	/* Generic mechanism */
	if (plug->max_ssf < minssf)
	    return 0; /* too weak */
    }

    /* if there are no users in the secrets database we can't use this 
       mechanism */
    if (mech->condition == SASL_NOUSER) return 0;
    
    /* security properties---if there are any flags that differ and are
       in what the connection are requesting, then fail */
    
    /* special case plaintext */
    myflags = conn->props.security_flags;

    /* if there's an external layer this is no longer plaintext */
    if ((conn->props.min_ssf <= conn->external.ssf) && 
	(conn->external.ssf > 1)) {
	myflags &= ~SASL_SEC_NOPLAINTEXT;
    }

    /* do we want to special case SASL_SEC_PASS_CREDENTIALS? nah.. */
    if (((myflags ^ plug->security_flags) & myflags) != 0) {
	return 0;
    }

    return 1;
}

/*
 * make the authorization 
 *
 */

static int do_authorization(sasl_server_conn_t *s_conn, const char **errstr)
{
    int ret;
    sasl_authorize_t *authproc;
    void *auth_context;
    const char *canonuser;
    
    /* now let's see if authname is allowed to proxy for username! */
    
    /* check the proxy callback */
    if (_sasl_getcallback(&s_conn->base, SASL_CB_PROXY_POLICY,
			  &authproc, &auth_context) != SASL_OK) {
	return SASL_NOAUTHZ;
    }
    ret = authproc(auth_context, s_conn->base.oparams.authid,
		   s_conn->base.oparams.user, &canonuser, errstr);
    
    if (ret == SASL_OK && canonuser != NULL) {
	if (s_conn->base.oparams.user != NULL)
	    sasl_FREE(s_conn->base.oparams.user);
	s_conn->base.oparams.user = (char *) canonuser;
    }

    return ret;
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
    if ((conn == NULL) || (mech==NULL) || ((clientin==NULL) && (clientinlen>0)))
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
  
    if (m==NULL) {
	result = SASL_NOMECH;
	goto done;
    }

    /* Make sure that we're willing to use this mech */
    if (! mech_permitted(conn, m)) {
	result = SASL_NOMECH;
	goto done;
    }

    if (m->condition == SASL_CONTINUE) {
	sasl_server_plug_init_t *entry_point;
	void *library = NULL;
	const sasl_server_plug_t *pluglist;
	int version, plugcount;
	int l = 0;

	/* need to load this plugin */
	result = _sasl_get_plugin(m->u.f, "sasl_server_plug_init",
		    _sasl_find_verifyfile_callback(global_callbacks.callbacks),
				  (void **) &entry_point, &library);
	if (result == SASL_OK) {
	    result = entry_point(mechlist->utils, SASL_SERVER_PLUG_VERSION,
				 &version, &pluglist, &plugcount);
	}
	if (result == SASL_OK) {
	    /* find the correct mechanism in this plugin */
	    for (l = 0; l < plugcount; l++) {
		if (!strcasecmp(pluglist[l].mech_name, 
				m->plug->mech_name)) break;
	    }
	    if (l == plugcount) {
		result = SASL_NOMECH;
	    }
	}
	if (result == SASL_OK) {
	    /* check that the parameters are the same */
	    if ((pluglist[l].max_ssf != m->plug->max_ssf) ||
		(pluglist[l].security_flags != m->plug->security_flags)) {
		_sasl_log(conn, SASL_LOG_ERR, 
			  pluglist[l].mech_name, SASL_NOMECH, 0, 
			  "security parameters don't match mechlist file");
		result = SASL_NOMECH;
	    }
	}
	if (result == SASL_OK) {
	    /* copy mechlist over */
	    sasl_FREE((sasl_server_plug_t *) m->plug);
	    m->plug = &pluglist[l];
	    m->condition = SASL_OK;
	    m->u.library = library;
	}

	if (result != SASL_OK) {
	    if (library) {
		/* won't be using you after all */
		_sasl_done_with_plugin(library);
	    }
	    return result;
	}
    }

    s_conn->mech = m;

    /* call the security layer given by mech */
    s_conn->sparams->serverFQDN=conn->serverFQDN;
    s_conn->sparams->service=conn->service;
    s_conn->sparams->user_realm=s_conn->user_realm;
    s_conn->sparams->props=conn->props;
    s_conn->sparams->external_ssf=conn->external.ssf;

    result = s_conn->mech->plug->mech_new(s_conn->mech->plug->glob_context,
					  s_conn->sparams,
					  NULL,
					  0,
					  &(conn->context),
					  errstr);

    if (result == SASL_OK) {
	result = s_conn->mech->plug->mech_step(conn->context,
					       s_conn->sparams,
					       clientin,
					       clientinlen,
					       serverout,
					       (int *) serveroutlen,
					       &conn->oparams,
					       errstr);
    }
   
    if (result == SASL_OK) {
	result = do_authorization(s_conn, errstr);
    }

 done:
    return result;
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
    int ret;
    sasl_server_conn_t *s_conn = (sasl_server_conn_t *) conn;  /* cast */

    /* check parameters */
    if ((clientin==NULL) && (clientinlen>0))
	return SASL_BADPARAM;

    if (errstr)
	*errstr = NULL;

    ret = s_conn->mech->plug->mech_step(conn->context,
					s_conn->sparams,
					clientin,
					clientinlen,
					serverout,
					(int *) serveroutlen,
					&conn->oparams,
					errstr);

    if (ret == SASL_OK) {
	ret = do_authorization(s_conn, errstr);
    }

    return ret;
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
  int flag;
  const char *mysep;

  /* if there hasn't been a sasl_sever_init() fail */
  if (_sasl_server_active==0) return SASL_FAIL;

  if (! conn || ! result)
    return SASL_FAIL;

  if (plen != NULL)
      *plen = 0;
  if (pcount != NULL)
      *pcount = 0;

  if (sep) {
      mysep = sep;
  } else {
      mysep = " ";
  }

  if (! mechlist)
    return SASL_FAIL;

  if (mechlist->mech_length <= 0)
    return SASL_NOMECH;

  resultlen = (prefix ? strlen(prefix) : 0)
            + (strlen(mysep) * (mechlist->mech_length - 1))
	    + mech_names_len()
            + (suffix ? strlen(suffix) : 0)
	    + 1;
  *result=sasl_ALLOC(resultlen);
  if ((*result)==NULL) return SASL_NOMEM;

  if (prefix)
    strcpy (*result,prefix);
  else
    **result = '\0';

  listptr = mechlist->mech_list;  
   
  flag = 0;
  /* make list */
  for (lup = 0; lup < mechlist->mech_length; lup++) {
      /* currently, we don't use the "user" parameter for anything */
      if (mech_permitted(conn, listptr)) {
	  if (pcount != NULL)
	      (*pcount)++;

	  /* print seperator */
	  if (flag) {
	      strcat(*result, mysep);
	  } else {
	      flag = 1;
	  }

	  /* now print the mechanism name */
	  strcat(*result, listptr->plug->mech_name);
      }

      listptr = listptr->next;
  }

  if (suffix)
      strcat(*result,suffix);

  if (plen!=NULL)
      *plen=strlen(*result);

  return SASL_OK;
  
}

#define EOSTR(s,n) (((s)[n] == '\0') || ((s)[n] == ' ') || ((s)[n] == '\t'))
static int is_mech(const char *t, const char *m)
{
    int sl = strlen(m);
    return ((!strncasecmp(m, t, sl)) && EOSTR(t, sl));
}

/* returns OK if it's valid */
static int _sasl_checkpass(sasl_conn_t *conn,
			   const char *mech, const char *service,
			   const char *user, const char *pass,
			   const char **errstr)
{
    sasl_server_conn_t *s_conn = (sasl_server_conn_t *) conn;
    int result = SASL_NOMECH;
    struct sasl_verify_password_s *v;

    if (mech == NULL) mech = DEFAULT_PLAIN_MECHANISM;
    for (v = _sasl_verify_password; v->name; v++) {
	if (is_mech(mech, v->name)) {
	    result = v->verify(conn, user, pass, 
			       service, s_conn->user_realm, errstr);
	    break;
	}
    }

    if (result == SASL_NOMECH) {
	/* no mechanism available ?!? */
	_sasl_log(conn, SASL_LOG_ERR, NULL, 0, 0,
		  "unrecognized plaintext verifier %s", mech);
    }

    return result;
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
int sasl_checkpass(sasl_conn_t *conn,
		   const char *user,
		   unsigned userlen __attribute__((unused)),
		   const char *pass,
		   unsigned passlen,
		   const char **errstr)
{
    const char *mech = NULL;
    int result = SASL_NOMECH;
    sasl_getopt_t *getopt;
    void *context;

    /* check params */
    if (_sasl_server_active==0) return SASL_FAIL;
    if ((conn == NULL) || (user == NULL) || (pass == NULL)) return SASL_BADPARAM;

    if (user == NULL) return SASL_NOUSER;

    /* figure out how to check (i.e. PAM or /etc/passwd or kerberos or etc...) */
    if (_sasl_getcallback(conn, SASL_CB_GETOPT, &getopt, &context)
	    == SASL_OK) {
	getopt(context, NULL, "pwcheck_method", &mech, NULL);
    }

    if (errstr != NULL) { *errstr = NULL; }
    result = _sasl_checkpass(conn, mech, conn->service, user, pass, errstr);

    if (result == SASL_OK) {
	result = _sasl_strdup(user, &(conn->oparams.authid), NULL);
	if (result != SASL_OK) return result;
      
	_sasl_transition(conn, pass, passlen);
    }

    return result;
}
