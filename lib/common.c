/* common.c - Functions that are common to server and clinet
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
#include <limits.h>
#ifdef HAVE_VSYSLOG
#include <syslog.h>
#endif
#include <stdarg.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>
#include "saslint.h"

int _sasl_debug = 0;

static const char build_ident[] = "$Build: libsasl " PACKAGE "-" VERSION " $";

void (*_sasl_client_cleanup_hook)(void) = NULL;
void (*_sasl_server_cleanup_hook)(void) = NULL;
int (*_sasl_client_idle_hook)(sasl_conn_t *conn) = NULL;
int (*_sasl_server_idle_hook)(sasl_conn_t *conn) = NULL;
sasl_server_getsecret_t *_sasl_server_getsecret_hook = NULL;
sasl_server_putsecret_t *_sasl_server_putsecret_hook = NULL;

sasl_allocation_utils_t _sasl_allocation_utils={
  (sasl_malloc_t *)  &malloc,
  (sasl_calloc_t *)  &calloc,
  (sasl_realloc_t *) &realloc,
  (sasl_free_t *) &free
};

static void *sasl_mutex_new(void)
{
  /* got to return something; NULL => failure */
  return sasl_ALLOC(1);
}

static int sasl_mutex_lock(void *mutex __attribute__((unused)))
{
  return SASL_OK;
}

static int sasl_mutex_unlock(void *mutex __attribute__((unused)))
{
  return SASL_OK;
}

static void sasl_mutex_dispose(void *mutex)
{
  sasl_FREE(mutex);
}

sasl_mutex_utils_t _sasl_mutex_utils={
  &sasl_mutex_new,
  &sasl_mutex_lock,
  &sasl_mutex_unlock,
  &sasl_mutex_dispose
};

void sasl_set_mutex(sasl_mutex_new_t *n, sasl_mutex_lock_t *l,
		    sasl_mutex_unlock_t *u, sasl_mutex_dispose_t *d)
{
  _sasl_mutex_utils.new=n;
  _sasl_mutex_utils.lock=l;
  _sasl_mutex_utils.unlock=u;
  _sasl_mutex_utils.dispose=d;
}


/* copy a string to malloced memory */
int _sasl_strdup(const char *in, char **out, int *outlen)
{
  size_t len = strlen(in);
  if (outlen) *outlen = len;
  *out=sasl_ALLOC(len + 1);
  if (! *out) return SASL_NOMEM;
  strcpy((char *) *out, in);
  return SASL_OK;
}

int sasl_encode(sasl_conn_t *conn, const char *input, unsigned inputlen,
		char **output, unsigned *outputlen)
{
  if (! conn || ! input || ! output || ! outputlen)
    return SASL_FAIL;
  if (conn->oparams.encode==NULL)
  {
    /* just copy the string, no encryption */
    *output = sasl_ALLOC(inputlen+1);
    if (! *output) return SASL_NOMEM;
    memcpy(*output, input, inputlen);
    *outputlen = inputlen;
    (*output)[inputlen] = '\0'; /* sanity for stupid clients */
    return SASL_OK;
  } else {
    return conn->oparams.encode(conn->context, input,
				inputlen, output, outputlen);
  }
}


int sasl_decode(sasl_conn_t *conn, const char *input, unsigned inputlen,
		char **output, unsigned *outputlen)
{
  if (! conn || ! input || ! output || ! outputlen)
    return SASL_FAIL;
  if (conn->oparams.encode==NULL)
  {
    /* just copy the string, no encryption */
    *output = sasl_ALLOC(inputlen + 1);
    if (! *output) return SASL_NOMEM;
    memcpy(*output, input, inputlen);
    *outputlen = inputlen;
    (*output)[inputlen] = '\0'; /* sanity for stupid clients */
    return SASL_OK;

  } else {
    return conn->oparams.decode(conn->context, input, inputlen,
				output, outputlen);
  }
}


void
sasl_set_alloc(sasl_malloc_t *m,
	       sasl_calloc_t *c,
	       sasl_realloc_t *r,
	       sasl_free_t *f)
{
  _sasl_allocation_utils.malloc=m;
  _sasl_allocation_utils.calloc=c;
  _sasl_allocation_utils.realloc=r;
  _sasl_allocation_utils.free=f;
}

void sasl_done(void)
{
  if (_sasl_server_cleanup_hook)
    _sasl_server_cleanup_hook();

  if (_sasl_client_cleanup_hook)
    _sasl_client_cleanup_hook();
}

/* fills in the base sasl_conn_t info */
int _sasl_conn_init(sasl_conn_t *conn,
		    const char *service,
		    int secflags,
		    int (*idle_hook)(sasl_conn_t *conn),
		    const sasl_callback_t *callbacks,
		    const sasl_global_callbacks_t *global_callbacks) {
  int result = SASL_OK;

  I(conn);
  I(service);

  conn->mutex = sasl_MUTEX_NEW();
  if (! conn->mutex) return SASL_FAIL;
  result = _sasl_strdup(service, &conn->service, NULL);
  if (result != SASL_OK) goto cleanup_mutex;
  conn->external.ssf = 0;
  conn->external.auth_id = NULL;
  memset(&conn->oparams, 0, sizeof(conn->oparams));
  conn->secflags = secflags;
  conn->open = 1;
  conn->got_ip_local = 0;
  conn->got_ip_remote = 0;
  conn->props.min_ssf = 0;
  if (secflags & SASL_SECURITY_LAYER)
    conn->props.max_ssf = UINT_MAX;
  else
    conn->props.max_ssf = 0;
  conn->idle_hook = idle_hook;
  conn->callbacks = callbacks;
  conn->global_callbacks = global_callbacks;
  return result;

cleanup_mutex:
  sasl_MUTEX_DISPOSE(conn->mutex);
  return result;
}

/* dispose connection state, sets it to NULL
 *  checks for pointer to NULL
 */
void sasl_dispose(sasl_conn_t **pconn)
{
  if (! pconn) return;
  if (! *pconn) return;

  (*pconn)->destroy_conn(*pconn);
  sasl_FREE(*pconn);
  *pconn=NULL;
}

void _sasl_conn_dispose(sasl_conn_t *conn) {
  if (conn->service)
    sasl_FREE(conn->service);

  if (conn->external.auth_id)
    sasl_FREE(conn->external.auth_id);

  if (conn->oparams.user)
    sasl_FREE(conn->oparams.user);

  if (conn->oparams.authid)
    sasl_FREE(conn->oparams.authid);

  if (conn->oparams.realm)
    sasl_FREE(conn->oparams.realm);

  sasl_MUTEX_DISPOSE(conn->mutex);
}


int sasl_getprop(sasl_conn_t *conn, int propnum, void **pvalue)
{
  int result;

  if (! conn) return SASL_FAIL;
  if (! pvalue) return SASL_FAIL;

  result = sasl_MUTEX_LOCK(conn->mutex);
  if (result != SASL_OK) return result;

  switch(propnum)
  {
    case SASL_USERNAME:
      if (! conn->oparams.user)
	result = SASL_NOTDONE;
      else
	*pvalue=conn->oparams.user;
      break;
    case SASL_SSF:
      *(sasl_ssf_t *)pvalue= conn->oparams.mech_ssf;
      break;      
    case SASL_MAXOUTBUF:
      *(unsigned *)pvalue = conn->oparams.maxoutbuf;
      break;
    case SASL_REALM:
      if (! conn->oparams.realm)
	result = SASL_NOTDONE;
      else
	*pvalue = conn->oparams.realm;
      break;
    case SASL_GETOPTCTX:
      /* ??? */
      break;
    case SASL_IP_LOCAL:
      if (! conn->got_ip_local)
	result = SASL_NOTDONE;
      else
	*(struct sockaddr_in *)pvalue = conn->ip_local;
      break;
    case SASL_IP_REMOTE:
      if (! conn->got_ip_remote)
	result = SASL_NOTDONE;
      else
	*(struct sockaddr_in *)pvalue = conn->ip_remote;
      break;
    default: 
      result = SASL_BADPARAM;
  }
  sasl_MUTEX_UNLOCK(conn->mutex);
  return result; 
}

int sasl_setprop(sasl_conn_t *conn, int propnum, const void *value)
{
  int result;
  char *str;

  /* make sure the sasl context is valid */
  if (!conn)
    return SASL_BADPARAM;

  /* grab mutex so can only one thread can modify a property at a time */
  result = sasl_MUTEX_LOCK(conn->mutex);
  if (result != SASL_OK) return result;

  switch(propnum)
  {
    case SASL_SSF_EXTERNAL:
    {
      sasl_external_properties_t *external
	= (sasl_external_properties_t *) value;
      if (external->auth_id && strlen(external->auth_id)) {
	result = _sasl_strdup(external->auth_id,
			      &str,
			      NULL);
	if (result != SASL_OK)
	  return result;
      } else
	str = NULL;
      if (conn->external.auth_id)
	sasl_FREE(conn->external.auth_id);
      conn->external.auth_id = NULL;
      conn->external.ssf = external->ssf;
      break;
    }
    case SASL_SEC_PROPS:
      memcpy(&(conn->props),(sasl_security_properties_t *)value,
	     sizeof(sasl_security_properties_t));
      break;
    case SASL_IP_LOCAL:
      conn->got_ip_local = 1;
      conn->ip_local= *(struct sockaddr_in *) value;
      break;
    case SASL_IP_REMOTE:
      conn->got_ip_remote = 1;
      conn->ip_remote= *(struct sockaddr_in *) value;
      break;
    default:
      result = SASL_BADPARAM;
  }
  sasl_MUTEX_UNLOCK(conn->mutex);
  return result;
}

int sasl_usererr(int saslerr)
{
  if (saslerr==SASL_NOUSER)
    return SASL_BADAUTH;

  /* return the error given; no transform necessary */
  return saslerr;
}

const char *sasl_errstring(int saslerr,
			   const char *langlist __attribute__((unused)),
			   const char **outlang)
{
  if (outlang) *outlang="en-us";

  switch(saslerr)
    {
    case SASL_CONTINUE: return "another step is needed in authentication";
    case SASL_OK:       return "successful result";
    case SASL_FAIL:     return "generic failure";
    case SASL_NOMEM:    return "no memory available";
    case SASL_BUFOVER:  return "overflowed buffer";
    case SASL_NOMECH:   return "no mechanism available";
    case SASL_BADPROT:  return "bad protocol / cancel";
    case SASL_NOTDONE:  return "can't request info until later in exchange";
    case SASL_BADPARAM: return "invalid parameter supplied (probably config file)";
    case SASL_TRYAGAIN: return "transient failure (e.g., weak key)";
    case SASL_BADMAC:   return "integrity check failed";
                             /* -- client only codes -- */
    case SASL_INTERACT:   return "needs user interaction";
    case SASL_BADSERV:    return "server failed mutual authentication step";
    case SASL_WRONGMECH:  return "mechanism doesn't support requested feature";
    case SASL_NEWSECRET:  return "new secret needed";
                             /* -- server only codes -- */
    case SASL_BADAUTH:    return "authentication failure";
    case SASL_NOAUTHZ:    return "authorization failure";
    case SASL_TOOWEAK:    return "mechanism too weak for this user";
    case SASL_ENCRYPT:    return "encryption needed to use mechanism";
    case SASL_TRANS:      return "One time use of a plaintext password will enable requested mechanism for user";
    case SASL_EXPIRED:    return "passphrase expired, has to be reset";
    case SASL_DISABLED:   return "account disabled";
    case SASL_NOUSER:     return "user not found";
    case SASL_PWLOCK:     return "password locked";
    case SASL_NOCHANGE:   return "requested change was not needed";
    case SASL_BADVERS:    return "version mismatch with plug-in";
    case SASL_NOPATH:     return "path not set";
    default:   return "undefined error!";
    }

}

static int
_sasl_global_getopt(void *context,
		    const char *plugin_name,
		    const char *option,
		    const char ** result,
		    unsigned *len)
{
  const sasl_global_callbacks_t * global_callbacks;
  const sasl_callback_t *callback;

  if (! context)
    return SASL_FAIL;

  global_callbacks = (const sasl_global_callbacks_t *) context;

  if (global_callbacks && global_callbacks->callbacks)
    for (callback = global_callbacks->callbacks;
	 callback->id != SASL_CB_LIST_END;
	 callback++)
      if (callback->id == SASL_CB_GETOPT
	  && (((sasl_getopt_t *)(callback->proc))(callback->context,
						  plugin_name,
						  option,
						  result,
						  len)
	      == SASL_OK))
	return SASL_OK;

  /* TODO: Someday, we ought to look up options in a global
   * configuration file of some sort.  For now, though, we
   * just default to pretending the option doesn't exist. */
  return SASL_FAIL;
}

static int
_sasl_conn_getopt(void *context,
		  const char *plugin_name,
		  const char *option,
		  const char ** result,
		  unsigned *len)
{
  sasl_conn_t * conn;
  const sasl_callback_t *callback;

  if (! context)
    return SASL_FAIL;

  conn = (sasl_conn_t *) context;

  if (conn->callbacks)
    for (callback = conn->callbacks;
	 callback->id != SASL_CB_LIST_END;
	 callback++)
      if (callback->id == SASL_CB_GETOPT
	  && (((sasl_getopt_t *)(callback->proc))(callback->context,
						  plugin_name,
						  option,
						  result,
						  len)
	      == SASL_OK))
	return SASL_OK;

  /* If we made it here, we didn't find an appropriate callback
   * in the connection's callback list, or the callback we did
   * find didn't return SASL_OK.  So we attempt to use the
   * global callback for this connection... */
  return _sasl_global_getopt((void *)conn->global_callbacks,
			     plugin_name,
			     option,
			     result,
			     len);
}

#ifdef HAVE_VSYSLOG

/* this is the default logging */
static int _sasl_syslog(void *context __attribute__((unused)),
			int priority,
			const char *message)
{
  int syslog_priority;

  /* set syslog priority */
  switch(priority) {
  case SASL_LOG_ERR:
    syslog_priority = LOG_ERR;
  case SASL_LOG_WARNING:
    syslog_priority = LOG_WARNING;
  case SASL_LOG_INFO:
    syslog_priority = LOG_INFO;
    break;
  default:
    return SASL_BADPARAM;
  }

  /* do the syslog call. do not need to call openlog */
  syslog(syslog_priority | LOG_AUTH, message);
  
  return SASL_OK;
}


#endif				/* HAVE_VSYSLOG */

static int
_sasl_getsimple(void *context,
		int id,
		const char ** result,
		unsigned * len)
{
  const char *userid;
  sasl_conn_t *conn;

  if (! context || ! result || ! len)
    return SASL_BADPARAM;

  conn = (sasl_conn_t *)context;

  switch(id) {
  case SASL_CB_USER:
    *result = "";
    *len = 0;
    return SASL_OK;
  case SASL_CB_AUTHNAME:
    userid = getenv("USER");
    if (userid != NULL) {
      *result = userid;
      *len = strlen(userid);
      return SASL_OK;
    }
    return SASL_FAIL;
  default:
    return SASL_BADPARAM;
  }
}

static int
_sasl_getpath(void *context __attribute__((unused)),
	      char ** path_dest)
{
  char *path;

  if (! path_dest)
    return SASL_BADPARAM;
  path = getenv(SASL_PATH_ENV_VAR);
  if (! path)
    path = PLUGINDIR;
  return _sasl_strdup(path, path_dest, NULL);
}

int
_sasl_getcallback(sasl_conn_t * conn,
		  unsigned long callbackid,
		  int (**pproc)(),
		  void **pcontext)
{
  const sasl_callback_t *callback;

  printf("in getcallback\n");

  if (! conn || ! pproc || ! pcontext)
    return SASL_BADPARAM;

  /* Some callbacks are always provided by the library */
  switch (callbackid) {
  case SASL_CB_LIST_END:
    /* Nothing ever gets to provide this */
    return SASL_FAIL;
  case SASL_CB_GETOPT:
    *pproc = &_sasl_conn_getopt;
    *pcontext = conn;
    return SASL_OK;
  }

  printf("in getcallback 2\n");

  /* If it's not always provided by the library, see if there's
   * a version provided by the application for this connection... */
  if (conn->callbacks)
    for (callback = conn->callbacks;
	 callback->id != SASL_CB_LIST_END;
	 callback++)
      if (callback->id == callbackid) {
	*pproc = callback->proc;
	*pcontext = callback->context;
	if (callback->proc)
	  return SASL_OK;
	else
	  return SASL_INTERACT;
      }

  printf("in getcallback 3\n");

  /* And, if not for this connection, see if there's one
   * for all {server,client} connections... */
  if (conn->global_callbacks && conn->global_callbacks->callbacks)
    for (callback = conn->global_callbacks->callbacks;
	 callback->id != SASL_CB_LIST_END;
	 callback++)
      if (callback->id == callbackid) {
	*pproc = callback->proc;
	*pcontext = callback->context;
	if (callback->proc)
	  return SASL_OK;
	else
	  return SASL_INTERACT;
      }

  printf("in getcallback 4\n");

  /* Otherwise, see if the library provides a default callback. */
  switch (callbackid) {
#ifdef HAVE_VSYSLOG
  case SASL_CB_LOG:
    *pproc = (int (*)()) &_sasl_syslog;
    *pcontext = NULL;
    break;
#endif /* HAVE_VSYSLOG */
  case SASL_CB_GETPATH:
    *pproc = (int (*)()) &_sasl_getpath;
    *pcontext = NULL;
    break;
  case SASL_CB_USER:
  case SASL_CB_AUTHNAME:
    *pproc = (int (*)()) &_sasl_getsimple;
    *pcontext = conn;
    break;
  case SASL_CB_SERVER_GETSECRET:
    *pproc = _sasl_server_getsecret_hook;
    *pcontext = NULL;
    break;
  case SASL_CB_SERVER_PUTSECRET:
    *pproc = _sasl_server_putsecret_hook;
    *pcontext = NULL;
    break;
  default:
  printf("in getcallback 4.5\n");
    return SASL_INTERACT;
  }

  printf("in getcallback 5\n");
  return SASL_OK;
}

/* checks size of buffer and resizes if needed */
static int checksize(char **out, int *alloclen, int newlen)
{
  if (*alloclen>newlen+2)
    return SASL_OK;

  *out=sasl_REALLOC(*out, newlen+10);  
  if (! *out) return SASL_NOMEM; 
  
  *alloclen=newlen+10;

  return SASL_OK;
}

/* adds a string to the buffer; reallocing if need be */
static int add_string(char **out, int *alloclen, int *outlen, char *add)
{
  int addlen=strlen(add); /* only compute once */
  if (checksize(out, alloclen, (*outlen)+addlen)!=SASL_OK)
    return SASL_NOMEM;

  strncpy(*out + *outlen, add, addlen);
  *outlen += addlen;

  return SASL_OK;
}

/*
 * This function is typically called froma a plugin.
 * It creates a string from the formatting and varargs given
 * and calls the logging callback (syslog by default)
 */

static int sasl_log (sasl_conn_t *conn,
		     int priority,
		     const char *plugin_name,
		     int sasl_error,	/* %z */
		     int errno,	/* %m */
		     const char *format,
		     ...)
{
  char *out=(char *) sasl_ALLOC(100);
  int alloclen=100; /* current allocated length */
  int outlen=0; /* current length of output buffer */
  int pos=0; /* current position in format string */
  int formatlen=strlen(format);
  int result;
  sasl_log_t *log_cb;
  void *log_ctx;
  
  int ival;
  va_list ap; /* varargs thing */

  /* See if we have a logging callback... */
  result = _sasl_getcallback(conn, SASL_CB_LOG, &log_cb, &log_ctx);
  if (result == SASL_OK && ! log_cb)
    result = SASL_FAIL;
  if (result != SASL_OK)
    return result;
  
  /* add the plugin name */
  if (plugin_name!=NULL)
  {
    result = add_string(&out, &alloclen, &outlen,(char *)
			plugin_name);
    if (result != SASL_OK)
      return result;
    result = add_string(&out, &alloclen, &outlen, ": ");
    if (result != SASL_OK)
      return result;
  }

  va_start(ap, format); /* start varargs */

  while(pos<formatlen)
  {
    if (format[pos]!='%') /* regular character */
    {
      out[outlen]=format[pos];
      result = checksize(&out, &alloclen, outlen+1);
      if (result != SASL_OK)
	return result;
      outlen++;
      pos++;

    } else { /* formating thing */
      int done=0;
      char frmt[10];
      int frmtpos=1;
      char tempbuf[21];
      frmt[0]='%';
      pos++;

      while (done==0)
      {
	switch(format[pos])
	  {
	  case 's': /* need to handle this */
	    ival = va_arg(ap, int); /* get the next arg */
	    result = add_string(&out, &alloclen,
				&outlen, (char *) ival);
	      
	    if (result != SASL_OK) /* add the string */
	      return result;

	    done=1;
	    break;

	  case '%': /* double % output the '%' character */
	    out[outlen]='%';
	    result = checksize(&out,&alloclen,outlen+1);
	    if (result != SASL_OK)
	      return result;
	    outlen++;
	    done=1;
	    break;

	  case 'm': /* insert the errno string */
	    result = add_string(&out, &alloclen, &outlen,
				strerror(errno));
	    if (result != SASL_OK)
	      return result;
	    done=1;
	    break;
	  case 'z': /* insert the sasl error string */
	    result = add_string(&out, &alloclen, &outlen,
				(char *) sasl_errstring(sasl_error,NULL,NULL));
	    if (result != SASL_OK)
	      return result;
	    done=1;
	    break;

	  /* only d, i, o, u, x, or X 
	     c, e,  E, f,  g, or G can end the format thing */
	  case 'c':
	  case 'd':
	  case 'i':
	  case 'o':
	  case 'u':
	  case 'x':
	  case 'X':
	  case 'e':
	  case 'E':
	  case 'f':
	  case 'g':
	  case 'G':
	    frmt[frmtpos++]=format[pos];
	    frmt[frmtpos]=0;
	    ival = va_arg(ap, int); /* get the next arg */

	    snprintf(tempbuf,20,frmt,ival); /* have sprintf do the work */
	    /* now add the string */
	    result = add_string(&out, &alloclen, &outlen, tempbuf);
	    if (result != SASL_OK)
	      return result;
	    done=1;

	    break;
	  default: 
	    frmt[frmtpos++]=format[pos]; /* add to the formating */
	    frmt[frmtpos]=0;	    
	    if (frmtpos>9) 
	      done=1;
	  }
	pos++;
	if (pos>formatlen)
	  done=1;
      }

    }
  }


  out[outlen]=0; /* put 0 at end */

  va_end(ap);    

  /* send log message */
  result = log_cb(log_ctx, priority, out);
  sasl_FREE(out);
  return result;
}

sasl_utils_t *
_sasl_alloc_utils(sasl_conn_t *conn,
		  sasl_global_callbacks_t *global_callbacks)
{
  sasl_utils_t *utils;
  /* set util functions - need to do rest*/
  utils=sasl_ALLOC(sizeof(sasl_utils_t));
  if (utils==NULL)
    return NULL;

  utils->conn = conn;
  if (conn) {
    utils->getopt = &_sasl_conn_getopt;
    utils->getopt_context = conn;
  } else {
    utils->getopt = &_sasl_global_getopt;
    utils->getopt_context = global_callbacks;
  }
  utils->malloc=_sasl_allocation_utils.malloc;
  utils->calloc=_sasl_allocation_utils.calloc;
  utils->realloc=_sasl_allocation_utils.realloc;
  utils->free=_sasl_allocation_utils.free;
  
  utils->MD5Init  = &MD5Init;
  utils->MD5Update= &MD5Update;
  utils->MD5Final = &MD5Final;
  utils->hmac_md5 = &hmac_md5;

  utils->getprop=&sasl_getprop;
  utils->getcallback=&_sasl_getcallback;
  utils->rand=&sasl_rand;

  utils->log=&sasl_log;

  sasl_randcreate(&utils->rpool);
  /* there are more to fill in */

  return utils;
}

int
_sasl_free_utils(sasl_utils_t ** utils)
{
  if (! utils) return SASL_BADPARAM;
  if (! *utils) return SASL_OK;
  sasl_randfree(&(*utils)->rpool);
  sasl_FREE(*utils);
  *utils = NULL;
  return SASL_OK;
}

int sasl_idle(sasl_conn_t *conn)
{
  if (! conn) {
    if (_sasl_server_idle_hook
	&& _sasl_server_idle_hook(NULL))
      return 1;
    if (_sasl_client_idle_hook
	&& _sasl_client_idle_hook(NULL))
      return 1;
    return 0;
  }

  if (conn->idle_hook)
    return conn->idle_hook(conn);

  return 0;
}

const sasl_callback_t *
_sasl_find_getpath_callback(const sasl_callback_t *callbacks)
{
  static const sasl_callback_t default_getpath_cb = {
    SASL_CB_GETPATH,
    &_sasl_getpath,
    NULL
  };

  if (callbacks)
    while (callbacks->id != SASL_CB_LIST_END)
    {
      if (callbacks->id == SASL_CB_GETPATH)
      {
	return callbacks;
      } else {
	++callbacks;
      }
    }
  
  return &default_getpath_cb;
}

