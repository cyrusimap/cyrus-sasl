/* saslplug.h --  API for SASL plug-ins
 */

#ifndef SASLPLUG_H
#define SASLPLUG_H 1

#ifndef MD5GLOBAL_H
#include "md5global.h"
#endif
#ifndef MD5_H
#include "md5.h"
#endif
#ifndef HMAC_MD5_H
#include "hmac-md5.h"
#endif

/* callback to lookup a property from a SASL connection state
 * input:
 *  conn          -- the connection to get a property from
 *  propnum       -- property number
 * output:
 *  pvalue        -- pointer to value
 * returns:
 *  SASL_OK       -- no error
 *  SASL_NOTDONE  -- property not available yet
 *  SASL_BADPARAM -- bad property number
 */
typedef int sasl_getprop_t(sasl_conn_t *conn,
			   int propnum,
			   void **pvalue);

/* callback to lookup a sasl_callback_t for a connnection
 * input:
 *  conn        -- the connection to lookup a callback for
 *  callbacknum -- the number of the callback
 * output:
 *  pproc       -- pointer to the callback function
 *  pcontext    -- pointer to the callback context
 * returns:
 *  SASL_OK -- no error
 *  SASL_FAIL -- unable to find a callback of the requested type
 *  SASL_INTERACT -- caller must use interaction to get data
 */
typedef int sasl_getcallback_t(sasl_conn_t *conn,
			       unsigned long callbackid,
			       int (**pproc)(),
			       void **pcontext);

#ifdef WIN32
/* need to handle the fact that errno has been defined as a function
   in a dll, not an extern int */
#ifdef errno
#undef errno
#endif /* errno */
#endif /* WIN32 */

/* utility function set for plug-ins
 */
typedef struct sasl_utils {
    int version;

    /* contexts */
    sasl_conn_t *conn;
    sasl_rand_t *rpool;
    void *getopt_context;

    /* option function */
    sasl_getopt_t *getopt;

    /* property function */
    sasl_getprop_t *getprop;

    /* allocation functions: */
    sasl_malloc_t *malloc;
    sasl_calloc_t *calloc;
    sasl_realloc_t *realloc;
    sasl_free_t *free;

    /* mutex functions: */
    sasl_mutex_new_t *mutex_new;
    sasl_mutex_lock_t *mutex_lock;
    sasl_mutex_unlock_t *mutex_unlock;
    sasl_mutex_dispose_t *mutex_dispose;

    /* MD5 hash and HMAC functions */
    void (*MD5Init)(MD5_CTX *);
    void (*MD5Update)(MD5_CTX *, const unsigned char *text, unsigned int len);
    void (*MD5Final)(unsigned char [16], MD5_CTX *);
    void (*hmac_md5)(const unsigned char *text, int text_len,
		    const unsigned char *key, int key_len,
		    unsigned char [16]);
    void (*hmac_md5_init)(HMAC_MD5_CTX *, const unsigned char *key, int len);
    /* hmac_md5_update() is just a call to MD5Update on inner context */
    void (*hmac_md5_final)(unsigned char [16], HMAC_MD5_CTX *);
    void (*hmac_md5_precalc)(HMAC_MD5_STATE *, const unsigned char *key,
			     int len);
    void (*hmac_md5_import)(HMAC_MD5_CTX *, HMAC_MD5_STATE *);

    /* mechanism utility functions (same as above): */
    int (*mkchal)(sasl_conn_t *conn, char *buf, unsigned maxlen, int hostflag);
    int (*utf8verify)(const char *str, unsigned len);
    void (*rand)(sasl_rand_t *rpool, char *buf, unsigned len);
    void (*churn)(sasl_rand_t *rpool, const char *data, unsigned len);

    /* current CMU hack.  DO NOT USE EXCEPT IN PLAIN */
    int (*checkpass)(sasl_conn_t *conn,
		     const char *mech, const char *service,
		     const char *user, const char *pass, 
		     const char **errstr);

    /* callback function */
    sasl_getcallback_t *getcallback;

    /* logging */
    int (*log)(sasl_conn_t *conn,
	       int priority,
	       const char *plugin_name,
	       int sasl_error,	/* %z */
	       int errno,	/* %m */
	       const char *format,
	       ...);
} sasl_utils_t;

/* variable sized secret structure created by client mechanism
 *
 * structure uses offsets to allow it to be copied & saved
 *
 * buf contains the mechanism specific data followed by the mechanism
 *  name (NUL terminated) followed by the user name (NUL terminated)
 * mechoffset is offset in buf to start of mechanism name (0 = plain mech)
 * useroffset is offset in buf to start of user name
 *
 * PLAIN:
 *   len = passlen + userlen + 2
 *   mechoffset = 0
 *   useroffset = passlen + 1
 *   <password> NUL
 *   <username> NUL
 * CRAM-MD5/SCRAM-MD5:
 *   len = userlen + 50
 *   mechoffset = 32
 *   useroffset = 41
 *   <HMAC-MD5 pre-result, big-endian>
 *   "CRAM-MD5" NUL
 *   <username> NUL
 */
typedef struct sasl_mech_secret {
    unsigned long len;
    unsigned long mechoffset;	/* 0 if plain mechanism */
    unsigned long useroffset;
    char buf[1];
} sasl_mech_secret_t;

typedef struct sasl_credentials sasl_credentials_t;

/* output parameters from SASL API
 */
typedef struct sasl_out_params {
    int doneflag;		/* exchange complete */
    sasl_ssf_t mech_ssf;	/* security layer strength factor of mech */
    unsigned maxoutbuf;		/* max plain output to security layer */

    /* mic functions differs from encode in that the output is intended to be
     * appended to the input rather than an encapsulated variant of it.
     * a plugin which supports getmic()/verifymic() but not
     * encode()/decode() should be exportable.  Ditto for framework.
     * datalen param of verifymic returns length of data in buffer
     */
    void *encode_context;
    int (*encode)(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen);
    int (*getmic)(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen);
    void *decode_context;
    int (*decode)(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen);
    int (*verifymic)(void *context, const char *input, unsigned inputlen,
		     unsigned *datalen);

    char *user; 		/* canonicalized user name */
    char *authid;		/* canonicalized authentication id */
    char *realm;		/* security realm */

    /* set to 0 initially, this allows a plugin with extended parameters
     * to work with an older framework by updating version as parameters
     * are added.
     */
    int param_version;

    /* Credentials passed by clients.  NOTE: this should ONLY
     * be set by server plugins. */
    sasl_credentials_t *credentials;
} sasl_out_params_t;

/******************************
 * Client Mechanism Functions *
 ******************************/

/* input parameters to client SASL plugin
 */
typedef struct sasl_client_params {
    const char *service;	  /* service name */
    const char *pass;		  /* plaintext passphrase, if used */
    const char *serverFQDN;	  /* server fully qualified domain name */
    const char *clientFQDN;	  /* client's local domain name */
    sasl_utils_t *utils;	  /* SASL API utility routines */
    sasl_mech_secret_t *secret;	  /* mech-specific decrypted secret */

    /* application's security requirements & info */
    sasl_security_properties_t props;
    sasl_ssf_t external_ssf;	/* external SSF active */

    /* set to 0 initially, this allows a plugin with extended parameters
     * to work with an older framework by updating version as parameters
     * are added.
     */
    int param_version;
} sasl_client_params_t;

/* a C object for a client mechanism
 */
typedef struct sasl_client_plug {
    /* mechanism name */
    const char *mech_name;

    /* best mech additional security layer strength factor */
    sasl_ssf_t max_ssf;

    /* best security flags, as defined in sasl_security_properties_t */
    int security_flags;

    /* required prompt ids, NULL = user/pass only */
    const long *required_prompts;
    
    /* global state for mechanism */
    void *glob_context;
    
    /* create context for mechanism, using params supplied
     *  glob_context   -- from above
     *  params         -- params from sasl_client_new
     *  conn_context   -- context for one connection
     * returns:
     *  SASL_OK        -- success
     *  SASL_NOMEM     -- not enough memory
     *  SASL_WRONGMECH -- mech doesn't support security params
     */
    int (*mech_new)(void *glob_context,
    		    sasl_client_params_t *params,
    		    void **conn_context);
    
    /* perform one step of exchange.  NULL is passed for serverin on
     * first step.
     * returns:
     *  SASL_OK        -- success
     *  SASL_INTERACT  -- user interaction needed to fill in prompts
     *  SASL_BADPROT   -- server protocol incorrect/cancelled
     *  SASL_BADSERV   -- server failed mutual auth
     */
    int (*mech_step)(void *conn_context,
    		     sasl_client_params_t *params,
    		     const char *serverin,
    		     int serverinlen,
		     sasl_interact_t **prompt_need,
    		     char **clientout,
    		     int *clientoutlen,
		     sasl_out_params_t *oparams);
    
    /* dispose of connection context from mech_new
     */
    void (*mech_dispose)(void *conn_context, sasl_utils_t *utils);
    
    /* free all global space used by mechanism
     *  mech_dispose must be called on all mechanisms first
     */
    void (*mech_free)(void *glob_context, sasl_utils_t *utils);
    
    /* create an authentication secret (optional)
     *  glob_context -- from above
     *  user         -- user name
     *  pass         -- password/passphrase
     *  passlen      -- length of password/passphrase
     *  prompts      -- prompts result list, from mech_new or middleware
     *  utils        -- middleware utilities (e.g., MD5, SHA-1)
     * output:
     *  psecret      -- gets unencrypted secret
     *
     * returns:
     *  SASL_INTERACT -- not enough of prompts supplied
     *  SASL_OK       -- success
     *  SASL_BADPARAM -- wrong prompts supplied
     *  SASL_NOMEM    -- out of memory
     *  SASL_NOMECH   -- missing utility functions
     */
    int (*auth_create)(void *glob_context,
    		       const char *user,
    		       const char *pass,
    		       int passlen,
    		       sasl_interact_t *prompts,
    		       sasl_utils_t *utils,
    		       sasl_mech_secret_t **psecret);
     
     /* perform precalculations during a network round-trip
      *  or idle period.  conn_context may be NULL
      *  returns 1 if action taken, 0 if no action taken
      */
     int (*idle)(void *glob_context,
     		 void *conn_context,
     		 sasl_client_params_t *cparams);
} sasl_client_plug_t;

#define SASL_CLIENT_PLUG_VERSION 3

/* plug-in entry point:
 *  utils       -- utility callback functions
 *  max_version -- highest client plug version supported
 * returns:
 *  out_version -- client plug version of result
 *  pluglist    -- list of mechanism plug-ins
 *  plugcount   -- number of mechanism plug-ins
 * results:
 *  SASL_OK       -- success
 *  SASL_NOMEM    -- failure
 *  SASL_BADVERS  -- max_version too small
 *  SASL_BADPARAM -- bad config string
 *  ...
 */
typedef int sasl_client_plug_init_t(sasl_utils_t *utils,
				    int max_version,
				    int *out_version,
				    const sasl_client_plug_t **pluglist,
				    int *plugcount);

/********************
 * Server Functions *
 ********************/

/* input parameters to server SASL plugin
 */
typedef struct sasl_server_params {
    const char *service;	/* NULL = default service for user_exists
				   and setpass */
    const char *appname;	/* name of calling application */
    const char *serverFQDN;	/* local domain name */
    const char *user_realm;	/* set of users who are active */
    sasl_utils_t *utils;	/* SASL API utility routines */

    /* application's security requirements */
    sasl_security_properties_t props;
    sasl_ssf_t external_ssf;	/* external SSF active */

    /* server plug-in calls this when it first has access to the plaintext
     *  passphrase.  This is used to transition users via setpass calls.
     *  If passlen is 0, it defaults to strlen(pass).
     *  returns 0 if no entry added, 1 if entry added
     */
    int (*transition)(sasl_conn_t *conn, const char *pass, int passlen);
    const char *retain_users;	/* users exempt from password REMOVE/DISABLE */

    /* set to 0 initially, this allows a plugin with extended parameters
     * to work with an older framework by updating version as parameters
     * are added.
     */
    int param_version;
} sasl_server_params_t;

/* additional flags for setpass() function below:
 */
/*      SASL_SET_CREATE                     create user if pass non-NULL */
/*      SASL_SET_DISABLE                    disable user */
#define SASL_SET_REMOVE  SASL_SET_CREATE /* remove user if pass is NULL */

/* a C object for a server mechanism
 */
typedef struct sasl_server_plug {
    /* mechanism name */
    const char *mech_name;

    /* best mech additional security layer strength factor */
    sasl_ssf_t max_ssf;

    /* best security flags, as defined in sasl_security_properties_t */
    int security_flags;
    
    /* global state for mechanism */
    void *glob_context;

    /* create a new mechanism handler
     *  glob_context  -- global context
     *  sparams       -- server config params
     *  challenge     -- server challenge from previous instance or NULL
     *  challen       -- length of challenge from previous instance or 0
     * out:
     *  conn_context  -- connection context
     *  errstr        -- optional reply error string
     *
     * returns:
     *  SASL_OK       -- successfully created mech instance
     *  SASL_*        -- any other server error code
     */
    int (*mech_new)(void *glob_context,
    		    sasl_server_params_t *sparams,
		    const char *challenge,
		    int challen,
    		    void **conn_context,
    		    const char **errstr);
    
    /* perform one step in exchange
     *
     * returns:
     *  SASL_OK       -- success, all done
     *  SASL_CONTINUE -- success, one more round trip
     *  SASL_*        -- any other server error code
     */
    int (*mech_step)(void *conn_context,
    		     sasl_server_params_t *sparams,
    		     const char *clientin,
    		     int clientinlen,
    		     char **serverout,
    		     int *serveroutlen,
		     sasl_out_params_t *oparams,
    		     const char **errstr);
    
    /* dispose of a connection state
     */
    void (*mech_dispose)(void *conn_context, sasl_utils_t *utils);
    
    /* free global state for mechanism
     *  mech_dispose must be called on all mechanisms first
     */
    void (*mech_free)(void *glob_context, sasl_utils_t *utils);
    
    /* set a password (optional)
     *  glob_context  -- global context
     *  sparams       -- service, middleware utilities, etc. props ignored
     *  user          -- user name
     *  pass          -- password/passphrase (NULL = disable/remove/delete)
     *  passlen       -- length of password/passphrase
     *  flags         -- see above
     *  errstr        -- may be set to detailed error string
     *
     * returns:
     *  SASL_NOCHANGE -- no change was needed
     *  SASL_NOUSER   -- no entry for user
     *  SASL_NOMECH   -- no mechanism compatible entry for user
     *  SASL_PWLOCK   -- password locked
     *  SASL_DIABLED  -- account disabled
     *  etc.
     */
    int (*setpass)(void *glob_context,
    		   sasl_server_params_t *sparams,
    		   const char *user,
    		   const char *pass,
    		   unsigned passlen,
    		   int flags,
		   const char **errstr);

    /* query which mechanisms are available to user
     *  glob_context  -- context
     *  sparams       -- service, middleware utilities, etc. props ignored
     *  user          -- NUL terminated user name
     *  maxmech       -- max number of strings in mechlist (0 = no output)
     * output:
     *  mechlist      -- an array of C string pointers, filled in with
     *                   mechanism names available to the user
     *
     * returns:
     *  SASL_OK       -- success
     *  SASL_NOMEM    -- not enough memory
     *  SASL_FAIL     -- lower level failure
     *  SASL_DISABLED -- account disabled
     *  SASL_NOUSER   -- user not found
     *  SASL_BUFOVER  -- maxmech is too small
     *  SASL_NOMECH   -- user found, but no mechanisms available
     */
    int (*user_query)(void *glob_context,
		      sasl_server_params_t *sparams,
		      const char *user,
		      int maxmech,
		      const char **mechlist);
     
     /* perform precalculations during a network round-trip
      *  or idle period.  conn_context may be NULL (optional)
      *  returns 1 if action taken, 0 if no action taken
      */
     int (*idle)(void *glob_context,
     		 void *conn_context,
     		 sasl_server_params_t *sparams);

     /* install credentials returned earlier by the plugin. */
     int (*install_credentials)(void *conn_context,
				sasl_credentials_t *credentials);
     /* uninstall credentials returned earlier by the plugin. */
     int (*uninstall_credentials)(void *conn_context,
				  sasl_credentials_t *credentials);
     /* free credentials returned earlier by the plugin. */
     int (*dispose_credentials)(void *conn_context,
				sasl_credentials_t *credentials);
} sasl_server_plug_t;

#define SASL_SERVER_PLUG_VERSION 3

/* plug-in entry point:
 *  utils         -- utility callback functions
 *  max_version   -- highest server plug version supported
 * returns:
 *  out_version   -- server plug-in version of result
 *  pluglist      -- list of mechanism plug-ins
 *  plugcount     -- number of mechanism plug-ins
 * results:
 *  SASL_OK       -- success
 *  SASL_NOMEM    -- failure
 *  SASL_BADVERS  -- max_version too small
 *  SASL_BADPARAM -- bad config string
 *  ...
 */
typedef int sasl_server_plug_init_t(sasl_utils_t *utils,
				    int max_version,
				    int *out_version,
				    const sasl_server_plug_t **pluglist,
				    int *plugcount);

#endif /* SASLPLUG_H */

