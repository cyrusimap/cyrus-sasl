/* This is a proposed C API for support of SASL
 *
 * Basic Type Summary:
 *  sasl_conn_t       Context for a SASL connection negotiation
 *  sasl_ssf_t        Security layer Strength Factor
 *  sasl_callback_t   A typed client/server callback function and context
 *  sasl_interact_t   A client interaction descriptor
 *  sasl_secret_t     A client authentication secret/credentials/passphrase
 *  sasl_rand_t       Random data context structure
 *  sasl_security_properties_t  An application's required security level
 *  sasl_external_properties_t  Security provided by an external security layer
 *
 * Callbacks:
 *  sasl_getopt_t     client/server: Get an option value
 *  sasl_log_t        client/server: Log message handler
 *  sasl_getpath_t    client/server: Get path to search for mechanisms
 *  sasl_getsimple_t  client: Get user/language list
 *  sasl_getsecret_t  client: Get authentication secret
 *  sasl_chalprompt_t client: Display challenge and prompt for response
 *  sasl_authorize_t  server: Authorize policy callback
 *  sasl_server_getsecret_t server: User secret database read
 *  sasl_server_putsecret_t server: User secret database write
 *
 * Client/Server Function Summary:
 *  sasl_done         Release all SASL global state
 *  sasl_dispose      Connection done: Dispose of sasl_conn_t
 *  sasl_getprop      Get property (e.g., user name, security layer info)
 *  sasl_setprop      Set property (e.g., external ssf)
 *  sasl_usererr      Translate server error code to user error code
 *  sasl_errstring    Translate sasl error code to a string
 *  sasl_encode       Encode data to send using security layer
 *  sasl_decode       Decode data received using security layer
 *
 * Client Function Summary:
 *  sasl_client_init  Load and initialize client plug-ins (call once)
 *  sasl_client_new   Initialize client connection context: sasl_conn_t
 *  sasl_client_start Select mechanism for connection
 *  sasl_client_step  Perform one authentication step
 *  sasl_client_auth  Create client secret (e.g., from a user & passphrase)
 *  sasl_free_secret  Erase & Dispose of a sasl_secret_t
 *
 * Server Function Summary
 *  sasl_server_init  Load and initialize server plug-ins (call once)
 *  sasl_server_new   Initialize server connection context: sasl_conn_t
 *  sasl_listmech     Create list of available mechanisms
 *  sasl_server_start Begin an authentication exchange
 *  sasl_server_step  Perform one authentication exchange step
 *  sasl_checkpass    Check a plaintext passphrase
 *  sasl_userexists   Check if user exists
 *  sasl_setpass      Change a password or add a user entry
 *
 * Basic client model:
 *  1. client calls sasl_client_init() at startup to load plug-ins
 *  2. when connection formed, call sasl_client_new()
 *  3. once list of supported mechanisms received from server, client
 *     calls sasl_client_start().  goto 4a
 *  4. client calls sasl_client_step()
 * [4a. If SASL_INTERACT, fill in prompts and goto 4
 *      -- doesn't happen if callbacks provided]
 *  4b. If SASL error, goto 7 or 3
 *  4c. If SASL_OK, continue or goto 6 if last server response was success
 *  5. send message to server, wait for response
 *  5a. On data or success with server response, goto 4
 *  5b. On failure goto 7 or 3
 *  5c. On success with no server response continue
 *  6. continue with application protocol until connection closes
 *     call sasl_getprop/sasl_encode/sasl_decode() if using security layer
 *  7. call sasl_dispose(), may return to step 2
 *  8. call sasl_done() when program terminates
 *
 * Basic Server model:
 *  1. call sasl_server_init() at startup to load plug-ins
 *  2. On connection, call sasl_server_new()
 * [3. call sasl_listmech() and send list to client]
 *  4. after client AUTH command, call sasl_server_start(), goto 5a
 *  5. call sasl_server_step()
 *  5a. If SASL_CONTINUE, output to client, wait response, repeat 5
 *  5b. If SASL error, then goto 7
 *  5c. If SASL_OK, move on
 *  6. continue with application protocol until connection closes
 *     call sasl_getprop/sasl_encode/sasl_decode() if using security layer
 *  7. call sasl_dispose(), may return to step 2
 *  8. call sasl_done() when program terminates
 *
 */

#ifndef SASL_H
#define SASL_H 1

#define SASL_VERSION_MAJOR 1
#define SASL_VERSION_MINOR 5
#define SASL_VERSION_STEP 28

/* The following ifdef block is the standard way of creating macros
 * which make exporting from a DLL simpler. All files within this DLL
 * are compiled with the LIBSASL_EXPORTS symbol defined on the command
 * line. this symbol should not be defined on any project that uses
 * this DLL. This way any other project whose source files include
 * this file see LIBSASL_API functions as being imported from a DLL,
 * wheras this DLL sees symbols defined with this macro as being
 * exported.  */
/* Under Unix, life is simpler: we just need to mark library functions
 * as extern.  (Technically, we don't even have to do that.) */
#ifdef WIN32
# ifdef LIBSASL_EXPORTS
#  define LIBSASL_API  __declspec(dllexport)
# else /* LIBSASL_EXPORTS */
#  define LIBSASL_API  __declspec(dllimport)
# endif /* LIBSASL_EXPORTS */
#else /* WIN32 */
# define LIBSASL_API extern
#endif /* WIN32 */

/*************
 * Basic API *
 *************/

/* SASL result codes: */
#define SASL_CONTINUE   (1)  /* another step is needed in authentication */
#define SASL_OK         (0)  /* successful result */
#define SASL_FAIL      (-1)  /* generic failure */
#define SASL_NOMEM     (-2)  /* memory shortage failure */
#define SASL_BUFOVER   (-3)  /* overflowed buffer */
#define SASL_NOMECH    (-4)  /* mechanism not supported */
#define SASL_BADPROT   (-5)  /* bad protocol / cancel */
#define SASL_NOTDONE   (-6)  /* can't request info until later in exchange */
#define SASL_BADPARAM  (-7)  /* invalid parameter supplied */
#define SASL_TRYAGAIN  (-8)  /* transient failure (e.g., weak key) */
#define SASL_BADMAC    (-9)  /* integrity check failed */
                             /* -- client only codes -- */
#define SASL_INTERACT   (2)  /* needs user interaction */
#define SASL_BADSERV   (-10) /* server failed mutual authentication step */
#define SASL_WRONGMECH (-11) /* mechanism doesn't support requested feature */
#define SASL_NEWSECRET (-12) /* new secret needed */
                             /* -- server only codes -- */
#define SASL_BADAUTH   (-13) /* authentication failure */
#define SASL_NOAUTHZ   (-14) /* authorization failure */
#define SASL_TOOWEAK   (-15) /* mechanism too weak for this user */
#define SASL_ENCRYPT   (-16) /* encryption needed to use mechanism */
#define SASL_TRANS     (-17) /* One time use of a plaintext password will
				enable requested mechanism for user */
#define SASL_EXPIRED   (-18) /* passphrase expired, has to be reset */
#define SASL_DISABLED  (-19) /* account disabled */
#define SASL_NOUSER    (-20) /* user not found */
#define SASL_PWLOCK    (-21) /* password locked */
#define SASL_NOCHANGE  (-22) /* requested change was not needed */
#define SASL_BADVERS   (-23) /* version mismatch with plug-in */

#define SASL_NOPATH    (-25) /* path not set */

/* max size of a sasl mechanism name */
#define SASL_MECHNAMEMAX 20

/* per-connection SASL negotiation state for client or server
 */
typedef struct sasl_conn sasl_conn_t;

/* opaque passphrase/secret kept encrypted by API middleware
 *  can be used by caller for single sign-on
 * client "KEY" option will be used as key for
 *  clients which offer a save-to-disk option.
 */
typedef struct sasl_secret {
    unsigned long len;
    char data[1];		/* variable sized */
} sasl_secret_t;

/* random data context structure
 */
typedef struct sasl_rand_s sasl_rand_t;


/****************************
 * Configure Basic Services *
 ****************************/

/* the following functions are used to adjust how allocation and mutexes work
 * they must be called before all other SASL functions:
 */

/* memory allocation functions which may optionally be replaced:
 */
typedef void *sasl_malloc_t(unsigned long);
typedef void *sasl_calloc_t(unsigned long, unsigned long);
typedef void *sasl_realloc_t(void *, unsigned long);
typedef void sasl_free_t(void *);

LIBSASL_API void sasl_set_alloc(sasl_malloc_t *,
				sasl_calloc_t *,
				sasl_realloc_t *,
                                sasl_free_t *);

/* mutex functions which may optionally be replaced:
 *  sasl_mutex_new allocates a mutex structure
 *  sasl_mutex_lock blocks until mutex locked
 *   returns SASL_FAIL on deadlock or parameter error
 *   returns SASL_OK on success
 *  sasl_mutex_unlock unlocks mutex if it's locked
 *   returns SASL_FAIL if not locked or parameter error
 *   returns SASL_OK on success
 */
typedef void *sasl_mutex_new_t();
typedef int sasl_mutex_lock_t(void *mutex);
typedef int sasl_mutex_unlock_t(void *mutex);
typedef void sasl_mutex_dispose_t(void *mutex);

LIBSASL_API void sasl_set_mutex(sasl_mutex_new_t *, sasl_mutex_lock_t *,
                                sasl_mutex_unlock_t *, sasl_mutex_dispose_t *);

/*****************************
 * Security preference types *
 *****************************/

/* security layer strength factor -- an unsigned integer usable by the caller
 *  to specify approximate security layer strength desired.  Roughly
 *  correlated to effective key length for encryption.
 * 0   = no protection
 * 1   = integrity protection only
 * 40  = 40-bit DES or 40-bit RC2/RC4
 * 56  = DES
 * 112 = triple-DES
 * 128 = 128-bit RC2/RC4/BLOWFISH
 */
typedef unsigned sasl_ssf_t;

/* secflags provided on sasl_server_new and sasl_client_new:
 */
#define SASL_SECURITY_LAYER (0x0001) /* caller supports security layer */

/***************************
 * Security Property Types *
 ***************************/

/* Structure specifying the client or server's security policy
 * and optional additional properties.
 */

/* These are the various security flags apps can specify. */
/* NOPLAINTEXT          -- don't permit mechanisms susceptible to simple
 *                         passive attack (e.g., PLAIN, LOGIN)
 * NOACTIVE             -- protection from active (non-dictionary) attacks
 *                         during authentication exchange.
 * 			   Authenticates server.
 * NODICTIONARY         -- don't permit mechanisms susceptible to passive
 *                         dictionary attack
 * FORWARD_SECRECY      -- require forward secrecy between sessions
 *                         (breaking one won't help break next)
 * NOANONYMOUS          -- don't permit mechanisms that allow anonymous login
 * PASS_CREDENTIALS     -- require mechanisms which pass client
 *			   credentials, and allow mechanisms which can pass
 *			   credentials to do so
 */
#define SASL_SEC_NOPLAINTEXT     (0x0001)
#define SASL_SEC_NOACTIVE        (0x0002)
#define SASL_SEC_NODICTIONARY    (0x0004)
#define SASL_SEC_FORWARD_SECRECY (0x0008)
#define SASL_SEC_NOANONYMOUS     (0x0010)
#define SASL_SEC_PASS_CREDENTIALS (0x0200)

typedef struct sasl_security_properties 
{
    /* security strength factor
     *  min_ssf      = minimum acceptable final level
     *  max_ssf      = maximum acceptable final level
     */ 
    sasl_ssf_t min_ssf;
    sasl_ssf_t max_ssf;

    /* Maximum security layer receive buffer size.
     *  0=security layer not supported
     */
    unsigned maxbufsize; 
    
    /* bitfield for security properties -- see SASL_SEC_* above */
    int security_flags;

    /* NULL terminated array of additional property names, values */ 
    const char **property_names;
    const char **property_values;
} sasl_security_properties_t; 


/* Structure communicating the characteristics of an external security
 * mechanism.  This is used with sasl_setprop() to inform the library
 * of an active external security layer.  If the auth_id is non-NULL,
 * this enables the EXTERNAL authentication mechanism; this may also
 * allow other mechanisms to become active (for instance, if an
 * application demands encryption, mechanisms which solely provide
 * authentication might become active if the necessary encryption is
 * provided external to SASL).  Since this potentially changes the
 * list of supported mechanisms, the mechanism list should be re-sent,
 * if it has been sent already.  */
typedef struct sasl_external_properties
{
  /* security provided by the external mechanism */
  sasl_ssf_t ssf;

  /* authorization identity provided by the external mechanism */
  char *auth_id;
} sasl_external_properties_t;

/******************
 * Callback types *
 ******************/

/* Extensible type for a client/server callbacks
 *  id      -- identifies callback type
 *  proc    -- procedure call arguments vary based on id
 *  context -- context passed to procedure
 */
typedef struct sasl_callback {
    /* Identifies the type of the callback function.
     * Mechanisms must ignore callbacks with id's they don't recognize.
     */
    unsigned long id;
    int (*proc)();  /* Callback function.  Types of arguments vary by 'id' */
    void *context;
} sasl_callback_t;

/* callback ids & functions:
 */
#define SASL_CB_LIST_END  (0) /* end of list */

/* option reading callback -- this allows a SASL configuration to be
 *  encapsulated in the caller's configuration system.  Some implementations
 *  may use default config file(s) if this is omitted.  Configuration items
 *  may be plugin-specific and are arbitrary strings.
 *
 * inputs:
 *  context     -- option context from callback record
 *  plugin_name -- name of plugin (NULL = general SASL option)
 *  option      -- name of option
 * output:
 *  result      -- set to result which persists until next getopt in
 *                 same thread, unchanged if option not found
 *  len         -- length of result (optional)
 * returns:
 *  SASL_OK     -- no error
 *  SASL_FAIL   -- error
 */
typedef int sasl_getopt_t(void *context, const char *plugin_name,
			  const char *option,
			  const char **result, unsigned *len);
#define SASL_CB_GETOPT      (1)

/* Logging levels for use with the logging callback function. */
#define SASL_LOG_ERR        (1) /* error message */
#define SASL_LOG_WARNING    (2) /* warning message */
#define SASL_LOG_INFO       (3) /* normal message */

/* logging callback -- this allows plugins and the middleware to
 *  log operations they perform.
 * inputs:
 *  context     -- logging context from the callback record
 *  priority    -- logging priority; see above
 *  message     -- message to log
 * returns:
 *  SASL_OK     -- no error
 *  SASL_FAIL   -- error
 */
typedef int sasl_log_t(void *context,
		       int priority,
		       const char *message);

#define SASL_CB_LOG	    (2)

/* getpath callback -- this allows applications to specify the
 * colon-separated path to search for plugins (by default,
 * taken from the SASL_PATH environment variable).
 * inputs:
 *  context     -- getpath context from the callback record
 * outputs:
 *  path	-- colon seperated path (allocated on the heap; the
 *                 library will free it using the sasl_free_t *
 *                 passed to sasl_set_alloc(), or the standard free()
 *                 library call).
 * returns:
 *  SASL_OK     -- no error
 *  SASL_FAIL   -- error
 */
typedef int sasl_getpath_t(void * context,
			   char ** path);

#define SASL_CB_GETPATH	    (3)

/* verify file callback -- this allows applications to check if they
 * want SASL to use files, file by file.  This is intended to allow
 * applications to sanity check the environment to make sure plugins
 * or the configuration file can't be written to, etc.
 * inputs: 
 *  context     -- verifypath context from the callback record
 *  file        -- full path to file to verify
 *  type        -- type of file to verify

 * returns:
 *  SASL_OK        -- no error (file can safely be used)
 *  SASL_CONTINUE  -- continue WITHOUT using this file
 *  SASL_FAIL      -- error 
 */
typedef int sasl_verifyfile_t(void * context,
                              const char * file, const int type);

#define SASL_CB_VERIFYFILE  (4)

/* these are the types of files libsasl will ask about */
#define SASL_VRFY_PLUGIN	(1)
#define SASL_VRFY_CONF		(2)
#define SASL_VRFY_PASSWD	(3)
#define SASL_VRFY_OTHER		(4)

/* client/user interaction callbacks:
 */
/* Simple prompt -- result must persist until next call to getsimple or
 *  until connection context is disposed
 * inputs:
 *  context       -- context from callback structure
 *  id            -- callback id
 * outputs:
 *  result        -- set to NUL terminated string
 *                   NULL = user cancel
 *  len           -- length of result, ignored with SASL_CB_SECRET
 * returns SASL_OK
 */
typedef int sasl_getsimple_t(void *context, int id,
			     const char **result, unsigned *len);
#define SASL_CB_USER        (0x4001) /* client user identity to login as */
#define SASL_CB_AUTHNAME    (0x4002) /* client authentication name,
			              * defaults to authid in sasl_secret_t */
#define SASL_CB_LANGUAGE    (0x4003) /* comma separated list of RFC 1766
			              * language codes in order of preference
				      * to be used to localize client prompts
				      * or server error codes */

/* get a sasl_secret_t
 *  psecret -- may be left NULL if sasl_client_auth() called
 * returns SASL_OK
 */
typedef int sasl_getsecret_t(sasl_conn_t *conn, void *context, int id,
			     sasl_secret_t **psecret);
#define SASL_CB_PASS        (0x4004) /* client passphrase-based secret */


/* prompt for input in response to a challenge, result is copied & erased
 *  by caller.
 * input:
 *  context   -- context from callback structure
 *  id        -- callback id
 *  challenge -- server challenge
 * output:
 *  result    -- NUL terminated result, NULL = user cancel
 *  len       -- length of result
 * returns SASL_OK
 */
typedef int sasl_chalprompt_t(void *context, int id,
			      const char *challenge,
			      const char *prompt, const char *defresult,
			      const char **result, unsigned *len);
#define SASL_CB_ECHOPROMPT   (0x4005) /* challenge and client-entered result */
#define SASL_CB_NOECHOPROMPT (0x4006) /* challenge and client-entered result */

/* prompt (or autoselect) the realm to do authentication in.
 *  may get a list of valid realms.
 * input:
 *  context     -- context from callback structure
 *  id          -- callback id
 *  availrealms -- available realms; string list; NULL terminated
 * output:
 *  result      -- NUL terminated realm; NULL is equivalent to ""
 * returns SASL_OK
 * result must persist until the next callback
 */
/* If there is an interaction with SASL_CB_GETREALM the challenge of
 *  the sasl_interact_t will be of the format: {realm1, realm2,
 *  ...}. That is a list of possible realms seperated by comma spaces
 *  enclosed by brackets. 
 */
typedef int sasl_getrealm_t(void *context, int id,
			    const char **availrealms,
			    const char **result);
#define SASL_CB_GETREALM (0x4007) /* realm to attempt authentication in */


/* server callbacks:
 */
/* callback to verify authorization
 *  requested_user -- the identity/username to authorize
 *  auth_identity  -- the identity associated with the secret
 *                    if the identity is not in the realm specified in
 *                    sasl_server_new, it will be of the form user@realm
 * return:
 *  user           -- NULL = requested_user, otherwise canonicalized
 *  errstr         -- can be set to error string on failure
 * returns SASL_OK on success, SASL_BADAUTH or other SASL response on failure
 */
typedef int sasl_authorize_t(void *context,
			     const char *auth_identity,
			     const char *requested_user,
			     const char **user,
			     const char **errstr);
#define SASL_CB_PROXY_POLICY (0x8001)

/* callback to lookup a user's secret for a mechanism
 *  mechanism     -- the mechanism requesting its secret
 *  auth_identity -- the identity being looked up
 *  realm         -- the realm the identity is in
 * return:
 *  secret        -- the secret associated with this user
 *                   for this mechanism
 * returns SASL_OK on success or other SASL response on failure
 */
typedef int sasl_server_getsecret_t(void *context,
				    const char *mechanism,
				    const char *auth_identity,
				    const char *realm,
				    sasl_secret_t ** secret);
#define SASL_CB_SERVER_GETSECRET (0x8002)

/* callback to store a user's secret for a mechanism
 *  mechanism     -- the mechanism storing its secret
 *  auth_identity -- the identity being stored
 *  realm         -- the realm the identity is in
 *  secret        -- the secret associated with this user
 *                   for this mechanism.  If NULL, user's secret
 *		     for this mechanism will be erased.
 * returns SASL_OK on success or other SASL response on failure
 */
typedef int sasl_server_putsecret_t(void *context,
				    const char *mechanism,
				    const char *auth_identity,
				    const char *realm,
				    const sasl_secret_t * secret);
#define SASL_CB_SERVER_PUTSECRET (0x8003)


/**********************************
 * Common Client/server functions *
 **********************************/

/* dispose of all SASL plugins.  Connection
 * states have to be disposed of before calling this.
 */
LIBSASL_API void sasl_done(void);

/* dispose connection state, sets it to NULL
 *  checks for pointer to NULL
 */
LIBSASL_API void sasl_dispose(sasl_conn_t **pconn);

/* translate server error code to user error code
 *  currently only maps SASL_NOUSER to SASL_BADAUTH
 */
LIBSASL_API int sasl_usererr(int saslerr);

/* translate an error number into a string
 * input:
 *  saslerr  -- the error number
 *  langlist -- comma separated list of RFC 1766 languages (may be NULL)
 * results:
 *  outlang  -- the language actually used (may be NULL if don't care)
 * returns:
 *  the error message
 */
LIBSASL_API const char *sasl_errstring(int saslerr,
			   const char *langlist,
			   const char **outlang);
			   
/* get property from SASL connection state
 *  propnum       -- property number
 *  pvalue        -- pointer to value
 * returns:
 *  SASL_OK       -- no error
 *  SASL_NOTDONE  -- property not available yet
 *  SASL_BADPARAM -- bad property number
 */
LIBSASL_API int sasl_getprop(sasl_conn_t *conn, int propnum, void **pvalue);
#define SASL_USERNAME   0     /* pointer to NUL terminated user name */
#define SASL_SSF        1     /* security layer security strength factor,
			       * if 0, call to sasl_encode, sasl_decode
			       * unnecessary */
#define SASL_MAXOUTBUF  2     /* security layer max output buf unsigned */  
#define SASL_REALM      3     /* server authentication realm used */
#define SASL_GETOPTCTX  4     /* context for getopt callback */
#define SASL_IP_LOCAL   5     /* local address (pvalue=sockaddr_in *) */
#define SASL_IP_REMOTE  6     /* remote address (pvalue=sockaddr_in *) */

/* set property in SASL connection state
 * returns:
 *  SASL_OK       -- value set
 *  SASL_BADPARAM -- invalid property or value
 */
LIBSASL_API int sasl_setprop(sasl_conn_t *conn,
			     int propnum,
			     const void *value);
#define SASL_SSF_EXTERNAL 100  /* external SSF active --
				* sasl_external_properties_t */
#define SASL_SEC_PROPS    101  /* sasl_security_properties_t */
			       /* also allows SASL_IP_LOCAL, SASL_IP_REMOTE */

/* do precalculations during an idle period or network round trip
 *  may pass NULL to precompute for some mechanisms prior to connect
 *  returns 1 if action taken, 0 if no action taken
 */
LIBSASL_API int sasl_idle(sasl_conn_t *conn);

/**************
 * Client API *
 **************/

/* list of client interactions with user for caller to fill in
 */
typedef struct sasl_interact {
    unsigned long id;		/* same as client/user callback ID */
    const char *challenge;      /* may be computer readable */
    const char *prompt;         /* always human readable */
    const char *defresult;	/* default result string */
    void *result;		/* set to point to result -- this will 
				 * be freed by the library iff it
				 * would be freed by the library if
				 * returned from normal callback of
				 * the same id */
    unsigned len;		/* set to length of result */
} sasl_interact_t;

/* initialize the SASL client drivers
 *  callbacks      -- base callbacks for all client connections
 * returns:
 *  SASL_OK        -- Success
 *  SASL_NOMEM     -- Not enough memory
 *  SASL_BADVERS   -- Mechanism version mismatch
 *  SASL_BADPARAM  -- error in config file
 *  SASL_NOMECH    -- No mechanisms available
 *  ...
 */
LIBSASL_API int sasl_client_init(const sasl_callback_t *callbacks);

/* initialize a client exchange based on the specified mechanism
 *  service       -- registered name of the service using SASL (e.g. "imap")
 *  serverFQDN    -- the fully qualified domain name of the server
 *  prompt_supp   -- list of client interactions supported
 *                   may also include sasl_getopt_t context & call
 *                   NULL prompt_supp = user/pass via SASL_INTERACT only
 *                   NULL proc = interaction supported via SASL_INTERACT
 *  secflags      -- security flags (see above)
 * in/out:
 *  pconn         -- connection negotiation structure
 *                   pointer to NULL => allocate new
 *
 * Returns:
 *  SASL_OK       -- success
 *  SASL_NOMECH   -- no mechanism meets requested properties
 *  SASL_NOMEM    -- not enough memory
 */
LIBSASL_API int sasl_client_new(const char *service,
		    const char *serverFQDN,
		    const sasl_callback_t *prompt_supp,
		    int secflags,
		    sasl_conn_t **pconn);

/* select a mechanism for a connection
 *  mechlist      -- mechanisms server has available (punctuation ignored)
 *  secret        -- optional secret from previous session
 * output:
 *  prompt_need   -- on SASL_INTERACT, list of prompts needed to continue
 *  clientout     -- the initial client response to send to the server
 *  mech          -- set to mechanism name
 *
 * Returns:
 *  SASL_OK       -- success
 *  SASL_NOMEM    -- not enough memory
 *  SASL_NOMECH   -- no mechanism meets requested properties
 *  SASL_INTERACT -- user interaction needed to fill in prompt_need list
 */
LIBSASL_API int sasl_client_start(sasl_conn_t *conn,
				  const char *mechlist,
				  sasl_secret_t *secret,
				  sasl_interact_t **prompt_need,
				  char **clientout,
				  unsigned *clientoutlen,
				  const char **mech);

/* do a single authentication step.
 *  serverin    -- the server message received by the client, MUST have a NUL
 *                 sentinel, not counted by serverinlen
 * output:
 *  prompt_need -- on SASL_INTERACT, list of prompts needed to continue
 *  clientout   -- the client response to send to the server
 *
 * returns:
 *  SASL_OK        -- success
 *  SASL_INTERACT  -- user interaction needed to fill in prompt_need list
 *  SASL_BADPROT   -- server protocol incorrect/cancelled
 *  SASL_BADSERV   -- server failed mutual auth
 */
LIBSASL_API int
sasl_client_step(sasl_conn_t *conn,
		 const char *serverin,
		 unsigned serverinlen,
		 sasl_interact_t **prompt_need,
		 char **clientout,
		 unsigned *clientoutlen);

/* Set connection secret based on passphrase
 *  may be used in SASL_CB_PASS callback
 * input:
 *  user          -- username
 *  pass          -- plaintext passphrase with NUL sentinel
 *  passlen       -- 0 = strlen(pass)
 * out:
 *  prompts       -- if non-NULL, SASL_CB_PASS item filled in
 *  keepcopy      -- set to copy of secret if non-NULL
 * returns:
 *  SASL_OK       -- success
 *  SASL_NOMEM    -- failure
 */
LIBSASL_API int
sasl_client_auth(sasl_conn_t *conn,
		 const char *user,
		 const char *pass, unsigned passlen,
		 sasl_interact_t *prompts, sasl_secret_t **keepcopy);

/* erase & dispose of a sasl_secret_t
 *  calls free utility last set by sasl_set_alloc
 */
LIBSASL_API void sasl_free_secret(sasl_secret_t **);

/**************
 * Server API *
 **************/

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
LIBSASL_API int sasl_server_init(const sasl_callback_t *callbacks,
				 const char *appname);


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
LIBSASL_API int sasl_server_new(const char *service,
				const char *serverFQDN,
				const char *user_realm,
				const sasl_callback_t *callbacks,
				int secflags,
				sasl_conn_t **pconn);

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
LIBSASL_API int sasl_listmech(sasl_conn_t *conn,
			      const char *user,
			      const char *prefix,
			      const char *sep,
			      const char *suffix,
			      char **result,
			      unsigned *plen,
			      unsigned *pcount);

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
LIBSASL_API int sasl_server_start(sasl_conn_t *conn,
				  const char *mech,
				  const char *clientin,
				  unsigned clientinlen,
				  char **serverout,
				  unsigned *serveroutlen,
				  const char **errstr);

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
LIBSASL_API int sasl_server_step(sasl_conn_t *conn,
		     const char *clientin,
		     unsigned clientinlen,
		     char **serverout,
		     unsigned *serveroutlen,
		     const char **errstr);

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
LIBSASL_API int sasl_checkpass(sasl_conn_t *conn,
			       const char *user,
			       unsigned userlen,
			       const char *pass,
			       unsigned passlen,
			       const char **errstr);

/* check if a user exists on server
 *  service       -- registered name of the service using SASL (e.g. "imap")
 *  user_realm    -- permits multiple user domains on server, NULL = default
 *  user          -- NUL terminated user name
 *
 * returns:
 *  SASL_OK       -- success
 *  SASL_DISABLED -- account disabled
 *  SASL_NOUSER   -- user not found
 *  SASL_NOMECH   -- user found, but no usable mechanism
 */
LIBSASL_API int sasl_user_exists(const char *service,
		     const char *user_realm,
		     const char *user);

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
LIBSASL_API int sasl_setpass(sasl_conn_t *conn,
		 const char *user,
		 const char *pass,
		 unsigned passlen,
		 int flags,
		 const char **errstr);
#define SASL_SET_CREATE  0x01   /* create a new entry for user */
#define SASL_SET_DISABLE 0x02	/* disable user account */

/**********************
 * security layer API *
 **********************/

/* encode a block of data for transmission using security layer
 * returns:
 *  SASL_OK      -- success (returns input if no layer negotiated)
 *  SASL_NOTDONE -- security layer negotiation not finished
 */
LIBSASL_API int sasl_encode(sasl_conn_t *conn,
			    const char *input, unsigned inputlen,
			    char **output, unsigned *outputlen);

/* decode a block of data received using security layer
 * returns:
 *  SASL_OK      -- success (returns input if no layer negotiated)
 *  SASL_NOTDONE -- security layer negotiation not finished
 */
LIBSASL_API int sasl_decode(sasl_conn_t *conn,
			    const char *input, unsigned inputlen,
			    char **output, unsigned *outputlen);

/************************************
 * Credentials API (used by server) *
 ************************************/

/* install credentials passed by the client
 * Installing a set of credentials may install them on a per-process
 * or a per-thread basis; neither behavior may be assumed.
 * returns:
 *  SASL_OK      -- success
 *  SASL_FAIL    -- failure
 *  SASL_NOTDONE -- credentials not passed
 */
LIBSASL_API int sasl_cred_install(sasl_conn_t *conn);

/* uninstalls a connection's credentials
 * returns:
 *  SASL_OK      -- success
 *  SASL_FAIL    -- failure
 */
LIBSASL_API int sasl_cred_uninstall(sasl_conn_t *conn);
#endif /* SASL_H */

