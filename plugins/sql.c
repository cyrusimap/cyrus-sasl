/*
**
** SQL Auxprop plugin
**   based on the original work of Simon Loader and Patrick Welche
**
** $Id: sql.c,v 1.7 2003/09/17 15:21:27 ken3 Exp $
**
**  Auxiliary property plugin for Sasl 2.1.x
**
**   The plugin uses the following options in the
** sasl application config file ( usually in /usr/lib/sasl2 )
**
**  sql_engine: <database engine to use>
**  sql_user: <username to login as>
**  sql_passwd: <password to use>
**  sql_hostnames: < comma separated host[:port] list >
**  sql_database: <database to connect to>
**  sql_statement: <select statement to use>
**  sql_insert: <insert statement to use>
**  sql_verbose:  ( if it exists will print select statement to syslog )
**  sql_usessl:  ( if it exists will make a secured connection to server )
**
**   The select statement used in the option sql_statement is parsed
** for 3 place holders %u %r and %p they are replaced with username
** realm and property required respectively.
**
**  e.g
**    sql_statement: select %p from user_table where username = %u and
**    realm = %r
**  would produce a statement like this :-
**
**     select userPassword from user_table where username = simon
**     and realm = madoka.surf.org.uk
**
**   Presuming username is simon, the sasl application is trying to
**   authenticate and you didn't have a realm to start with (and it was
**   my computer).
**
**    sql_insert works in much the same way, with the addition of another
**  placeholder
**
**   for example:
**
**     sql_insert: INSERT INTO user_table(username, realm, password)
**                 VALUES ('%u', '%r', '%i')
**
**   would yield
**
**       INSERT INTO user_table(username, realm, password)
**       VALUES ('simon', 'madoka.surf.org.uk', 'wert');
**
** OK so thats a bit complex but essential
**   %u is the username the user logged in as
**   %p is the property requested this could technically be anything
**     but sasl authentication will try userPassword and
**     cmusaslsecretMECHNAME (where MECHNAME is the name of a mechanism).
**   %r is the realm which could be the kerbros realm, the FQDN of the 
**     computer the sasl app is on or what ever is after the @ on a username.
**   %i is the value of the requested property
** 
**   These do not have to be all used or used at all
** in testing I used select password from auth where username = '%u'
**     
*/

#include <config.h>

#include <stdio.h>
#include <assert.h>

#include "sasl.h"
#include "saslutil.h"
#include "saslplug.h"

#include <ctype.h>

#include "plugin_common.h"

typedef struct sql_engine {
    const char *name;
    void *(*sql_open)(char *host, char *port, int usessl,
		      const char *user, const char *password,
		      const char *database, const sasl_utils_t *utils);
    int (*sql_escape_str)(char *to, const char *from);
    int (*sql_query)(void *conn, char *query, char *value, size_t size,
		     size_t *value_len, const sasl_utils_t *utils);
    void (*sql_close)(void *conn);
} sql_engine_t;

typedef struct sql_settings 
{
  const sql_engine_t *sql_engine;
  const char *sql_user;
  const char *sql_passwd;
  const char *sql_hostnames;
  const char *sql_database;
  const char *sql_statement;
  const char *sql_insert;
  int sql_verbose;
  int sql_usessl;
} sql_settings_t;

static const char * SQL_BLANK_STRING = "";

#if HAVE_MYSQL
#include <mysql.h>

static void *_mysql_open(char *host, char *port, int usessl,
			 const char *user, const char *password,
			 const char *database, const sasl_utils_t *utils)
{
    MYSQL *mysql;

    if (!(mysql = mysql_init(NULL))) {
	utils->log(NULL, SASL_LOG_ERR,
			    "sql plugin: could not execute mysql_init()");
	return NULL;
    }

    return mysql_real_connect(mysql, host, user, password, database,
			      port ? strtoul(port, NULL, 10) : 0, NULL,
			      usessl ? CLIENT_SSL : 0);
}

static int _mysql_escape_str(char *to, const char *from)
{
    return mysql_escape_string(to, from, strlen(from));
}

static int _mysql_query(void *conn, char *query, char *value, size_t size,
			size_t *value_len, const sasl_utils_t *utils)
{
    MYSQL_RES *result;
    MYSQL_ROW row;
    int row_count;

    /* run the query */
    if (mysql_real_query(conn, query, strlen(query)) < 0
	|| !(result = mysql_store_result(conn))) {
	utils->free(query);
	return -1;
    }
	
    /* quick row check */
    row_count = mysql_num_rows(conn);
    if (!row_count) {
	/* umm nothing found */
	utils->free(query);
	mysql_free_result(result);
	return -1;
    }
    if (row_count > 1) {
	utils->log(NULL, SASL_LOG_WARN,
		   "sql plugin: found duplicate row for query %s", query);
    }
	
    /* now get the result set value and value_len */
    /* we only fetch one because we don't care about the rest */
    row = mysql_fetch_row(result);
    strncpy(value, row[0], size-2);
    value[size-1] = '\0';
    if (value_len) *value_len = strlen(value);
	
    /* free result */
    utils->free(query);
    mysql_free_result(result);

    return 0;
}

static void _mysql_close(void *conn)
{
    mysql_close(conn);
}
#endif /* HAVE_MYSQL */

#if HAVE_PGSQL
#include <libpq-fe.h>

int pgsql_exists(const char *input)
{
  char * theinput = (char*) input;

  if(theinput != SQL_BLANK_STRING)
    {
      return 1;
    }
  return 0;
}
static void *_pgsql_open(char *host, char *port,
			 int usessl __attribute__((unused)),
			 const char *user, const char *password,
			 const char *database,
			 const sasl_utils_t *utils __attribute__((unused)))
{
    PGconn *conn = NULL;
    /* create the connection info string */

    char *conninfo = 
      malloc(sizeof(user) + sizeof(password) + sizeof(database) + sizeof(host)
	     + sizeof(port) + 64);

    /* we have to have a host */
    sprintf(conninfo, "host='%s'", host);

    /* check if other terms exist */
    if(port!=NULL && port != "")
	sprintf(conninfo, "%s port='%s'", conninfo, port);

    if(pgsql_exists(user))
	sprintf(conninfo, "%s user='%s'", conninfo, user);

    if(pgsql_exists(password))
	sprintf(conninfo, "%s password='%s'",conninfo,  password);

    if(pgsql_exists(database))
	sprintf(conninfo, "%s dbname='%s'", conninfo,  database);

    /*are we using ssl?*/
    /*sprintf(conninfo, "%s requiressl='%d'", conninfo, usessl);*/

    conn = PQconnectdb((const char *)conninfo);
    free(conninfo);

    if((PQstatus(conn)==CONNECTION_OK))
	return conn;

    utils->log(NULL, SASL_LOG_ERR, "sql plugin: %s", PQerrorMessage(conn));
    return NULL;
}

static int _pgsql_escape_str(char *to, const char *from)
{
    return PQescapeString(to, from, strlen(from));
}

static int _pgsql_query(void *conn, char *query, char *value, size_t size,
			size_t *value_len, const sasl_utils_t *utils)
{
  PGresult *result;
  int row_count;

  /* run the query */
  result = PQexec(conn, query);
  if (PQresultStatus(result) != PGRES_TUPLES_OK) 
    {
      utils->log(NULL, SASL_LOG_NOTE, "sql plugin: %s", PQerrorMessage(conn));
      utils->free(query);
      PQclear(result);
      return -1;
    }
	
  /* quick row check */
  row_count = PQntuples(result);
  if (!row_count) 
    {
      /* umm nothing found */
      utils->free(query);
      PQclear(result);
      return -1;
    }
  if (row_count > 1) 
    {
      utils->log(NULL, SASL_LOG_WARN,
		 "sql plugin: found duplicate row for query %s", query);
    }
	
  /* now get the result set value and value_len */
  /* we only fetch one because we don't care about the rest */
  strncpy(value, PQgetvalue(result,0,0), size-2);
  value[size-1] = '\0';
  if (value_len) *value_len = strlen(value);
  
  /* free result */
  utils->free(query);
  PQclear(result);
  return 0;
}

static void _pgsql_close(void *conn)
{
    PQfinish(conn);
}
#endif /* HAVE_PGSQL */

static const sql_engine_t sql_engines[] = {
#if HAVE_MYSQL
  { "mysql", &_mysql_open, &_mysql_escape_str, &_mysql_query, &_mysql_close },
#endif
#if HAVE_PGSQL
  { "pgsql", &_pgsql_open, &_pgsql_escape_str, &_pgsql_query, &_pgsql_close },
#endif
  { NULL, NULL, NULL, NULL, NULL }
};

/*
**  Sql_create_statemnet
**   uses select line and allocate memory to replace
**  Parts with the strings provided.
**   %<char> =  no change
**   %% = %
**   %u = user
**   %p = prop
**   %r = realm
**   %i = value of prop
**  e.g select %p from auth where user = %p and domain = %r;
**  Note: calling function must free memory.
**
*/

static char *sql_create_statement(sasl_server_params_t *sparams,
				  const char *select_line, const char *prop,
				  const char *user, const char *realm, 
				  const char *insertvalue)
{
    const char *ptr, *line_ptr;
    char *buf, *buf_ptr;
    int filtersize;
    int ulen, plen, rlen, ilen;
    
    const char *begin, *commit, *rollback;
    int beginlen, commitlen, rollbacklen;
    int filtersize_plus_transaction;

    /* devise the appropiate transaction-safe terms 
     * if mysql: START TRANSACTION, COMMIT, ROLLBACK 
     * if postgresql: BEGIN, COMMIT, ROLLBACK 
     */

    /*Newer versions of postgres actually accept "START TRANSACTION"*/

    /* xxx temp fix until real fix available  -- no transactions */
    begin = "";
    commit = "";
    rollback = "";
      
    beginlen = strlen(begin);
    commitlen = strlen(commit);
    rollbacklen = strlen(rollback);
    
    
    /* calculate memory needed for creating the complete query string. */
    ulen = strlen(user);
    rlen = strlen(realm);
    plen = strlen(prop);
    ilen = insertvalue ? strlen(insertvalue) : 0;
    /* don't forget the trailing 0x0 */
    filtersize = strlen(select_line) + ulen + rlen + plen + ilen;
    /* add in the transaction terms, keep the trailer from before */ 
    filtersize_plus_transaction = filtersize + beginlen + commitlen + rollbacklen +1;

    /* ok, now try to allocate a chunk of that size */
    buf = (char *) sparams->utils->malloc(filtersize_plus_transaction);

    if (!buf) 
      {
	MEMERROR(sparams->utils);
	return NULL;
      }
    
    buf_ptr = buf;
    line_ptr = select_line;
    
    /*add the begin to the transaction block */
    memcpy(buf_ptr, begin, beginlen);
    buf_ptr += beginlen;
    
    /* replace the strings */
    while ( (ptr = strchr(line_ptr, '%')) ) 
      {
	/* copy up to but not including the next % */
	memcpy(buf_ptr, line_ptr, ptr - line_ptr); 
	buf_ptr += ptr - line_ptr;
	ptr++;
	switch (ptr[0]) 
	  {
	  case '%':
	    buf_ptr[0] = '%';
	    buf_ptr++;
	    break;
	  case 'u':
	    memcpy(buf_ptr, user, ulen);
	    buf_ptr += ulen;
	    break;
	  case 'r':
	    memcpy(buf_ptr, realm, rlen);
	    buf_ptr += rlen;
	    break;
	  case 'p':
	    memcpy(buf_ptr, prop, plen);
	    buf_ptr += plen;
	    break;
	  case 'i':
	    if(!insertvalue) {
		sparams->utils->log(NULL, SASL_LOG_ERR,
			            "Cannot use %%i in select statements");
		sparams->utils->free(buf);
		return NULL;
	    }
	    memcpy(buf_ptr, insertvalue, ilen);
	    buf_ptr += ilen;
	    break;
	  default:
	    buf_ptr[0] = '%';
	    buf_ptr[1] = ptr[0];
	    buf_ptr += 2;
	    break;
	  }
	ptr++;
	line_ptr = ptr;
      }

    /* now copy the last bit */

    memcpy(buf_ptr, line_ptr, strlen(line_ptr));
    buf_ptr += strlen(line_ptr);
   
    /*copy in the commit */
    memcpy(buf_ptr, commit, commitlen + 1);
    
    return(buf);
}

/* sql_get_settings
**
**  Get the auxprop settings and put them in 
** The global context array
*/
void sql_get_settings(const sasl_utils_t *utils, void *glob_context) {
    sql_settings_t *settings;
    int r;
    const char *verbose, *usessl, *engine_name;
    const sql_engine_t *e;
    
    settings = (sql_settings_t *) glob_context;

    utils->getopt(utils->getopt_context, "SQL", "sql_verbose",
		  &verbose, NULL);
    if (verbose) {
	settings->sql_verbose = 1;
	utils->log(NULL, SASL_LOG_NOTE,
		   "sql auxprop plugin being initialized\n");
    } else {
settings->sql_verbose = 0;
    }
	
    utils->getopt(utils->getopt_context, "SQL", "sql_usessl",
		  &usessl, NULL);
    if (usessl) {
	settings->sql_usessl = 1;
    } else {
	settings->sql_usessl = 0;
    }
	
    r = utils->getopt(utils->getopt_context,"SQL","sql_user",
		      &settings->sql_user, NULL);
    if ( r || !settings->sql_user ) {
	/* set it to a blank string */
	settings->sql_user = SQL_BLANK_STRING;
    }
    r = utils->getopt(utils->getopt_context,"SQL", "sql_passwd",
		      &settings->sql_passwd, NULL);
    if ( r || !settings->sql_passwd ) {
	settings->sql_passwd = SQL_BLANK_STRING;
    }
    r = utils->getopt(utils->getopt_context,"SQL", "sql_hostnames",
		      &settings->sql_hostnames, NULL);
    if ( r || !settings->sql_hostnames ) {
	settings->sql_hostnames = SQL_BLANK_STRING;
    }
    r = utils->getopt(utils->getopt_context,"SQL", "sql_database",
		      &settings->sql_database, NULL);
    if ( r || !settings->sql_database ) {
	settings->sql_database = SQL_BLANK_STRING;
    }
    r = utils->getopt(utils->getopt_context,"SQL", "sql_statement",
		      &settings->sql_statement, NULL);
    if ( r || !settings->sql_statement ) {
	settings->sql_statement = SQL_BLANK_STRING;
    }
    r = utils->getopt(utils->getopt_context, "SQL", "sql_insert",
		      &settings->sql_insert, NULL);
    if ( r || !settings->sql_insert) 
      {
	settings->sql_insert = SQL_BLANK_STRING;
      }
    r = utils->getopt(utils->getopt_context,"SQL", "sql_engine",
		      &engine_name, NULL);
    if ( r || !engine_name ) {
	engine_name = "mysql";
    }

    /* find the correct engine */
    e = sql_engines;
    while (e->name) {
	if (!strcasecmp(engine_name, e->name)) break;
	e++;
    }

    if (!e->name) {
	utils->log(NULL, SASL_LOG_ERR, "SQL engine '%s' not supported",
		   engine_name);
    }

    settings->sql_engine = e;
}

static void sql_auxprop_lookup(void *glob_context,
				 sasl_server_params_t *sparams,
				 unsigned flags,
				 const char *user,
				 unsigned ulen) 
{
    char *userid = NULL;
    /* realm could be used for something clever */
    char *realm = NULL;
    const char *user_realm = NULL;
    const struct propval *to_fetch, *cur;
    char value[8192];
    size_t value_len;
    
    char *user_buf;
    char *db_host_ptr = NULL;
    char *db_host = NULL;
    char *cur_host, *cur_port;
    char *query = NULL;
    char *escap_userid = NULL;
    char *escap_realm = NULL;
    sql_settings_t *settings;
    void *conn = NULL;
    
    if (!glob_context || !sparams || !user) return;
    
    /* setup the settings */
    settings = (sql_settings_t *) glob_context;
    
    if (settings->sql_verbose)
	sparams->utils->log(NULL, SASL_LOG_NOTE,
			    "sql plugin Parse the username %s\n", user);
    
    user_buf = sparams->utils->malloc(ulen + 1);
    if (!user_buf) goto done;
    
    memcpy(user_buf, user, ulen);
    user_buf[ulen] = '\0';
    
    if(sparams->user_realm) {
	user_realm = sparams->user_realm;
    } else {
	user_realm = sparams->serverFQDN;
    }
    
    if (_plug_parseuser(sparams->utils, &userid, &realm, user_realm,
			sparams->serverFQDN, user_buf) != SASL_OK )
	goto done;
    
    /* just need to escape userid and realm now */
    /* allocate some memory */
    escap_userid = (char *)sparams->utils->malloc(strlen(userid)*2+1);
    escap_realm = (char *)sparams->utils->malloc(strlen(realm)*2+1);
    
    if (!escap_userid || !escap_realm) {
	MEMERROR(sparams->utils);
	goto done;
    }
    
    /*************************************/
    
    /* find out what we need to get */
    /* this corrupts const char *user */
    to_fetch = sparams->utils->prop_get(sparams->propctx);
    if(!to_fetch) goto done;
    
    /* now loop around hostnames till we get a connection 
    ** it should probably save the connection but for 
    ** now we will just disconnect eveyrtime
    */
    if ( settings->sql_verbose )
	sparams->utils->log(NULL, SASL_LOG_NOTE,
			    "sql plugin try and connect to a host\n");
    
    /* create a working version of the hostnames */
    _plug_strdup(sparams->utils, settings->sql_hostnames,
		 &db_host_ptr, NULL);
    db_host = db_host_ptr;
    cur_host = db_host;
    while ( cur_host != NULL ) {
	db_host = strchr(db_host,',');
	if ( db_host != NULL ) {  
	    db_host[0] = '\0';
	    /* loop till we find some text */
	    while (!isalnum(db_host[0]))
		db_host++;
	}
	
	if (settings->sql_verbose)
	    sparams->utils->log(NULL, SASL_LOG_NOTE,
				"sql plugin trying to open db '%s' on host '%s'%s\n",
				settings->sql_database, cur_host,
				settings->sql_usessl ? " using SSL" : "");

	/* set the optional port */
	if ((cur_port = strchr(cur_host, ':')))
	    *cur_port++ = '\0';

	conn = settings->sql_engine->sql_open(cur_host, cur_port,
					      settings->sql_usessl,
					      settings->sql_user,
					      settings->sql_passwd,
					      settings->sql_database,
					      sparams->utils);
	if (conn)
	    break;

	/* xxx we should do this and get the error codes correctly for
	 * both pgsql and MySQL */	
        sparams->utils->log(NULL, SASL_LOG_ERR,
                            "SQL plugin could not connect to host %s",
                            cur_host);

	cur_host = db_host;
    }
    
    if ( !conn ) 
      {
	sparams->utils->log(NULL, SASL_LOG_ERR,
			    "sql plugin couldn't connect to any host\n");

	goto done;
      }
    
    /* escape out */
    settings->sql_engine->sql_escape_str(escap_userid, userid);
    settings->sql_engine->sql_escape_str(escap_realm, realm);
    
    for (cur = to_fetch; cur->name; cur++) {
	char *realname = (char *)cur->name;
	/* Only look up properties that apply to this lookup! */
	if (cur->name[0] == '*'
	    && (flags & SASL_AUXPROP_AUTHZID))
	    continue;
	if(!(flags & SASL_AUXPROP_AUTHZID)) {
	    if(cur->name[0] != '*')
		continue;
	    else
		realname = (char*)cur->name + 1;
	}
	
	/* If it's there already, we want to see if it needs to be
	 * overridden */
	if(cur->values && !(flags & SASL_AUXPROP_OVERRIDE))
	    continue;
	else if(cur->values)
	    sparams->utils->prop_erase(sparams->propctx, cur->name);
	
	if ( settings->sql_verbose )
	    sparams->utils->log(NULL, SASL_LOG_NOTE,
			       "sql plugin create statement from %s %s %s\n",
			       realname,escap_userid,escap_realm);
	
	/* create a statment that we will use */
	query = sql_create_statement(sparams,
				       settings->sql_statement,
				       realname,escap_userid,
				       escap_realm, NULL);
	
	if (settings->sql_verbose)
	    sparams->utils->log(NULL, SASL_LOG_NOTE,
				"sql plugin doing query %s\n",
				query);

	/* run the query */
	if (!settings->sql_engine->sql_query(conn, query, value, sizeof(value),
					     &value_len, sparams->utils))
	    sparams->utils->prop_set(sparams->propctx, cur->name,
				     value, value_len);
    }
    
 done:
    if (escap_userid) sparams->utils->free(escap_userid);
    if (escap_realm) sparams->utils->free(escap_realm);
    if (conn) settings->sql_engine->sql_close(conn);
    if (db_host_ptr) sparams->utils->free(db_host_ptr);
    if (userid) sparams->utils->free(userid);
    if (realm) sparams->utils->free(realm);
    if (user_buf) sparams->utils->free(user_buf);
}

static int sql_auxprop_store (void *glob_context,
			      sasl_server_params_t *sparams,
			      struct propctx *ctx,
			      const char *user,
			      unsigned ulen) 
{

  
    char *userid = NULL;
    char *realm = NULL;
    const char *user_realm = NULL;
    int ret = SASL_FAIL;
    const struct propval *to_store, *cur;
    
    char value[8192];
    size_t value_len;

    char *user_buf;
    char *db_host_ptr = NULL;
    char *db_host = NULL;
    char *cur_host, *cur_port;
    char *query = NULL;
    char *escap_userid = NULL;
    char *escap_realm = NULL;
    
    sql_settings_t *settings;
    void *conn = NULL;

    /* just checking if we are enabled */
    if(!ctx) 
      {
	return SASL_OK;
      }

    /* make sure our input is okay */
    if(!glob_context || !sparams || !user) 
      {
	return SASL_BADPARAM;
      }

    settings = (sql_settings_t *) glob_context; 
    if (settings->sql_verbose)
      {
	sparams->utils->log(NULL, SASL_LOG_NOTE,
			    "sql plugin Parse the username %s\n", user);
      }

    user_buf = sparams->utils->malloc(ulen + 1);
    if(!user_buf) 
      {
	ret = SASL_NOMEM;
	goto done;
      }

    memcpy(user_buf, user, ulen);
    user_buf[ulen] = '\0';
    
    if(sparams->user_realm) 
      {
	user_realm = sparams->user_realm;
      } 
    else 
      {
	user_realm = sparams->serverFQDN;
      }
    
    ret = _plug_parseuser(sparams->utils, &userid, &realm, user_realm,
			  sparams->serverFQDN, user_buf);
    if(ret != SASL_OK)
      {
	goto done;
      }
     
     /* just need to escape userid and realm now */
     /* allocate some memory */

    escap_userid = (char *)sparams->utils->malloc(strlen(userid)*2+1);
    escap_realm = (char *)sparams->utils->malloc(strlen(realm)*2+1);
    
    if (!escap_userid || !escap_realm) 
      {
	MEMERROR(sparams->utils);
	goto done;
      }
     
     to_store = sparams->utils->prop_get(sparams->propctx);
 
     if(!to_store)
       {
	 ret = SASL_BADPARAM;
	 goto done;
       }

    
    if (settings->sql_verbose)
	{
	  sparams->utils->log(NULL, SASL_LOG_NOTE,
			      "sql plugin try and connect to a host\n");
	}
    
    /* create a working version of the hostnames */
    _plug_strdup(sparams->utils, settings->sql_hostnames,
		 &db_host_ptr, NULL);

    db_host = db_host_ptr;
    cur_host = db_host;

    while (cur_host != NULL) 
      {
	db_host = strchr(db_host,',');

	if (db_host != NULL) 
	  {  
	    db_host[0] = '\0';
	    /* loop till we find some text */
	    while (!isalnum(db_host[0]))
	      {
		db_host++;
	      }
	  }
	if (settings->sql_verbose)
	  {
	    sparams->utils->log(NULL, SASL_LOG_NOTE,
				"sql plugin trying to open db '%s' on host '%s'%s\n",
				settings->sql_database, cur_host,
				settings->sql_usessl ? " using SSL" : "");
	  }

	/* set the optional port */
	if ((cur_port = strchr(cur_host, ':')))
	  {
	    *cur_port++ = '\0';
	  }

	if ((conn = settings->sql_engine->sql_open(cur_host, cur_port,
						  settings->sql_usessl,
						  settings->sql_user,
						  settings->sql_passwd,
						  settings->sql_database,
						   sparams->utils)))
	  {
	    break;
	  }
	cur_host = db_host;
      }
    
    if(!conn)
      {
	sparams->utils->log(NULL, SASL_LOG_ERR,
			    "sql plugin couldn't connect to any host\n");
	goto done;
      }

    settings->sql_engine->sql_escape_str(escap_userid, userid);
    settings->sql_engine->sql_escape_str(escap_realm, realm);

    for (cur = to_store; cur->name; cur++) 
      {	
	/* create a statment that we will use */
	query = sql_create_statement(sparams,
				     settings->sql_insert,
				     cur->name,escap_userid,
				     escap_realm, cur->values[0]);
	
	if (settings->sql_verbose)
	  {
	    sparams->utils->log(NULL, SASL_LOG_NOTE,
				"sql plugin doing query %s\n",
				query);
	  }

	/* run the query */
	if (!settings->sql_engine->sql_query(conn, query, value, sizeof(value),
					     &value_len, sparams->utils))
	  {
	    sparams->utils->prop_set(sparams->propctx, cur->name,
				     value, value_len);
	  }
      }
 done:
    if (escap_userid) sparams->utils->free(escap_userid);
    if (escap_realm) sparams->utils->free(escap_realm);
    if (conn) settings->sql_engine->sql_close(conn);
    if (db_host_ptr) sparams->utils->free(db_host_ptr);
    if (userid) sparams->utils->free(userid);
    if (realm) sparams->utils->free(realm);
    if (user_buf) sparams->utils->free(user_buf);
    return ret;
    /* do a little dance */
}


static void sql_auxprop_free(void *glob_context, const sasl_utils_t *utils) {
    struct sql_settings *settings;

    settings = (sql_settings_t *)glob_context;

    if (!settings) return;

    if (settings->sql_verbose)
	utils->log(NULL, SASL_LOG_DEBUG, "sql freeing memory\n");

    utils->free(settings);
}

static sasl_auxprop_plug_t sql_auxprop_plugin = {
    0,			/* Features */
    0,			/* spare */
    NULL,		/* glob_context */
    sql_auxprop_free,	/* auxprop_free */
    sql_auxprop_lookup,	/* auxprop_lookup */
    "sql",		/* name */
    sql_auxprop_store	/* auxprop_store */
};

int sql_auxprop_plug_init(const sasl_utils_t *utils,
			    int max_version,
			    int *out_version,
			    sasl_auxprop_plug_t **plug,
			    const char *plugname __attribute__((unused))) 
{
    sql_settings_t *settings;

    if (!out_version || !plug) return SASL_BADPARAM;
    
    if (max_version < SASL_AUXPROP_PLUG_VERSION) return SASL_BADVERS;
    *out_version = SASL_AUXPROP_PLUG_VERSION;
    
    *plug = &sql_auxprop_plugin;
    
    settings = (sql_settings_t *) utils->malloc(sizeof(sql_settings_t));

    if (!settings) {
	MEMERROR(utils);
	return SASL_NOMEM;
    }

    memset(settings, 0, sizeof(sql_settings_t));
    sql_get_settings(utils, settings);

    if (!settings->sql_engine->name) return SASL_NOMECH;
    if (settings->sql_verbose)
	utils->log(NULL, SASL_LOG_NOTE,
		   "sql auxprop plugin using %s engine\n",
		   settings->sql_engine->name);
    
    sql_auxprop_plugin.glob_context = settings;

    return SASL_OK;
}
