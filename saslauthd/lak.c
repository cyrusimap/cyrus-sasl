/* COPYRIGHT * Copyright (c) 2002-2002 Igor Brezac
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY IGOR BREZAC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IGOR BREZAC OR
 * ITS EMPLOYEES OR AGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * END COPYRIGHT */

#include "mechanisms.h"

#ifdef AUTH_LDAP

#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ldap.h>
#include <lber.h>
#include "lak.h"

static int lak_read_config(const char *);
static const char *lak_config_getstring(const char *, const char *);
static int lak_config_getint(const char *, int );
static int lak_config_getswitch(const char *, int );
static int lak_configure(LAK_CONF **, const char *);
static void lak_release_config(LAK_CONF **);
#if 0
static int lak_get_integer_value (LDAP *, LDAPMessage *, const char *, int *);
static int lak_get_long_integer_value (LDAP *, LDAPMessage *, const char *, long int *);
static int lak_oc_check (LDAP *, LDAPMessage *, const char *);
static int lak_has_value (char **, const char *);
static int lak_get_string_values (LDAP *, LDAPMessage *, const char *, char ***);
#endif
static int lak_get_string_value (LDAP *, LDAPMessage *, const char *, char **);
static int lak_escape(const char *, char **);
static int lak_filter(LAK_SESSION *, const char *, const char *, char **);
static int lak_get_user(LAK_SESSION *, const char *, const char *);
static void lak_release_user(LAK_USER **);
static int lak_get_session(LAK_SESSION **, const char *) ;
static int lak_open_session(LAK_SESSION *);
static int lak_reopen_session(LAK_SESSION *);
static void lak_close_session(LAK_SESSION **);
static int lak_connect_anonymously(LAK_SESSION *);
static int lak_connect_as_user(LAK_SESSION *, const char *);
static int lak_search(LAK_SESSION *, const char *, const char **, LDAPMessage **);
static int lak_retrieve(LAK_SESSION *, const char *, const char *, const char **, LAK **);
static int lak_custom_authenticate(LAK_SESSION *, const char *, const char *realm, const char *);
static int lak_bind_authenticate(LAK_SESSION *, const char *, const char *, const char *);

static LAK_SESSION *persistent_session = NULL;

#define CONFIGLISTGROWSIZE 100

struct configlist {
	char *key;
	char *value;
};

static struct configlist *configlist;
static int nconfiglist;

static int lak_read_config(const char *filename)
{
	FILE *infile;
	int lineno = 0;
	int alloced = 0;
	char buf[4096];
	char *p, *key;
	char *result;

	nconfiglist=0;

	infile = fopen(filename, "r");
	if (!infile) {
	    syslog(LOG_ERR|LOG_AUTH,
		   "Could not open LDAP config file: %s (%m)",
		   filename);
	    return LAK_FAIL;
	}
    
	while (fgets(buf, sizeof(buf), infile)) {
		lineno++;

		if (buf[strlen(buf)-1] == '\n') 
			buf[strlen(buf)-1] = '\0';
		for (p = buf; *p && isspace((int) *p); p++);
			if (!*p || *p == '#') 
				continue;

		key = p;
		while (*p && (isalnum((int) *p) || *p == '-' || *p == '_')) {
			if (isupper((int) *p)) 
				*p = tolower(*p);
			p++;
		}
		if (*p != ':') {
			return LAK_FAIL;
		}
		*p++ = '\0';

		while (*p && isspace((int) *p)) 
			p++;

		if (!*p) {
			return LAK_FAIL;
		}

		if (nconfiglist == alloced) {
			alloced += CONFIGLISTGROWSIZE;
			configlist=realloc((char *)configlist, alloced * sizeof(struct configlist));
			if (configlist==NULL) 
				return LAK_FAIL;
		}

		result = strdup(key);
		if (result==NULL) 
			return LAK_FAIL;

		configlist[nconfiglist].key = result;

		result = strdup(p);
		if (result==NULL) 
			return LAK_FAIL;
		configlist[nconfiglist].value = result;

		nconfiglist++;
	}

	fclose(infile);

	return LAK_OK;
}

static const char *lak_config_getstring(const char *key, const char *def)
{
    int opt;

    for (opt = 0; opt < nconfiglist; opt++) {
	if (*key == configlist[opt].key[0] &&
	    !strcmp(key, configlist[opt].key))
	  return configlist[opt].value;
    }
    return def;
}

static int lak_config_getint(const char *key, int def)
{
    const char *val = lak_config_getstring(key, (char *)0);

    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) return def;
    return atoi(val);
}

static int lak_config_getswitch(const char *key, int def)
{
    const char *val = lak_config_getstring(key, (char *)0);

    if (!val) return def;

    if (*val == '0' || *val == 'n' ||
	(*val == 'o' && val[1] == 'f') || *val == 'f') {
	return 0;
    }
    else if (*val == '1' || *val == 'y' ||
	     (*val == 'o' && val[1] == 'n') || *val == 't') {
	return 1;
    }
    return def;
}

static int lak_configure(LAK_CONF **pconf, const char *configFile)
{
    	const char *myname = "lak_configure";

	LAK_CONF *conf;
	int rc = 0;
	char *s;

	conf = malloc( sizeof(LAK_CONF) );
	if (conf == NULL) {
		return LAK_FAIL;
	}

	conf->path = strdup(configFile);
	if (conf->path == NULL) {
		return LAK_FAIL;
	}

	rc = lak_read_config(conf->path);
	if (rc != LAK_OK) {
		return LAK_FAIL;
	}

	conf->servers = (char *) lak_config_getstring("ldap_servers", "ldap://localhost/");
	conf->bind_dn = (char *) lak_config_getstring("ldap_bind_dn", "");
	conf->bind_pw = (char *) lak_config_getstring("ldap_bind_pw", "");
	conf->version = lak_config_getint("ldap_version", LDAP_VERSION3);
	conf->search_base = (char *) lak_config_getstring("ldap_search_base", "");
	conf->filter = (char *) lak_config_getstring("ldap_filter", "uid=%u");
	conf->lookup_attrib = (char *) lak_config_getstring("ldap_lookup_attrib", NULL);
	conf->auth_method = LAK_AUTH_METHOD_BIND;
	s = (char *) lak_config_getstring("ldap_auth_method", NULL);
	if (s) {
		if (!strcasecmp(s, "custom")) {
			conf->auth_method = LAK_AUTH_METHOD_CUSTOM;
		}
	}
	conf->timeout.tv_sec = lak_config_getint("ldap_timeout", 5);
	conf->timeout.tv_usec = 0;
	conf->sizelimit = lak_config_getint("ldap_sizelimit", 1);
	conf->timelimit = lak_config_getint("ldap_timelimit", 5);
	conf->deref = LDAP_DEREF_NEVER;
	s = (char *) lak_config_getstring("ldap_deref", NULL);
	if (s) {
		if (!strcasecmp(s, "search")) {
			conf->deref = LDAP_DEREF_SEARCHING;
		} else if (!strcasecmp(s, "find")) {
			conf->deref = LDAP_DEREF_FINDING;
		} else if (!strcasecmp(s, "always")) {
			conf->deref = LDAP_DEREF_ALWAYS;
		} else if (!strcasecmp(s, "never")) {
			conf->deref = LDAP_DEREF_NEVER;
		}
	}
	conf->referrals = lak_config_getswitch("ldap_referrals", 0);
	conf->restart = lak_config_getswitch("ldap_restart", 1);
	conf->cache_expiry = lak_config_getint("ldap_cache_expiry", 0);
	conf->cache_size = lak_config_getint("ldap_cache_size", 0);
	conf->scope = LDAP_SCOPE_SUBTREE;
	s = (char *) lak_config_getstring("ldap_scope", NULL);
	if (s) {
		if (!strcasecmp(s, "one")) {
			conf->scope = LDAP_SCOPE_ONELEVEL;
		} else if (!strcasecmp(s, "base")) {
			conf->scope = LDAP_SCOPE_BASE;
		}
	}
	conf->debug = lak_config_getint("ldap_debug", 0);
	conf->verbose = lak_config_getswitch("ldap_verbose", 0);
	conf->ssl = lak_config_getswitch("ldap_ssl", 0);
	conf->start_tls = lak_config_getswitch("ldap_start_tls", 0);
	if (conf->start_tls) {
		conf->ssl = 0;
	}
	conf->tls_checkpeer = lak_config_getint("ldap_tls_checkpeer", 0);
	conf->tls_cacertfile = (char *) lak_config_getstring("ldap_tls_cacertfile", NULL);
	conf->tls_cacertdir = (char *) lak_config_getstring("ldap_tls_cacertdir", NULL);
	conf->tls_ciphers = (char *) lak_config_getstring("ldap_tls_ciphers", NULL);
	conf->tls_cert = (char *) lak_config_getstring("ldap_tls_cert", NULL);
	conf->tls_key = (char *) lak_config_getstring("ldap_tls_key", NULL);

	*pconf = conf;
	return LAK_OK;
}

/*
 * Util functions
 */
#if 0
static int lak_get_integer_value (LDAP *ld, LDAPMessage *e, const char *attr, int *ptr)
{
	char **vals;

	vals = ldap_get_values (ld, e, (char *) attr);
	if (vals == NULL) {
		return LAK_FAIL;
	}
	*ptr = atoi (vals[0]);
	ldap_value_free (vals);

	return LAK_OK;
}

static int lak_get_long_integer_value (LDAP *ld, LDAPMessage *e, const char *attr, long int *ptr)
{
	char **vals;

	vals = ldap_get_values (ld, e, (char *) attr);
	if (vals == NULL) {
		return LAK_FAIL;
	}
	*ptr = atol (vals[0]);
	ldap_value_free (vals);

	return LAK_OK;
}


static int lak_oc_check (LDAP *ld, LDAPMessage *e, const char *oc)
{
	char **vals, **p;
	int rc = 0;

	vals = ldap_get_values (ld, e, "objectClass");
	if (vals == NULL) {
	return LAK_FAIL;
	}

	for (p = vals; *p != NULL; p++) {
		if (!strcasecmp (*p, oc)) {
			rc = 1;
			break;
		}
	}

	ldap_value_free (vals);

	return rc;
}

static int lak_has_value (char **src, const char *tgt)
{
	char **p;

	for (p = src; *p != NULL; p++) {
		if (!strcasecmp (*p, tgt)) {
			return 1;
		}
	}

	return 0;
}

static int lak_get_string_values (LDAP *ld, LDAPMessage *e, const char *attr, char ***ptr)
{
	char **vals;

	vals = ldap_get_values (ld, e, (char *) attr);
	if (vals == NULL) {
		return LAK_FAIL;
	}
	*ptr = vals;

	return LAK_OK;
}
#endif /* 0 */

static int lak_get_string_value (LDAP *ld, LDAPMessage *e, const char *attr, char **ptr)
{
	char **vals;
	int rc;

	vals = ldap_get_values (ld, e, (char *) attr);
	if (vals == NULL) {
		return LAK_FAIL;
	}
	*ptr = strdup (vals[0]);
	if (*ptr == NULL) {
		rc = LAK_FAIL;
	} else {
		rc = LAK_OK;
	}

	ldap_value_free (vals);

	return rc;
}

/*
 * If any characters in the supplied address should be escaped per RFC
 * 2254, do so. Thanks to Keith Stevenson and Wietse. And thanks to
 * Samuel Tardieu for spotting that wildcard searches were being done in
 * the first place, which prompted the ill-conceived lookup_wildcards
 * parameter and then this more comprehensive mechanism.
 *
 * Note: calling function must free memory.
 */
static int lak_escape(const char *s, char **result) 
{
    	/* char  *myname = "lak_escape"; */

	char *buf;
	char *end, *ptr, *temp;

	buf = malloc(strlen(s) * 2 + 1);
	if (buf == NULL) {
		return LAK_FAIL;
	}

	buf[0] = '\0';
	ptr = (char *)s;
	end = ptr + strlen(ptr);

	while (((temp = strpbrk(ptr, "*()\\\0"))!=NULL) && (temp < end)) {

		if ((temp-ptr) > 0)
			strncat(buf, ptr, temp-ptr);

		switch (*temp) {
			case '*':
				strcat(buf, "\\2a");
				break;
			case '(':
				strcat(buf, "\\28");
				break;
			case ')':
				strcat(buf, "\\29");
				break;
			case '\\':
				strcat(buf, "\\5c");
				break;
			case '\0':
				strcat(buf, "\\00");
				break;
		}
		ptr=temp+1;
	}
	if (temp<end)
		strcat(buf, ptr);

	*result = buf;

	return LAK_OK;
}

/*
 * lak_filter
 * Parts with the strings provided.
 *   %% = %
 *   %u = user
 *   %r = realm
 * Note: calling function must free memory.
 */
static int lak_filter(LAK_SESSION *session, const char *username, const char *realm, char **result) 
{
    	const char *myname = "lak_filter";

	char *buf; 
	char *end, *ptr, *temp;
	char *ebuf;
	int rc;
	
	if (session->conf->filter == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: filter not setup", myname);
		return LAK_FAIL;
	}

	buf=malloc(strlen(session->conf->filter)+strlen(username)+strlen(realm)+1);
	if(buf == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "%s: Cannot allocate memory", myname);
		return LAK_FAIL;
	}
	buf[0] = '\0';
	
	ptr=session->conf->filter;
	end = ptr + strlen(ptr);

	while ((temp=strchr(ptr,'%'))!=NULL ) {

		if ((temp-ptr) > 0)
			strncat(buf, ptr, temp-ptr);

		if ((temp+1) >= end) {
			syslog(LOG_WARNING|LOG_AUTH, "%s: Incomplete lookup substitution format", myname);
			break;
		}

		switch (*(temp+1)) {
			case '%':
				strncat(buf,temp+1,1);
				break;
			case 'u':
				if (username!=NULL) {
					rc=lak_escape(username, &ebuf);
					if (rc == LAK_OK) {
						strcat(buf,ebuf);
						free(ebuf);
					}
				} else {
					syslog(LOG_WARNING|LOG_AUTH, "%s: Username not available.", myname);
				}
				break;
			case 'r':
				if (realm!=NULL) {
					rc = lak_escape(realm, &ebuf);
					if (rc == LAK_OK) {
						strcat(buf,ebuf);
						free(ebuf);
					}
				} else {
					syslog(LOG_WARNING|LOG_AUTH, "%s: Realm not available.", myname);
				}
				break;
			default:
				break;
		}
		ptr=temp+2;
	}
	if (temp<end)
		strcat(buf, ptr);

	if (session->conf->verbose)
		syslog(LOG_INFO|LOG_AUTH,"%s: After filter substitution, it's %s", myname, buf);

	*result = buf;

	return LAK_OK;
}

static int lak_get_user(LAK_SESSION *session, const char *user, const char *realm)
{
	const char *myname = "lak_get_user";

	char *filter;
	int rc;
	LDAPMessage *res, *entry;

	if (session->user != NULL) { /* Should not happen, just a sanity check */
		lak_release_user(&session->user);
	}

	rc = lak_filter(session, user, realm, &filter);
	if (rc != LAK_OK) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: lak_filter failed.", myname);
		return LAK_FAIL;
	}

	rc = lak_search(session, filter, NULL, &res);
	if (rc != LAK_OK) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: lak_search failed.", myname);
		free(filter);
		return LAK_FAIL;
	}

	entry = ldap_first_entry(session->ld, res); 
	if (entry == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: ldap_first_entry() failed.", myname);
		free(filter);
		ldap_msgfree(res);
		return LAK_FAIL;
	}

	session->user = (LAK_USER *) malloc(sizeof(LAK_USER));
	if (session->user == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "%s: Cannot allocate memory", myname);
		free(filter);
		ldap_msgfree (res);
		return LAK_FAIL;
	}

	session->user->name = strdup(user);
	if (session->user->name == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "%s: Cannot strdup or username is empty", myname);
		free(filter);
		ldap_msgfree (res);
		lak_release_user(&session->user);
		return LAK_FAIL;
	}

	if (realm) {
		session->user->realm = strdup(realm);
		if (session->user->realm == NULL) {
			syslog(LOG_ERR|LOG_AUTH, "%s: Cannot strdup", myname);
			free(filter);
			ldap_msgfree (res);
			lak_release_user(&session->user);
			return LAK_FAIL;
		}
	}

	session->user->dn = ldap_get_dn(session->ld, res);
	if (session->user->dn == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "%s: ldap_get_dn() failed.", myname);
		free(filter);
		ldap_msgfree (res);
		lak_release_user(&session->user);
		return LAK_FAIL;
	}

	session->user->bound_as_user = 0;

	free(filter);
	ldap_msgfree (res);

	return LAK_OK;
}


static int lak_get_session(LAK_SESSION **psession, const char *configFile) 
{
    	char  *myname = "lak_get_session";

	LAK_SESSION *session;
	int rc;

	session = *psession;

	if (session != NULL) {
		if (session->conf->verbose)
			syslog(LOG_INFO|LOG_AUTH, "%s: Reuse existing lak session.", myname);

		if (session->user != NULL) { /* garbage collection, should not happen */
			lak_release_user(&session->user);
		}
		return LAK_OK;
	}

	session = (LAK_SESSION *)malloc(sizeof(LAK));
	if (session == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "%s: Cannot allocate memory", myname);
		return LAK_FAIL;
	}

	session->bound=0;
	session->ld=NULL;
	session->conf=NULL;
	session->user=NULL;

	rc = lak_configure(&session->conf, configFile);
	if (rc != LAK_OK) {
		syslog(LOG_ERR|LOG_AUTH, "%s: Configure failed - check configuration file %s.", myname, session->conf->path);
		lak_release_config(&session->conf);
		free(session);
		return rc;
	}

	if (session->conf->verbose)
		syslog(LOG_INFO|LOG_AUTH, "%s: Start a new lak session.", myname);

	*psession=session;

	return LAK_OK;
}


static int lak_open_session(LAK_SESSION *session)
{
	char   *myname = "lak_open_session";

	int     rc = 0;

	if (session->conf->verbose)
		syslog(LOG_INFO|LOG_AUTH, "%s: Setup LDAP structures.", myname);

	if (session->conf->ssl || session->conf->start_tls) {
		if (session->conf->tls_cacertfile != NULL) {
			rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE, session->conf->tls_cacertfile);
			if (rc != LDAP_SUCCESS) {
				syslog (LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_X_TLS_CACERTFILE (%s).", myname, ldap_err2string (rc));
			}
		}

		if (session->conf->tls_cacertdir != NULL) {
			rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR, session->conf->tls_cacertdir);
			if (rc != LDAP_SUCCESS) {
				syslog (LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_X_TLS_CACERTDIR (%s).", myname, ldap_err2string (rc));
			}
		}

		/* require cert? */
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &session->conf->tls_checkpeer);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_X_TLS_REQUIRE_CERT (%s).", myname, ldap_err2string (rc));
		}

		if (session->conf->tls_ciphers != NULL) {
			/* set cipher suite, certificate and private key: */
			rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, session->conf->tls_ciphers);
			if (rc != LDAP_SUCCESS) {
				syslog (LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_X_TLS_CIPHER_SUITE (%s).", myname, ldap_err2string (rc));
			}
		}

		if (session->conf->tls_cert != NULL) {
			rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CERTFILE, session->conf->tls_cert);
			if (rc != LDAP_SUCCESS) {
				syslog (LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_X_TLS_CERTFILE (%s).", myname, ldap_err2string (rc));
			}
		}

		if (session->conf->tls_key != NULL) {
			rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_KEYFILE, session->conf->tls_key);
			if (rc != LDAP_SUCCESS) {
				syslog (LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_X_TLS_KEYFILE (%s).", myname, ldap_err2string (rc));
			}
		}
	}

	rc = ldap_initialize(&session->ld, session->conf->servers);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR|LOG_AUTH, "%s: ldap_initialize failed", myname, session->conf->servers);
		return LAK_FAIL;
	}

	if (session->conf->debug) {
		rc = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &(session->conf->debug));
		if (rc != LDAP_OPT_SUCCESS)
			syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_DEBUG_LEVEL %x.", myname, session->conf->debug);
	}

	if (session->conf->ssl || session->conf->start_tls) {
		int tls = LDAP_OPT_X_TLS_HARD;
		rc = ldap_set_option (session->ld, LDAP_OPT_X_TLS, &tls);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_X_TLS_HARD (%s).", myname, ldap_err2string (rc));
			return LAK_FAIL;
		}
	}

	rc = ldap_set_option(session->ld, LDAP_OPT_PROTOCOL_VERSION, &(session->conf->version));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_PROTOCOL_VERSION %d.", myname, session->conf->version);
		session->conf->version = LDAP_VERSION2;
	}

	rc = ldap_set_option(session->ld, LDAP_OPT_NETWORK_TIMEOUT, &(session->conf->timeout));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_NETWORK_TIMEOUT %d.%d.", myname, session->conf->timeout.tv_sec, session->conf->timeout.tv_usec);
	}

	ldap_set_option(session->ld, LDAP_OPT_TIMELIMIT, &(session->conf->timelimit));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_TIMELIMIT %d.", myname, session->conf->timelimit);
	}

	rc = ldap_set_option(session->ld, LDAP_OPT_DEREF, &(session->conf->deref));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_DEREF %d.", myname, session->conf->deref);
	}

	rc = ldap_set_option(session->ld, LDAP_OPT_REFERRALS, session->conf->referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_REFERRALS.", myname);
	}

	rc = ldap_set_option(session->ld, LDAP_OPT_SIZELIMIT, &(session->conf->sizelimit));
	if (rc != LDAP_OPT_SUCCESS)
		syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_SIZELIMIT %d.", myname, session->conf->sizelimit);

	rc = ldap_set_option(session->ld, LDAP_OPT_RESTART, session->conf->restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to set LDAP_OPT_RESTART.", myname);
	}

	/*
	 * Set up client-side caching
	 */
	if (session->conf->cache_expiry) {
		if (session->conf->verbose)
			syslog(LOG_INFO|LOG_AUTH, "%s: Enabling %ld-byte cache with %ld-second expiry", myname, session->conf->cache_size, session->conf->cache_expiry);

		rc = ldap_enable_cache(session->ld, session->conf->cache_expiry, session->conf->cache_size);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to configure cache: %d (%s) -- continuing", myname, rc, ldap_err2string(rc));
		}
	}

	return LAK_OK;
}


static int lak_reopen_session(LAK_SESSION *session)
{

	/* FYI: V3 lets us avoid five unneeded binds in a password change */
	if (session->conf->version == LDAP_VERSION2) {
		if (session->ld != NULL) {
			if (session->conf->cache_expiry)
				ldap_destroy_cache(session->ld);
			ldap_unbind_s(session->ld);

			session->ld = NULL;
		}
		if (session->user != NULL) {
			session->user->bound_as_user = 0;
		}
		return lak_open_session(session);
	}

	return LAK_OK;
}


static int lak_connect_anonymously(LAK_SESSION *session)
{
	char   *myname = "lak_connect_anonymously";

	int rc;

	if (session->conf->verbose)
		syslog(LOG_INFO|LOG_AUTH, "%s: Connecting anonymously to %s", myname, session->conf->servers);

	if (session->ld == NULL) {
		rc = lak_open_session (session);
		if (rc != LAK_OK)
			return rc;
	}

	rc = ldap_simple_bind_s(session->ld, session->conf->bind_dn, session->conf->bind_pw);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to bind as %s to %s: %d (%s)", myname, session->conf->bind_dn, session->conf->servers, rc, ldap_err2string(rc));
		return LAK_FAIL;
	}

	if (session->user != NULL) {
		session->user->bound_as_user = 0;
	}

	return LAK_OK;
}


static int lak_connect_as_user(LAK_SESSION *session, const char *password)
{
	char   *myname = "lak_connect_as_user";

	int rc;

	if (session->conf->verbose)
		syslog(LOG_INFO|LOG_AUTH, "%s: Connecting as %s to %s", myname, session->user->dn, session->conf->servers);

	/* this shouldn't ever happen */
	if (session->user == NULL) {
		return LAK_FAIL;
	}

	/* avoid binding anonymously with a DN but no password */
	if (password == NULL || password[0] == '\0') {
		return LAK_FAIL;
	}

	if (session->ld == NULL) {
		rc = lak_open_session (session);
		if (rc != LAK_OK)
			return rc;
	}

	rc = ldap_simple_bind_s(session->ld, session->user->dn, password);
	if (rc != LDAP_SUCCESS) {
		if (session->conf->verbose)
			syslog(LOG_WARNING|LOG_AUTH, "%s: Unable to bind to server %s as %s: %d (%s)", myname, session->conf->servers, session->user->dn, rc, ldap_err2string(rc));
		return LAK_FAIL;
	}

	session->user->bound_as_user = 1;

	return LAK_OK;
}


static int lak_search(LAK_SESSION *session, const char *filter, const char **attrs, LDAPMessage **res)
{
	char   *myname = "lak_search";
	int rc = 0;

	*res = NULL;

	/*
	* Connect to the LDAP server, if necessary.
	*/
	if (!session->bound) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: No existing connection reopening", myname);

		if (session->ld) {
			if (session->conf->verbose)
				syslog(LOG_INFO|LOG_AUTH, "%s: Closing existing connection", myname);
			if (session->conf->cache_expiry)
				ldap_destroy_cache(session->ld);
				
			ldap_unbind_s(session->ld);

			session->ld = NULL;
		}

		rc = lak_connect_anonymously(session);
		if (rc) {
			syslog(LOG_WARNING|LOG_AUTH, "%s: (re)connect attempt failed", myname);
			return LAK_FAIL;
		}

		session->bound = 1;
	} 

	/*
	* On to the search.
	*/
	rc = ldap_search_st(session->ld, session->conf->search_base, session->conf->scope, filter, (char **) attrs, 0, &(session->conf->timeout), res);
	switch (rc) {
		case LDAP_SUCCESS:
		case LDAP_SIZELIMIT_EXCEEDED:
			break;

		default:
			syslog(LOG_WARNING|LOG_AUTH, "%s: ldap_search_st() failed: %s", myname, ldap_err2string(rc));
			ldap_msgfree(*res);
			session->bound = 0;
			return LAK_FAIL;
	}

	if ((ldap_count_entries(session->ld, *res)) != 1) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: object not found or got ambiguous search result.", myname);
		ldap_msgfree(*res);
		return LAK_FAIL;
	}

	return LAK_OK;
}


static void lak_release_user(LAK_USER **puser)
{
	LAK_USER *user;

	user = *puser;

	if (user == NULL) {
		return;
	}

	if (user->name != NULL) {
		free (user->name);
	}

	if (user->realm != NULL) {
		free (user->realm);
	}

	if (user->dn != NULL) {
		ldap_memfree(user->dn);
	}

	free (user);
	*puser = NULL;

	return;
}


static void lak_release_config(LAK_CONF **pconf) 
{
	LAK_CONF *conf;

	conf = *pconf;

	if (conf == NULL) {
		return;
	}

	if (conf->path != NULL) {
		free(conf->path);
	}

#if 0
	if (conf->servers != NULL) {
		free(conf->servers);
	}
	
	if (conf->bind_dn != NULL) {
		free(conf->bind_dn);
	}

	if (conf->bind_pw != NULL) {
		free(conf->bind_pw);
	}

	if (conf->search_base != NULL) {
		free(conf->search_base);
	}

	if (conf->filter != NULL) {
		free(conf->filter);
	}
#endif
	free(configlist);

	free (conf);
	*pconf = NULL;

	return;
}


/* 
 * lak_retrieve - retrieve user@realm values specified by 'attrs'
 */
static int lak_retrieve(LAK_SESSION *session, const char *user, const char *realm, const char **attrs, LAK **result)
{
	char   *myname = "lak_retrieve";

	int rc = 0;
	char *filter = NULL;
	LAK *ptr = NULL, *temp = NULL;
	LDAPMessage *res;
	LDAPMessage *entry;
	BerElement *ber;
	char *attr, *val;
    
    	*result = NULL;

	rc = lak_filter(session, user, realm, &filter);
	if (rc != LAK_OK) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: lak_filter failed.", myname);
		return LAK_FAIL;
	}

	rc = lak_search(session, filter, attrs, &res);
	if (rc != LAK_OK) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: lak_search failed.", myname);
		free(filter);
		return LAK_FAIL;
	}

	entry = ldap_first_entry(session->ld, res); 
	if (entry == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: ldap_first_entry() failed.", myname);
		free(filter);
		ldap_msgfree(res);
		return LAK_FAIL;
	}

	attr = ldap_first_attribute(session->ld, entry, &ber);
	if (attr == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "%s: no attributes found", myname);
		free(filter);
		ldap_msgfree(res);
		return LAK_FAIL;
	}

	while (attr != NULL) {

		rc = lak_get_string_value(session->ld, entry, attr, &val);
		if (rc == LAK_OK) {
			temp = (LAK *) malloc(sizeof(LAK));
			if (temp == NULL) {
				syslog(LOG_ERR|LOG_AUTH, "%s: Cannot allocate memory", myname);
				ldap_memfree(attr);
				lak_free_result(*result);
				rc = LAK_FAIL;
				goto done;
			}

			if (*result == NULL) {
				*result = temp;
				ptr = *result;
			}
			else {
				ptr->next = temp;
				ptr = temp;
			}
			ptr->attribute = (char *)strdup(attr);
			if (ptr->attribute == NULL) {
				syslog(LOG_ERR|LOG_AUTH, "%s: strdup() failed", myname);
				ldap_memfree(attr);
				lak_free_result(*result);
				rc = LAK_FAIL;
				goto done;
			}
			ptr->value = val;
			ptr->len = strlen(ptr->value);
			ptr->next = NULL;

			if (session->conf->verbose)
				syslog(LOG_INFO|LOG_AUTH, "%s: Attribute %s, Value %s", myname, ptr->attribute, ptr->value);
		} else {
			syslog(LOG_WARNING|LOG_AUTH, "%s: Entry %s has no value.", myname, attr);
		}

		ldap_memfree(attr);

		attr = ldap_next_attribute(session->ld, entry, ber);
	}
	rc = LAK_OK;

done:
	if (ber != NULL)
		ber_free(ber, 0);
	ldap_msgfree(res);
	free(filter);

	if (*result == NULL)
		return LAK_NOENT;

	return rc;
}


static int lak_bind_authenticate(LAK_SESSION *session, const char *user, const char *realm, const char *password) 
{
	int rc = LAK_OK;

	if (session->user == NULL) {
		rc = lak_get_user(session, user, realm);
		if (rc != LAK_OK)
			return rc;
	}

	rc = lak_reopen_session(session);
	if (rc != LAK_OK) {
		return rc;
	}

	rc = lak_connect_as_user(session, password);
	lak_release_user(&session->user);
	lak_reopen_session(session);
	lak_connect_anonymously(session);

	return rc;
}


static int lak_custom_authenticate(LAK_SESSION *session, const char *user, const char *realm, const char *password) 
{
	char   *myname = "lak_custom_authenticate";

	LAK *lres;
	int rc;
	char *end, *temp, *ptr;
	const char *attrs[] = {"userPassword", NULL};

	rc = lak_retrieve(session, user, realm, attrs, &lres);
	if (rc != LAK_OK) {
		if (session->conf->verbose) {
			syslog(LOG_WARNING|LOG_AUTH, "%s: User not found %s", myname, user);
		}
		return LAK_FAIL;
	}

	rc = LAK_FAIL;

	ptr = lres->value;
	end = (char *) ptr + lres->len;

	temp = (char *) strchr(ptr, '}');

	if ((temp != NULL) && (temp < end)) {
		if (!strncasecmp(ptr, "{crypt}", temp - ptr + 1)) {
			if (!strcmp(ptr+7, (char *)crypt(password, ptr+7)))
				rc = LAK_OK;
		}
		else if (!strncasecmp(ptr, "{clear}", temp - ptr + 1)) {
			if (!strcmp(ptr+7, password))
				rc = LAK_OK;
		}
		/* Add MD5, SHA and others */
		else {
			syslog(LOG_WARNING|LOG_AUTH, "%s: Unknown password encryption for %s", myname, user);
		}
	}

	lak_free_result(lres);

	return(rc);
}


static void lak_close_session(LAK_SESSION **psession) 
{

	LAK_SESSION *session;

	session = *psession;

	if (session == NULL) {
		return;
	}

	if (session->ld != NULL) {
		if (session->conf->cache_expiry)
			ldap_destroy_cache(session->ld);
		ldap_unbind_s(session->ld);
	}

	lak_release_user(&session->user);
	lak_release_config(&session->conf);

	free(session);
	*psession = NULL;

	return;
}


int lak_authenticate(const char *user, const char *realm, const char *password, const char *configFile) 
{
	char   *myname = "lak_authenticate";

	LAK_SESSION *session;
	int rc;

	session = persistent_session;

	if (session == NULL) {
		rc = lak_get_session(&session, configFile);
		if (rc != LAK_OK) {
			syslog(LOG_WARNING|LOG_AUTH, "%s: lak_get_session failed.", myname);
			return LAK_FAIL;
		}
		persistent_session = session;
	}

	if (session->conf->auth_method == LAK_AUTH_METHOD_BIND) {
		rc = lak_bind_authenticate(session, user, realm, password);
	} else {
		rc = lak_custom_authenticate(session, user, realm, password);
	}

	return rc;
}


int lak_lookup_attrib(const char *user, const char *realm, const char *configFile, LAK **result) 
{
	char   *myname = "lak_lookup_attrib";

	LAK_SESSION *session;
	LAK *lres;
	char *attrs[2];
	int rc;

	session = persistent_session;

	if (session == NULL) {
		rc = lak_get_session(&session, configFile);
		if (rc != LAK_OK) {
			syslog(LOG_WARNING|LOG_AUTH, "%s: lak_get_session failed.", myname);
			return LAK_FAIL;
		}
		persistent_session = session;
	}

	if (session->conf->lookup_attrib == NULL) {
		return LAK_FAIL;
	}

	attrs[0] = session->conf->lookup_attrib;
	attrs[1] = NULL;

	rc = lak_retrieve(session, user, realm, (const char **)attrs, &lres);
	if (rc != LAK_OK) {
		if (session->conf->verbose) {
			syslog(LOG_WARNING|LOG_AUTH, "%s: Attribute not found.", myname);
		}
		return LAK_FAIL;
	}

	*result = lres;

	return LAK_OK;
}


/* 
 * lak_free_result - free memory buffers
 */
void lak_free_result(LAK *result) 
{
	/* char   *myname = "lak_free_result"; */

	if (result == NULL)
		return;

	if (result->next != NULL) {
		lak_free_result(result->next);
	}

	free(result->attribute);	
	free(result->value);	
	free(result);

	return;
}


#endif /* AUTH_LDAP */
