/* COPYRIGHT
 * Copyright (c) 2002-2002 Igor Brezac
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
#include <ctype.h>

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ldap.h>
#include <lber.h>
#include "lak.h"

static LAK *persistent_lak = NULL;

#define configlistgrowsize 100

struct configlist {
	char *key;
	char *value;
};

#define CONFIGLISTGROWSIZE 100

static struct configlist *configlist;
static int nconfiglist;

static int lak_read_config(const char *);
static const char *lak_config_getstring(const char *, const char *);
static int lak_config_getint(const char *, int );
static int lak_config_getswitch(const char *, int );
static int lak_config(const char *, LAK_CONF **);
static int lak_escape(const char *, char **);
static int lak_filter(LAK *, const char *, const char *, char **);
static int lak_connect(LAK *);
static int lak_bind(LAK *, char, const char *, const char *);
static int lak_init(const char *, LAK **);
static int lak_search(LAK *, const char *, const char **, LDAPMessage **);
static int lak_retrieve(LAK *, const char *, const char *, const char **, LAK_RESULT **);
static int lak_auth_custom(LAK *, const char *, const char *, const char *);
static int lak_auth_bind(LAK *, const char *, const char *, const char *);
static void lak_free_config(LAK_CONF **);
static int lak_add_result(LAK *lak, LDAPMessage *, const char *, LAK_RESULT **);

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
			return LAK_NOMEM;

		configlist[nconfiglist].key = result;

		result = strdup(p);
		if (result==NULL) 
			return LAK_NOMEM;
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


static int lak_config(const char *configFile, LAK_CONF **ret)
{
	LAK_CONF *conf;
	int rc = 0;
	char *s;

	conf = malloc( sizeof(LAK_CONF) );
	if (conf == NULL) {
		return LAK_NOMEM;
	}

	conf->path = strdup(configFile);
	if (conf->path == NULL) {
		return LAK_NOMEM;
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
	conf->size_limit = lak_config_getint("ldap_size_limit", 1);
	conf->time_limit = lak_config_getint("ldap_time_limit", 5);
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
	conf->cache_ttl = lak_config_getint("ldap_cache_ttl", 0);
	conf->cache_mem = lak_config_getint("ldap_cache_mem", 0);
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
	conf->tls_check_peer = lak_config_getint("ldap_tls_check_peer", 0);
	conf->tls_cacert_file = (char *) lak_config_getstring("ldap_tls_cacert_file", NULL);
	conf->tls_cacert_dir = (char *) lak_config_getstring("ldap_tls_cacert_dir", NULL);
	conf->tls_ciphers = (char *) lak_config_getstring("ldap_tls_ciphers", NULL);
	conf->tls_cert = (char *) lak_config_getstring("ldap_tls_cert", NULL);
	conf->tls_key = (char *) lak_config_getstring("ldap_tls_key", NULL);

	*ret = conf;
	return LAK_OK;
}


/*
 * Note: calling function must free memory.
 */
static int lak_escape(const char *s, char **result) 
{
	char *buf;
	char *end, *ptr, *temp;

	buf = malloc(strlen(s) * 2 + 1);
	if (buf == NULL) {
		return LAK_NOMEM;
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
static int lak_filter(LAK *lak, const char *username, const char *realm, char **result) 
{
	char *buf; 
	char *end, *ptr, *temp;
	char *ebuf;
	int rc;
	
	if (lak->conf->filter == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "filter not setup");
		return LAK_FAIL;
	}

	buf=malloc(strlen(lak->conf->filter)+strlen(username)+strlen(realm)+1);
	if(buf == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "Cannot allocate memory");
		return LAK_NOMEM;
	}
	buf[0] = '\0';
	
	ptr=lak->conf->filter;
	end = ptr + strlen(ptr);

	while ((temp=strchr(ptr,'%'))!=NULL ) {

		if ((temp-ptr) > 0)
			strncat(buf, ptr, temp-ptr);

		if ((temp+1) >= end) {
			syslog(LOG_WARNING|LOG_AUTH, "Incomplete lookup substitution format");
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
					syslog(LOG_WARNING|LOG_AUTH, "Username not available.");
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
					syslog(LOG_WARNING|LOG_AUTH, "Realm not available.");
				}
				break;
			default:
				break;
		}
		ptr=temp+2;
	}
	if (temp<end)
		strcat(buf, ptr);

	*result = buf;

	return LAK_OK;
}


static int lak_init(const char *configFile, LAK **ret) 
{
	LAK *lak;
	int rc;

	lak = *ret;

	if (lak != NULL) {
		return LAK_OK;
	}

	lak = (LAK *)malloc(sizeof(LAK));
	if (lak == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "Cannot allocate memory");
		return LAK_NOMEM;
	}

	lak->bind_status=LAK_NOT_BOUND;
	lak->ld=NULL;
	lak->conf=NULL;

	rc = lak_config(configFile, &lak->conf);
	if (rc != LAK_OK) {
		lak_free_config(&lak->conf);
		free(lak);
		return rc;
	}

	*ret=lak;
	return LAK_OK;
}


static int lak_connect(LAK *lak)
{
	int     rc = 0;

	if (lak->conf->tls_cacert_file != NULL) {
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE, lak->conf->tls_cacert_file);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_X_TLS_CACERTFILE (%s).", ldap_err2string (rc));
		}
	}

	if (lak->conf->tls_cacert_dir != NULL) {
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR, lak->conf->tls_cacert_dir);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_X_TLS_CACERTDIR (%s).", ldap_err2string (rc));
		}
	}

	if (lak->conf->tls_check_peer != 0) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &lak->conf->tls_check_peer);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_X_TLS_REQUIRE_CERT (%s).", ldap_err2string (rc));
		}
	}

	if (lak->conf->tls_ciphers != NULL) {
		/* set cipher suite, certificate and private key: */
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, lak->conf->tls_ciphers);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_X_TLS_CIPHER_SUITE (%s).", ldap_err2string (rc));
		}
	}

	if (lak->conf->tls_cert != NULL) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, lak->conf->tls_cert);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_X_TLS_CERTFILE (%s).", ldap_err2string (rc));
		}
	}

	if (lak->conf->tls_key != NULL) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, lak->conf->tls_key);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_X_TLS_KEYFILE (%s).", ldap_err2string (rc));
		}
	}

	rc = ldap_initialize(&lak->ld, lak->conf->servers);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR|LOG_AUTH, "ldap_initialize failed", lak->conf->servers);
		return LAK_FAIL;
	}

	if (lak->conf->debug) {
		rc = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &(lak->conf->debug));
		if (rc != LDAP_OPT_SUCCESS)
			syslog(LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_DEBUG_LEVEL %x.", lak->conf->debug);
	}

	rc = ldap_set_option(lak->ld, LDAP_OPT_PROTOCOL_VERSION, &(lak->conf->version));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_PROTOCOL_VERSION %d.", lak->conf->version);
		lak->conf->version = LDAP_VERSION2;
	}

	rc = ldap_set_option(lak->ld, LDAP_OPT_NETWORK_TIMEOUT, &(lak->conf->timeout));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_NETWORK_TIMEOUT %d.%d.", lak->conf->timeout.tv_sec, lak->conf->timeout.tv_usec);
	}

	ldap_set_option(lak->ld, LDAP_OPT_TIMELIMIT, &(lak->conf->time_limit));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_TIMELIMIT %d.", lak->conf->time_limit);
	}

	rc = ldap_set_option(lak->ld, LDAP_OPT_DEREF, &(lak->conf->deref));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_DEREF %d.", lak->conf->deref);
	}

	rc = ldap_set_option(lak->ld, LDAP_OPT_REFERRALS, lak->conf->referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_REFERRALS.");
	}

	rc = ldap_set_option(lak->ld, LDAP_OPT_SIZELIMIT, &(lak->conf->size_limit));
	if (rc != LDAP_OPT_SUCCESS)
		syslog(LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_SIZELIMIT %d.", lak->conf->size_limit);

	rc = ldap_set_option(lak->ld, LDAP_OPT_RESTART, lak->conf->restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING|LOG_AUTH, "Unable to set LDAP_OPT_RESTART.");
	}

	/*
	 * Set up client-side caching
	 */
	if (lak->conf->cache_ttl) {
		rc = ldap_enable_cache(lak->ld, lak->conf->cache_ttl, lak->conf->cache_mem);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_WARNING|LOG_AUTH, "Unable to enable cache -- continuing (%s)", ldap_err2string(rc));
		}
	}

	return LAK_OK;
}


static int lak_bind(LAK *lak, char flag, const char *bind_dn, const char *password) 
{
	int rc;

	if (lak->bind_status == LAK_BIND_ANONYMOUS) {
		if (flag == LAK_BIND_ANONYMOUS) {
			return LAK_OK;
		}
	}

	if (lak->bind_status == LAK_NOT_BOUND) {
		if (lak->ld) {
			if (lak->conf->cache_ttl)
				ldap_destroy_cache(lak->ld);
			ldap_unbind_s(lak->ld);
			lak->ld = NULL;
		}

		rc = lak_connect(lak);
		if (rc != LAK_OK) {
			return rc;
		}
	} else {
		if (lak->conf->version == LDAP_VERSION2) {
			if (lak->ld != NULL) {
				if (lak->conf->cache_ttl)
					ldap_destroy_cache(lak->ld);
				ldap_unbind_s(lak->ld);

				lak->ld = NULL;
			}
			rc = lak_connect(lak);
			if (rc != LAK_OK) {
				return rc;
			}
		}
	}

	rc = ldap_simple_bind_s(lak->ld, bind_dn, password);
	if (rc != LDAP_SUCCESS) {
		if (flag == LAK_BIND_ANONYMOUS) {
			syslog(LOG_WARNING|LOG_AUTH, "ldap_simple_bind(as %s) failed (%s)", bind_dn, ldap_err2string(rc));
		}
		return LAK_FAIL;
	}

	lak->bind_status = flag;
	return LAK_OK;
}


static int lak_search(LAK *lak, const char *filter, const char **attrs, LDAPMessage **res)
{
	int rc = 0;
	int retry = 1;

	*res = NULL;

retry:
	rc = lak_bind(lak, LAK_BIND_ANONYMOUS, lak->conf->bind_dn, lak->conf->bind_pw);
	if (rc) {
		syslog(LOG_WARNING|LOG_AUTH, "lak_bind() failed");
		return LAK_FAIL;
	}

	rc = ldap_search_st(lak->ld, lak->conf->search_base, lak->conf->scope, filter, (char **) attrs, 0, &(lak->conf->timeout), res);
	switch (rc) {
		case LDAP_SUCCESS:
		case LDAP_SIZELIMIT_EXCEEDED:
			break;
		case LDAP_SERVER_DOWN:
			if (retry) {
				syslog(LOG_WARNING|LOG_AUTH, "ldap_search_st() failed: %s. Trying to reconnect.", ldap_err2string(rc));
				ldap_msgfree(*res);
				lak->bind_status = LAK_NOT_BOUND;
				retry = 0;
				goto retry;
			}
		default:
			syslog(LOG_ERR|LOG_AUTH, "ldap_search_st() failed: %s", ldap_err2string(rc));
			ldap_msgfree(*res);
			lak->bind_status = LAK_NOT_BOUND;
			return LAK_FAIL;
	}

	if ((ldap_count_entries(lak->ld, *res)) != 1) {
		syslog(LOG_DEBUG|LOG_AUTH, "Entry not found or more than one entries found (%s).", filter);
		ldap_msgfree(*res);
		return LAK_FAIL;
	}

	return LAK_OK;
}


/* 
 * lak_retrieve - retrieve user@realm values specified by 'attrs'
 */
static int lak_retrieve(LAK *lak, const char *user, const char *realm, const char **attrs, LAK_RESULT **ret)
{
	int rc = 0;
	char *filter = NULL;
	LDAPMessage *res;
	LDAPMessage *entry;
	BerElement *ber;
	char *attr;
    
    	*ret = NULL;

	rc = lak_filter(lak, user, realm, &filter);
	if (rc != LAK_OK) {
		return LAK_FAIL;
	}

	rc = lak_search(lak, filter, attrs, &res);
	if (rc != LAK_OK) {
		free(filter);
		return LAK_FAIL;
	}

	entry = ldap_first_entry(lak->ld, res); 
	if (entry == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "ldap_first_entry() failed.");
		free(filter);
		ldap_msgfree(res);
		return LAK_FAIL;
	}

	for (attr = ldap_first_attribute(lak->ld, entry, &ber); attr != NULL; 
		attr = ldap_next_attribute(lak->ld, entry, ber)) {

		lak_add_result(lak, entry, attr, ret);

		ldap_memfree(attr);
	}

	if (ber != NULL)
		ber_free(ber, 0);
	ldap_msgfree(res);
	free(filter);

	if (*ret == NULL)
		return LAK_NOENT;

	return LAK_OK;
}


static int lak_auth_custom(LAK *lak, const char *user, const char *realm, const char *password) 
{
	LAK_RESULT *lres;
	int rc;
	char *end, *temp, *ptr;
	const char *attrs[] = {"userPassword", NULL};

	rc = lak_retrieve(lak, user, realm, attrs, &lres);
	if (rc != LAK_OK) {
		return rc;
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
			syslog(LOG_WARNING|LOG_AUTH, "Unknown password encryption for %s", user);
		}
	}

	lak_free_result(lres);

	return(rc);
}


static int lak_auth_bind(LAK *lak, const char *user, const char *realm, const char *password) 
{
	char *filter;
	int rc;
	char *dn;
	LDAPMessage *res, *entry;

	rc = lak_filter(lak, user, realm, &filter);
	if (rc != LAK_OK) {
		syslog(LOG_WARNING|LOG_AUTH, "lak_filter failed.");
		return LAK_FAIL;
	}

	rc = lak_search(lak, filter, NULL, &res);
	if (rc != LAK_OK) {
		free(filter);
		return LAK_FAIL;
	}

	entry = ldap_first_entry(lak->ld, res); 
	if (entry == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "ldap_first_entry().");
		free(filter);
		ldap_msgfree(res);
		return LAK_FAIL;
	}

	dn = ldap_get_dn(lak->ld, res);
	if (dn == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "ldap_get_dn() failed.");
		free(filter);
		ldap_msgfree (res);
		return LAK_FAIL;
	}

	free(filter);
	ldap_msgfree(res);

	rc = lak_bind(lak, LAK_BIND_AS_USER, dn, password);

	ldap_memfree(dn);

	lak_bind(lak, LAK_BIND_ANONYMOUS, lak->conf->bind_dn, lak->conf->bind_pw);

	return rc;
}


int lak_authenticate(const char *user, const char *realm, const char *password, const char *configFile) 
{
	LAK *lak;
	int rc;

	lak = persistent_lak;

	if (lak == NULL) {
		rc = lak_init(configFile, &lak);
		if (rc != LAK_OK) {
			return rc;
		}
		persistent_lak = lak;
	}

	if (lak->conf->auth_method == LAK_AUTH_METHOD_BIND) {
		rc = lak_auth_bind(lak, user, realm, password);
	} else {
		rc = lak_auth_custom(lak, user, realm, password);
	}

	return rc;
}


int lak_lookup_attrib(const char *user, const char *realm, const char *configFile, LAK_RESULT **ret) 
{
	LAK *lak;
	LAK_RESULT *lres;
	char *attrs[2];
	int rc;

	lak = persistent_lak;

	if (lak == NULL) {
		rc = lak_init(configFile, &lak);
		if (rc != LAK_OK) {
			return rc;
		}
		persistent_lak = lak;
	}

	if (lak->conf->lookup_attrib == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "ldap_lookup_attrib not supplied.");
		return LAK_FAIL;
	}

	attrs[0] = lak->conf->lookup_attrib;
	attrs[1] = NULL;

	rc = lak_retrieve(lak, user, realm, (const char **)attrs, &lres);
	if (rc != LAK_OK) {
		return rc;
	}

	*ret = lres;
	return LAK_OK;
}


static void lak_free_config(LAK_CONF **ret) 
{
	LAK_CONF *conf;

	conf = *ret;

	if (conf == NULL) {
		return;
	}

	if (conf->path != NULL) {
		free(conf->path);
	}

	free(configlist);
	free (conf);

	*ret = NULL;
	return;
}

static int lak_add_result(LAK *lak, LDAPMessage *entry, const char *attr, LAK_RESULT **ret)  
{
	LAK_RESULT *lres, *temp;
	char **vals;
	
	vals = ldap_get_values(lak->ld, entry, attr);
	if (vals == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "ldap_get_values failed for %s.", attr);
		return LAK_FAIL;
	}

	lres = (LAK_RESULT *) malloc(sizeof(LAK_RESULT));
	if (lres == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "Cannot allocate memory");
		return LAK_NOMEM;
	}

	lres->value = strdup(vals[0]);
	ldap_value_free(vals);
	if (lres->value == NULL) {
		lak_free_result(lres);
		return LAK_NOMEM;
	}

	lres->attribute = strdup(attr);
	if (lres->attribute == NULL) {
		lak_free_result(lres);
		return LAK_NOMEM;
	}

	lres->len = strlen(lres->value);
	lres->next = NULL;

	if (*ret == NULL) {
		*ret = lres;
	} else {
		for (temp = (*ret)->next; temp != NULL; temp = temp->next) ;
		temp = lres;
	}

	return LAK_OK;
}


void lak_free_result(LAK_RESULT *lres) 
{
	if (lres == NULL)
		return;

	if (lres->next != NULL) {
		lak_free_result(lres->next);
	}

	if (lres->attribute != NULL) {
		free(lres->attribute);	
	}

	if (lres->value != NULL) {
		free(lres->value);	
	}

	free(lres);

	return;
}

#endif /* AUTH_LDAP */
