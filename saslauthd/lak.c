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

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#endif

#include <ldap.h>
#include <lber.h>
#include "lak.h"

struct password_scheme {
	char *hash;
	int (*check) (const char *cred, const char *passwd);
};

static int lak_config_read(LAK_CONF *, const char *);
static int lak_config_int(const char *);
static int lak_config_switch(const char *);
static void lak_config_free(LAK_CONF *);
static int lak_config(const char *, LAK_CONF **);
static int lak_escape(const char *, char **);
static int lak_filter(LAK *, const char *, const char *, char **);
static int lak_connect(LAK *);
static int lak_bind(LAK *, char, const char *, const char *);
static int lak_search(LAK *, const char *, const char **, LDAPMessage **);
static int lak_auth_custom(LAK *, const char *, const char *, const char *);
static int lak_auth_bind(LAK *, const char *, const char *, const char *);
static int lak_result_add(LAK *lak, const char *, const char *, LAK_RESULT **);
static int lak_check_password(const char *, const char *);
static int lak_check_crypt(const char *, const char *);
#ifdef HAVE_OPENSSL
static int lak_base64_decode(const char *, char **, int *);
static int lak_check_md5(const char *, const char *);
static int lak_check_smd5(const char *, const char *);
static int lak_check_sha1(const char *, const char *);
static int lak_check_ssha1(const char *, const char *);
#endif

static const struct password_scheme password_scheme[] = {
	{ "{CRYPT}", lak_check_crypt },
	{ "{UNIX}", lak_check_crypt },
#ifdef HAVE_OPENSSL
	{ "{MD5}", lak_check_md5 },
	{ "{SMD5}", lak_check_smd5 },
	{ "{SHA}", lak_check_sha1 },
	{ "{SSHA}", lak_check_ssha1 },
#endif
	{ NULL, NULL }
};

static int lak_config_read(LAK_CONF *conf, const char *configfile)
{
	FILE *infile;
	int i, lineno = 0;
	int alloced = 0;
	char buf[4096];
	char *p, *key;
	char *result;

	infile = fopen(configfile, "r");
	if (!infile) {
	    syslog(LOG_ERR|LOG_AUTH,
		   "Could not open LDAP config file: %s (%m)",
		   configfile);
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

		if (!strcasecmp(key, "ldap_servers")) {
			conf->servers = strdup(p);
			if (conf->servers == NULL) {
				fclose(infile);
				return LAK_NOMEM;
			}
		} else if (!strcasecmp(key, "ldap_bind_dn")) {
			conf->bind_dn = strdup(p);
			if (conf->bind_dn == NULL) {
				fclose(infile);
				return LAK_NOMEM;
			}
		} else if (!strcasecmp(key, "ldap_bind_pw")) {
			conf->bind_pw = strdup(p);
			if (conf->bind_pw == NULL) {
				fclose(infile);
				return LAK_NOMEM;
			}
		} else if (!strcasecmp(key, "ldap_version")) {
			conf->version = lak_config_int(p);
		} else if (!strcasecmp(key, "ldap_search_base")) {
			conf->search_base = strdup(p);
			if (conf->search_base == NULL) {
				fclose(infile);
				return LAK_NOMEM;
			}
		} else if (!strcasecmp(key, "ldap_filter")) {
			conf->filter = strdup(p);
			if (conf->filter == NULL) {
				fclose(infile);
				return LAK_NOMEM;
			}
		} else if (!strcasecmp(key, "ldap_auth_method")) {
			if (!strcasecmp(p, "custom")) {
				conf->auth_method = LAK_AUTH_METHOD_CUSTOM;
			}
		} else if (!strcasecmp(key, "ldap_timeout")) {
			conf->timeout.tv_sec = lak_config_int(p);
			conf->timeout.tv_usec = 0;
		} else if (!strcasecmp(key, "ldap_size_limit")) {
			conf->size_limit = lak_config_int(p);
		} else if (!strcasecmp(key, "ldap_time_limit")) {
			conf->time_limit = lak_config_int(p);
		} else if (!strcasecmp(key, "ldap_deref")) {
			if (!strcasecmp(p, "search")) {
				conf->deref = LDAP_DEREF_SEARCHING;
			} else if (!strcasecmp(p, "find")) {
				conf->deref = LDAP_DEREF_FINDING;
			} else if (!strcasecmp(p, "always")) {
				conf->deref = LDAP_DEREF_ALWAYS;
			} else if (!strcasecmp(p, "never")) {
				conf->deref = LDAP_DEREF_NEVER;
			}
		} else if (!strcasecmp(key, "ldap_referrals")) {
			conf->referrals = lak_config_switch(p);
		} else if (!strcasecmp(key, "ldap_restart")) {
			conf->restart = lak_config_switch(p);
		} else if (!strcasecmp(key, "ldap_cache_ttl")) {
			conf->cache_ttl = lak_config_int(p);
		} else if (!strcasecmp(key, "ldap_cache_mem")) {
			conf->cache_mem = lak_config_int(p);
		} else if (!strcasecmp(key, "ldap_scope")) {
			if (!strcasecmp(p, "one")) {
				conf->scope = LDAP_SCOPE_ONELEVEL;
			} else if (!strcasecmp(p, "base")) {
				conf->scope = LDAP_SCOPE_BASE;
			}
		} else if (!strcasecmp(key, "ldap_tls_check_peer")) {
			conf->tls_check_peer = lak_config_switch(p);
		} else if (!strcasecmp(key, "ldap_tls_cacert_file")) {
			conf->tls_cacert_file = strdup(p);
		} else if (!strcasecmp(key, "ldap_tls_cacert_dir")) {
			conf->tls_cacert_dir = strdup(p);
		} else if (!strcasecmp(key, "ldap_tls_ciphers")) {
			conf->tls_ciphers = strdup(p);
		} else if (!strcasecmp(key, "ldap_tls_cert")) {
			conf->tls_cert = strdup(p);
		} else if (!strcasecmp(key, "ldap_tls_key")) {
			conf->tls_key = strdup(p);
		} else if (!strcasecmp(key, "ldap_debug")) {
			conf->debug = lak_config_int(p);
		}
	}

	fclose(infile);

	return LAK_OK;
}

static int lak_config_int(const char *val)
{
    if (!val) return 0;

    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) return 0;

    return atoi(val);
}

static int lak_config_switch(const char *val)
{
    if (!val) return 0;
    
    if (*val == '0' || *val == 'n' ||
	(*val == 'o' && val[1] == 'f') || *val == 'f') {
	return 0;
    } else if (*val == '1' || *val == 'y' ||
	     (*val == 'o' && val[1] == 'n') || *val == 't') {
	return 1;
    }
    return 0;
}

static void lak_config_free(LAK_CONF *conf) 
{
	if (conf == NULL) {
		return;
	}

	if (conf->servers != NULL) {
		memset(conf->servers, 0, strlen(conf->servers));
		free(conf->servers);
	}
	if (conf->bind_dn != NULL) {
		memset(conf->bind_dn, 0, strlen(conf->bind_dn));
		free(conf->bind_dn);
	}
	if (conf->bind_pw != NULL) {
		memset(conf->bind_pw, 0, strlen(conf->bind_pw));
		free(conf->bind_pw);
	}
	if (conf->search_base != NULL)
		free(conf->search_base);
	if (conf->filter != NULL)
		free(conf->filter);
	if (conf->tls_cacert_file != NULL)
		free(conf->tls_cacert_file);
	if (conf->tls_cacert_dir != NULL)
		free(conf->tls_cacert_dir);
	if (conf->tls_ciphers != NULL)
		free(conf->tls_ciphers);
	if (conf->tls_cert != NULL)
		free(conf->tls_cert);
	if (conf->tls_key != NULL)
		free(conf->tls_key);
	if (conf->path != NULL)
		free(conf->path);

	free (conf);

	return;
}

static int lak_config(const char *configfile, LAK_CONF **ret)
{
	LAK_CONF *conf;
	int rc = 0;
	char *s;

	conf = malloc( sizeof(LAK_CONF) );
	if (conf == NULL) {
		return LAK_NOMEM;
	}

	memset(conf, 0, sizeof(LAK_CONF));

	conf->servers = "ldap://localhost/";
	conf->bind_dn = "";
	conf->bind_pw = "";
	conf->version = LDAP_VERSION3;
	conf->search_base = "";
	conf->filter = "uid=%u";
	conf->auth_method = LAK_AUTH_METHOD_BIND;
	conf->timeout.tv_sec = 5;
	conf->timeout.tv_usec = 0;
	conf->size_limit = 1;
	conf->time_limit = 5;
	conf->deref = LDAP_DEREF_NEVER;
	conf->restart = 1;
	conf->scope = LDAP_SCOPE_SUBTREE;

	conf->path = strdup(configfile);
	if (conf->path == NULL) {
		lak_config_free(conf);
		return LAK_NOMEM;
	}

	rc = lak_config_read(conf, conf->path);
	if (rc != LAK_OK) {
		lak_config_free(conf);
		return rc;
	}

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

	/* to permit multiple occurences of username and/or realm in filter */
	/* and avoid memory overflow in filter build [eg: (|(uid=%u)(userid=%u)) ] */
	int percents, realm_len, user_len, maxparamlength;
	
	if (lak->conf->filter == NULL) {
		syslog(LOG_WARNING|LOG_AUTH, "filter not setup");
		return LAK_FAIL;
	}

	/* find the longest param of username and realm */
	user_len=strlen(username);
	realm_len=strlen(realm);
	if( user_len > realm_len )
	    maxparamlength = user_len;
	else
	    maxparamlength = realm_len;

	/* find the number of occurences of percent sign in filter */
	for( percents=0, buf=lak->conf->filter; *buf; buf++ ) {
		if( *buf == '%' ) percents++;
	}

	buf=malloc(strlen(lak->conf->filter) + (percents * maxparamlength) +1);
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

int lak_init(const char *configfile, LAK **ret) 
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

	rc = lak_config(configfile, &lak->conf);
	if (rc != LAK_OK) {
		free(lak);
		return rc;
	}

	*ret=lak;
	return LAK_OK;
}

void lak_close(LAK *lak) {

	if (lak == NULL)
		return;

	if (lak->ld != NULL) {
		if (lak->conf->cache_ttl)
			ldap_destroy_cache(lak->ld);
		ldap_unbind_s(lak->ld);
	}

	lak_config_free(lak->conf);

	free(lak);

	return;
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
	if (rc != LAK_OK) {
		syslog(LOG_WARNING|LOG_AUTH, "lak_bind() failed");
		return LAK_FAIL;
	}

	rc = ldap_search_st(lak->ld, lak->conf->search_base, lak->conf->scope, filter, (char **) attrs, 0, &(lak->conf->timeout), res);
	switch (rc) {
		case LDAP_SUCCESS:
		case LDAP_NO_SUCH_OBJECT:
			break;
		case LDAP_TIMEOUT:
		case LDAP_TIMELIMIT_EXCEEDED:
		case LDAP_BUSY:
		case LDAP_UNAVAILABLE:
		case LDAP_INSUFFICIENT_ACCESS:
			/*  We do not need to re-connect to the LDAP server 
			    under these conditions */
			syslog(LOG_ERR|LOG_AUTH, "ldap_search_st() failed: %s", ldap_err2string(rc));
			ldap_msgfree(*res);
			return LAK_FAIL;
		case LDAP_SERVER_DOWN:
			if (retry) {
				syslog(LOG_WARNING|LOG_AUTH, "ldap_search_st() failed: %s. Trying to reconnect.", ldap_err2string(rc));
				ldap_msgfree(*res);
				lak->bind_status = LAK_NOT_BOUND;
				retry--;
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
int lak_retrieve(LAK *lak, const char *user, const char *realm, const char **attrs, LAK_RESULT **ret)
{
	int rc = 0, i;
	char *filter = NULL;
	LDAPMessage *res;
	LDAPMessage *entry;
	BerElement *ber;
	char *attr, **vals;
    
    	*ret = NULL;

	if (lak == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "lak_init did not run.");
		return LAK_FAIL;
	}

	if (user == NULL || user[0] == '\0') {
		return LAK_FAIL;
	}

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

	rc = LAK_OK;
	for (attr = ldap_first_attribute(lak->ld, entry, &ber); attr != NULL; 
		attr = ldap_next_attribute(lak->ld, entry, ber)) {

		vals = ldap_get_values(lak->ld, entry, attr);
		if (vals == NULL) {
			continue;
		}

		for (i = 0; vals[i] != NULL; i++) {
			rc = lak_result_add(lak, attr, vals[i], ret);
			if (rc != LAK_OK) {
				break;
			}
		}

		ldap_value_free(vals);
		ldap_memfree(attr);

		if (rc != LAK_OK) {
			lak_result_free(*ret);
			*ret = NULL;
			break;
		}
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
	LAK_RESULT *lres, *ptr;
	int rc;
	struct password_check *pc;
	const char *attrs[] = {"userPassword", NULL};

	rc = lak_retrieve(lak, user, realm, attrs, &lres);
	if (rc != LAK_OK) {
		return rc;
	}

	rc = LAK_FAIL;

	for (ptr = lres; ptr != NULL; ptr = ptr->next) {
		
		rc = lak_check_password(ptr->value, password);
		if (rc == LAK_OK) {
			break;
		}
	}

	lak_result_free(lres);

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


int lak_authenticate(LAK *lak, const char *user, const char *realm, const char *password) 
{
	int rc;

	if (lak == NULL) {
		syslog(LOG_ERR|LOG_AUTH, "lak_init did not run.");
		return LAK_FAIL;
	}

	if (user == NULL || user[0] == '\0') {
		return LAK_FAIL;
	}

	if (lak->conf->auth_method == LAK_AUTH_METHOD_BIND) {
		rc = lak_auth_bind(lak, user, realm, password);
	} else {
		rc = lak_auth_custom(lak, user, realm, password);
	}

	return rc;
}


static int lak_result_add(LAK *lak, const char *attr, const char *val, LAK_RESULT **ret)  
{
	LAK_RESULT *lres;
	
	lres = (LAK_RESULT *) malloc(sizeof(LAK_RESULT));
	if (lres == NULL) {
		return LAK_NOMEM;
	}

	lres->next = NULL;

	lres->attribute = strdup(attr);
	if (lres->attribute == NULL) {
		lak_result_free(lres);
		return LAK_NOMEM;
	}

	lres->value = strdup(val);
	if (lres->value == NULL) {
		lak_result_free(lres);
		return LAK_NOMEM;
	}
	lres->len = strlen(lres->value);

	lres->next = *ret;

	*ret = lres;
	return LAK_OK;
}


void lak_result_free(LAK_RESULT *res) 
{
	LAK_RESULT *lres, *ptr = res;

	if (ptr == NULL)
		return;

	for (lres = ptr; lres != NULL; lres = ptr) {

		ptr = lres->next;

		if (lres->attribute != NULL) {
			memset(lres->attribute, 0, strlen(lres->value));
			free(lres->attribute);	
		}

		if (lres->value != NULL) {
			memset(lres->value, 0, strlen(lres->value));
			free(lres->value);	
		}

		lres->next = NULL;

		free(lres);
	}

	return;
}

static int lak_check_password(const char *hash, const char *passwd) 
{
	int i, hlen;
	int rc;

	if (hash == NULL || hash == '\0') {
		return LAK_FAIL;
	}

	if (passwd == NULL || passwd == '\0') {
		return LAK_FAIL;
	}

	for (i = 0; password_scheme[i].hash != NULL; i++) {

		hlen = strlen(password_scheme[i].hash);
		if (!strncasecmp(password_scheme[i].hash, hash, hlen)) {
			if (password_scheme[i].check) {
				rc = (password_scheme[i].check)(hash+hlen, passwd);
			}
			return rc;
		}
	}

	return strcmp(hash, passwd) ? LAK_FAIL : LAK_OK;
}

#ifdef HAVE_OPENSSL

static int lak_base64_decode(const char *src, char **ret, int *rlen) {

	int rc, i, tlen = 0;
	char *text;
	EVP_ENCODE_CTX EVP_ctx;

	text = (char *)malloc(((strlen(src)+3)/4 * 3) + 1);
	if (text == NULL) {
		return LAK_NOMEM;
	}

	EVP_DecodeInit(&EVP_ctx);
	rc = EVP_DecodeUpdate(&EVP_ctx, text, &i, (char *)src, strlen(src));
	if (rc < 0) {
		free(text);
		return LAK_FAIL;
	}
	tlen += i;
	EVP_DecodeFinal(&EVP_ctx, text, &i); 

	*ret = text;
	if (rlen != NULL) {
		*rlen = tlen;
	}

	return LAK_OK;
}

static int lak_check_md5(const char *hash, const char *passwd)
{
	int rc;
	MD5_CTX MD5_ctx;
	unsigned char MD5digest[MD5_DIGEST_LENGTH];
	char *cred;

	rc = lak_base64_decode(hash, &cred, NULL);
	if (rc != LAK_OK) {
		return rc;
	}

	MD5_Init(&MD5_ctx);
	MD5_Update(&MD5_ctx, passwd, strlen(passwd));
	MD5_Final(MD5digest, &MD5_ctx);

	rc = memcmp((char *)cred, (char *)MD5digest, sizeof(MD5digest));
	free(cred);
	return rc ? LAK_FAIL : LAK_OK;
}

static int lak_check_smd5(const char *hash, const char *passwd)
{
	int rc, clen;
	MD5_CTX MD5_ctx;
	unsigned char MD5digest[MD5_DIGEST_LENGTH];
	char *cred;

	rc = lak_base64_decode(hash, &cred, &clen);
	if (rc != LAK_OK) {
		return rc;
	}

	MD5_Init(&MD5_ctx);
	MD5_Update(&MD5_ctx, passwd, strlen(passwd));
	MD5_Update(&MD5_ctx, &cred[sizeof(MD5digest)], clen - sizeof(MD5digest));
	MD5_Final(MD5digest, &MD5_ctx);

	rc = memcmp((char *)cred, (char *)MD5digest, sizeof(MD5digest));
	free(cred);
	return rc ? LAK_FAIL : LAK_OK;
}

static int lak_check_sha1(const char *hash, const char *passwd)
{
	int rc;
	SHA_CTX SHA1_ctx;
	unsigned char SHA1digest[SHA_DIGEST_LENGTH];
	char *cred;

	rc = lak_base64_decode(hash, &cred, NULL);
	if (rc != LAK_OK) {
		return rc;
	}

	SHA1_Init(&SHA1_ctx);
	SHA1_Update(&SHA1_ctx, passwd, strlen(passwd));
	SHA1_Final(SHA1digest, &SHA1_ctx);

	rc = memcmp((char *)cred, (char *)SHA1digest, sizeof(SHA1digest));
	free(cred);
	return rc ? LAK_FAIL : LAK_OK;
} 

static int lak_check_ssha1(const char *hash, const char *passwd)
{
	int rc, clen;
	SHA_CTX SHA1_ctx;
	unsigned char SHA1digest[SHA_DIGEST_LENGTH];
	char *cred;

	rc = lak_base64_decode(hash, &cred, &clen);
	if (rc != LAK_OK) {
		return rc;
	}

	SHA1_Init(&SHA1_ctx);
	SHA1_Update(&SHA1_ctx, passwd, strlen(passwd));
	SHA1_Update(&SHA1_ctx, &cred[sizeof(SHA1digest)], clen - sizeof(SHA1digest));
	SHA1_Final(SHA1digest, &SHA1_ctx);

	rc = memcmp((char *)cred, (char *)SHA1digest, sizeof(SHA1digest));
	free(cred);
	return rc ? LAK_FAIL : LAK_OK;
} 

#endif /* HAVE_OPENSSL */

static int lak_check_crypt(const char *hash, const char *passwd) 
{
	char *cred;

	if (hash == NULL || hash[0] == '\0') {
		return LAK_FAIL;
	}

	if (passwd == NULL || passwd[0] == '\0') {
		return LAK_FAIL;
	}

	if (strlen(hash) < 2 ) {
		return LAK_FAIL;
	}

	cred = crypt(passwd, hash);
	if( cred == NULL || cred[0] == '\0' ) {
		return LAK_FAIL;
	}

	return strcmp(hash, cred) ? LAK_FAIL : LAK_OK;
}

#endif /* AUTH_LDAP */
