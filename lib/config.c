/* SASL Config file API
 * Tim Martin (originally in Cyrus distribution)
 * $Id: config.c,v 1.7 1999/10/01 20:16:47 leg Exp $
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

/*
 * Current Valid keys:
 *
 * pwcheck_method: <string>
 * auto_transition: <boolean>
 *
 * srvtab: <string>
 */


#include "sasl.h"
#include "saslint.h"

#include <stdio.h>
#include <ctype.h>
#ifndef WIN32
#include <syslog.h>
#endif /* WIN32 */

struct configlist {
    char *key;
    char *value;
};

static struct configlist *configlist;
static int nconfiglist;

#define CONFIGLISTGROWSIZE 10 /* 100 */

int sasl_config_init(const char *filename)
{
    FILE *infile;
    int lineno = 0;
    int alloced = 0;
    char buf[4096];
    char *p, *key;
    int result;

    nconfiglist=0;

    infile = fopen(filename, "r");
    if (!infile) {
      return SASL_CONTINUE;
    }
    
    while (fgets(buf, sizeof(buf), infile)) {
	lineno++;

	VL(("reading config file lineno=%i\n",lineno));

	if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
	for (p = buf; *p && isspace((int) *p); p++);
	if (!*p || *p == '#') continue;

	key = p;
	while (*p && (isalnum((int) *p) || *p == '-' || *p == '_')) {
	    if (isupper((int) *p)) *p = tolower(*p);
	    p++;
	}
	if (*p != ':') {
	  return SASL_FAIL;
	}
	*p++ = '\0';

	while (*p && isspace((int) *p)) p++;
	
	if (!*p) {
	  return SASL_FAIL;
	}

	if (nconfiglist == alloced) {
	    alloced += CONFIGLISTGROWSIZE;
	    configlist=sasl_REALLOC((char *)configlist, alloced*sizeof(struct configlist));
	    if (configlist==NULL) return SASL_NOMEM;
	}



	result = _sasl_strdup(key,
			      &(configlist[nconfiglist].key),
			      NULL);
	if (result!=SASL_OK) return result;
	result = _sasl_strdup(p,
			      &(configlist[nconfiglist].value),
			      NULL);
	if (result!=SASL_OK) return result;

	nconfiglist++;
    }
    fclose(infile);

    return SASL_OK;
}

const char *sasl_config_getstring(const char *key,const char *def)
{
    int opt;

    for (opt = 0; opt < nconfiglist; opt++) {
	if (*key == configlist[opt].key[0] &&
	    !strcmp(key, configlist[opt].key))
	  return configlist[opt].value;
    }
    return def;
}

int sasl_config_getint(const char *key,int def)
{
    const char *val = sasl_config_getstring(key, (char *)0);

    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) return def;
    return atoi(val);
}

int sasl_config_getswitch(const char *key,int def)
{
    const char *val = sasl_config_getstring(key, (char *)0);

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

