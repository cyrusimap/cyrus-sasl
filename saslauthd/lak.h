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

#ifndef _LAK_H
#define _LAK_H

#include <ldap.h>
#include <lber.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#define LAK_OK 0
#define LAK_FAIL -1
#define LAK_NOENT -2

#define LAK_AUTH_METHOD_BIND 0
#define LAK_AUTH_METHOD_CUSTOM 1

typedef struct lak_conf {
    char   *path;
    char   *servers;
    char   *bind_dn;
    char   *bind_pw;
    int     version;
    struct  timeval timeout;
    int     sizelimit;
    int     timelimit;
    int     deref;
    int     referrals;
    int     restart;
    long    cache_expiry;
    long    cache_size;
    int     scope;
    char   *search_base;
    char   *filter;
    char   *lookup_attrib;
    char    auth_method;
    int     debug;
    int     verbose;
    int     ssl;
    int     start_tls;
    int     tls_checkpeer;
    char   *tls_cacertfile;
    char   *tls_cacertdir;
    char   *tls_ciphers;
    char   *tls_cert;
    char   *tls_key;
} LAK_CONF;

typedef struct lak_user {
    char    *name;
    char    *realm;
    char    *dn;
    char     bound_as_user;
} LAK_USER;

typedef struct lak_session {
    LDAP     *ld;
    char      bound;
    LAK_CONF *conf;
    LAK_USER *user;
} LAK_SESSION;

typedef struct lak {
    char       *attribute;
    char       *value;
    size_t      len;
    struct lak *next;
} LAK;

int lak_authenticate(const char *, const char *, const char *, const char *);
int lak_lookup_attrib(const char *, const char *, const char *, LAK **);
void lak_free_result(LAK *);

#endif  /* _LAK_H */
