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
#define LAK_NOMEM -3

#define LAK_NOT_BOUND 0
#define LAK_BIND_ANONYMOUS 1
#define LAK_BIND_AS_USER 2

#define LAK_AUTH_METHOD_BIND 0
#define LAK_AUTH_METHOD_CUSTOM 1
#define LAK_AUTH_METHOD_FASTBIND 2

typedef struct lak_conf {
    char   *path;
    char   *servers;
    char   *bind_dn;
    char   *bind_pw;
    int     version;
    struct  timeval timeout;
    int     size_limit;
    int     time_limit;
    int     deref;
    int     referrals;
    int     restart;
    int     scope;
    char   *search_base;
    char   *filter;
    char   *group_dn;
    char   *group_attr;
    char   *password_attr;
    char    auth_method;
    int     tls_check_peer;
    char   *tls_cacert_file;
    char   *tls_cacert_dir;
    char   *tls_ciphers;
    char   *tls_cert;
    char   *tls_key;
    int     debug;
} LAK_CONF;

typedef struct lak {
    LDAP     *ld;
    char      bind_status;
    LAK_CONF *conf;
} LAK;

typedef struct lak_result {
    char              *attribute;
    char              *value;
    size_t             len;
    struct lak_result *next;
} LAK_RESULT;

int lak_init(const char *, LAK **);
void lak_close(LAK *);
int lak_authenticate(LAK *, const char *, const char *, const char *, const char *);
int lak_retrieve(LAK *, const char *, const char *, const char *, const char **, LAK_RESULT **);
void lak_result_free(LAK_RESULT *);

#endif  /* _LAK_H */
