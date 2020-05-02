
/* MODULE: auth_htpasswd */

/* COPYRIGHT
 * Copyright (c) 2020 Ryszard Trojnacki.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain any existing copyright
 *    notice, and this entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 2. Redistributions in binary form must reproduce all prior and current
 *    copyright notices, this list of conditions, and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * END COPYRIGHT */

/* PUBLIC DEPENDENCIES */
#include "mechanisms.h"

#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <config.h>
#include <unistd.h>
#include <syslog.h>
#include <apr-1.0/apr_strings.h>
#include <apr-1.0/apr_md5.h>            /* for apr_password_validate */
#include <apr-1.0/apr_file_io.h>
#include <apr-1.0/apr_lib.h>

/* END PUBLIC DEPENDENCIES */

# include "globals.h"

#define RETURN(x) return strdup(x)

static apr_pool_t* pool;

#define MAX_STRING_LEN  8192        /* from httpd.h */

/* FUNCTION: auth_httpform_init */

/* SYNOPSIS
 * Validate the host and service names for the remote server.
 * END SYNOPSIS */

int
auth_htpasswd_init (
) {
    if(apr_initialize()!= APR_SUCCESS) {
        return -1;
    }
    apr_pool_initialize();
    if(apr_pool_create(&pool, NULL)!= APR_SUCCESS) {
        return -2;
    }
    return 0;
}

/* END FUNCTION: auth_httpform_init */


/* FUNCTION: auth_htpasswd */

char *					/* R: allocated response string */
auth_htpasswd (
        /* PARAMETERS */
#ifdef AUTH_HTPASSWD
        const char *login,			/* I: plaintext authenticator */
        const char *password,			/* I: plaintext password */
        const char *service __attribute__((unused)),
        const char *realm __attribute__((unused)),
#else
        const char *login __attribute__((unused)),/* I: plaintext authenticator */
        const char *password __attribute__((unused)),  /* I: plaintext password */
        const char *service __attribute__((unused)),
        const char *realm __attribute__((unused)),
#endif
        const char *remote __attribute__((unused)) /* I: remote host address */
        /* END PARAMETERS */
)
{
#ifdef AUTH_HTPASSWD
    /* VARIABLES */
    apr_file_t *fpw = NULL;
    char line[MAX_STRING_LEN];
    char *scratch, cp[MAX_STRING_LEN];

    int ret=-10;
    /* END VARIABLES */

    if(!mech_option) {
        syslog(LOG_WARNING, "auth_htpasswd: no -O parameter provided with htpasswd file name!");
        RETURN("NO");
    }

    if (apr_file_open(&fpw, mech_option, APR_READ | APR_BUFFERED, APR_OS_DEFAULT, pool) != APR_SUCCESS) {
        syslog(LOG_WARNING, "auth_htpasswd: couldn't open htpasswd '%s' file!", mech_option);
        RETURN("NO");   /* error opening htpasswd file*/
    }

    while (apr_file_gets(line, sizeof(line), fpw) == APR_SUCCESS) {
        char *colon;

        strcpy(cp, line);
        scratch = cp;
        while (apr_isspace(*scratch)) {
            ++scratch;
        }

        if (!*scratch || (*scratch == '#')) {
            continue;
        }
        /*
         * See if this is our user.
         */
        colon = strchr(scratch, ':');
        if (colon != NULL) {
            *colon = '\0';
        }
        else {
            /*
             * If we've not got a colon on the line, this could well
             * not be a valid htpasswd file.
             * We should bail at this point.
             */
            ret=-1;
            break;
        }
        if (strcmp(login, scratch) == 0) {
            /* We found the user we were looking for */
            /* Verify */
            char *hash = colon + 1;
            size_t len;

            len = strcspn(hash, "\r\n");
            if (len == 0) {
                /*apr_file_printf(errfile, "Empty hash for user %s" NL,
                                user);*/
                syslog(LOG_WARNING, "auth_htpasswd: invalid htpasswd '%s' file content!", mech_option);
                ret=-2;
                break;
            }
            hash[len] = '\0';

            if (apr_password_validate(password, hash) != APR_SUCCESS) {
                ret=1;  /* invalid password */
            } else {
                ret=0;
            }
            break;
        }
    }
    apr_file_close(fpw);

    if(ret) RETURN("NO");

    RETURN("OK");
#else
    RETURN("NO");
#endif
}

/* END FUNCTION: auth_htpasswd */

/* END MODULE: auth_htpasswd */
