/* acconfig.h - autoheader configuration input
 * Rob Earhart
 */
/* 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef CONFIG_H
#define CONFIG_H

@TOP@

/* Our package */
#undef PACKAGE

/* Our version */
#undef VERSION

/* Set to the database name you want SASL to use for
 * username->secret lookups */
#undef SASL_DB_PATH

/* what db package are we using? */
#undef SASL_GDBM
#undef SASL_NDBM
#undef SASL_BERKELEYDB

/* This is where plugins will live at runtime */
#undef PLUGINDIR

/* Make autoheader happy */
#undef WITH_SYMBOL_UNDERSCORE

/* should we use the internal rc4 library? */
#undef WITH_RC4

/* do we have des available? */
#undef WITH_DES
#undef WITH_SSL_DES

/* Do we have kerberos for plaintext password checking? */
#undef HAVE_KRB

/* do we have SIA for plaintext password checking? */
#undef HAVE_SIA

/* do we have PAM for plaintext password checking? */
#undef HAVE_PAM

/* what flavor of GSSAPI are we using? */
#undef HAVE_GSS_C_NT_HOSTBASED_SERVICE

/* do we have gssapi.h or gssapi/gssapi.h? */
#undef HAVE_GSSAPI_H

/* do we have getsubopt()? */
#undef HAVE_GETSUBOPT

/* Does your system have the snprintf() call? */
#undef HAVE_SNPRINTF

/* Does your system have the vsnprintf() call? */
#undef HAVE_VSNPRINTF

/* does your system have gettimeofday()? */
#undef HAVE_GETTIMEOFDAY

/* should we include support for the pwcheck daemon? */
#undef HAVE_PWCHECK

/* where do we look for the pwcheck daemon? */
#undef PWCHECKDIR

/* should we include support for the saslauth daemon? */
#undef HAVE_SASLAUTHD

/* where does saslauthd look for the communication socket? */
#undef PATH_SASLAUTHD_RUNDIR

/* do we pay attention to IP addresses in the kerberos 4 tickets? */
#undef KRB4_IGNORE_IP_ADDRESS

/* do we have a preferred mechanism, or should we just pick the highest ssf? */
#undef PREFER_MECH

/* define if your compile has __attribute__ */
#undef HAVE___ATTRIBUTE__

/* define if you have unistd.h */
#undef HAVE_UNISTD_H

/* define if your system has getpid() */
#undef HAVE_GETPID

@BOTTOM@

/* location of the random number generator */
#ifndef DEV_RANDOM
#define DEV_RANDOM "/dev/random"
#endif

/* Make Solaris happy... */
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif

/* Make Linux happy... */
#define _GNU_SOURCE

#include <stdio.h>

/* we no longer support or use nana, 
   but we still have code that refers to it */
#define WITHOUT_NANA
#define L_DEFAULT_GUARD (0)
#define I_DEFAULT_GUARD (0)
#define I(foo)
#define VL(foo)
#define VLP(foo,bar)

#ifndef HAVE___ATTRIBUTE__
/* Can't use attributes... */
#define __attribute__(foo)
#endif

#define SASL_PATH_ENV_VAR "SASL_PATH"

#include <stdlib.h>
#include <sys/types.h>
#ifndef WIN32
# include <netdb.h>
# include <sys/param.h>
#else /* WIN32 */
# include <winsock.h>
#endif /* WIN32 */
#include <string.h>

#include <netinet/in.h>

#endif /* CONFIG_H */
