/* acconfig.h - autoheader configuration input
 * Rob Earhart
 */
/***********************************************************
        Copyright 1998 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

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

/* Do we have rc4 available? */
#undef WITH_CMU_RC4
#undef WITH_SSL_RC4

/* do we have des available? */
#undef WITH_DES

/* Do we have kerberos for plaintext password checking? */
#undef HAVE_KRB

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
