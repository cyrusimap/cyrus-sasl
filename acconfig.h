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

/* This is where plugins will live at runtime */
#undef PLUGINDIR

/* Make autoheader happy */
#undef WITH_SYMBOL_UNDERSCORE

@BOTTOM@

/* Make Solaris happy... */
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif

/* Make Linux happy... */
#define _GNU_SOURCE

#include <stdio.h>

#ifdef HAVE_LIBNANA

extern int _sasl_debug;
#define L_DEFAULT_GUARD (_sasl_debug)

#include <nana.h>
#else				/* ! HAVE_LIBNANA */
#define WITHOUT_NANA
#define L_DEFAULT_GUARD (0)
#define I_DEFAULT_GUARD (0)
#define I(foo)
#define VL(foo)
#define VLP(foo,bar)
#endif				/* ! HAVE_LIBNANA */

#ifndef __GNUC__
/* Can't use attributes... */
#define __attribute__(foo)
#endif

#define SASL_PATH_ENV_VAR "SASL_PATH"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <stdlib.h>
#include <sys/types.h>
#ifndef WIN32
# include <netdb.h>
# include <sys/param.h>
#else /* WIN32 */
# include <winsock.h>
#endif /* WIN32 */
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else /* HAVE_DIRENT_H */
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif /* ! HAVE_DIRENT_H */
#if STDC_HEADERS
# include <string.h>
#else  /* STDC_HEADERS */
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif /* ! HAVE_STRCHR */
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# else /* HAVE_STRINGS_H */
char *strchr(), *strrchr();
# endif /* ! HAVE_STRINGS_H */
# ifndef HAVE_MEMCPY
#  define memcpy(d, s, n) bcopy ((s), (d), (n))
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# endif /* ! HAVE_MEMCPY */
#endif /* ! STDC_HEADERS */

#endif /* CONFIG_H */
