/* acconfig.h - autoheader configuration input
 * Rob Earhart
 * $Id: acconfig.h,v 1.1 1998/11/16 20:06:36 rob Exp $
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

/* The DB lib type we're using */
#undef SASL_DB_TYPE

/* This is where plugins will live at runtime */
#undef PLUGINDIR

@BOTTOM@

/* Make Solaris happy... */
#define __EXTENSIONS__

/* Make Linux happy... */
#define _GNU_SOURCE

#ifdef HAVE_LIBNANA

extern int _sasl_debug;
#define L_DEFAULT_GUARD (_sasl_debug)

#include <stdio.h>
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

#endif /* CONFIG_H */
