/* winconfig.h--SASL configuration for win32
 * Ryan Troll
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

#ifndef _WINCONFIG_H_
#define _WINCONFIG_H_

#include <windows.h>

/* Our package */
#define PACKAGE "cyrus-sasl"

/* Our version */
#define VERSION "v1.4b1"

/* Registry key that contains the locations of the plugins */
#define SASL_KEY "SOFTWARE\\Carnegie Mellon\\Project Cyrus\\SASL Library\\Available Plugins"

/* We only want minimal server functionality.  Cripple the server functionality when necessary to get
 * things to compile.
 *
 * Currently only cripples PLAIN.
 */
#define SASL_MINIMAL_SERVER 1

/* DB Type */
#undef SASL_DB_TYPE

/* ------------------------------------------------------------ */

/* Things that are fetched via autoconf under Unix
 */
#define HAVE_MEMCPY 1

#define SASL_PATH_ENV_VAR "SASL_PATH"
#define PLUGINDIR "\\sasl-plugins"

/* Windows calls these functions something else
 */
#define strcasecmp   stricmp
#define snprintf    _snprintf
#define strncasecmp  strnicmp

#define MAXHOSTNAMELEN 1024

/* ------------------------------------------------------------ */

#define WITHOUT_NANA
#define L_DEFAULT_GUARD (0)
#define I_DEFAULT_GUARD (0)
#define I(foo)
#define VL(foo)
// #define VL(foo)  printf foo;
#define VLP(foo,bar)

#define __attribute__(foo)

#endif /* _WINCONFIG_H_ */
