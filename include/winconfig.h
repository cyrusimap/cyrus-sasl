#ifndef _WINCONFIG_H_
#define _WINCONFIG_H_

#include <windows.h>

/* Our package */
#define PACKAGE "cyrus-sasl"

/* Our version */
#define VERSION "v1.1b"

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

/* Windows calls this function something else
 */
#define strcasecmp stricmp

#define MAXHOSTNAMELEN 1024

/* ------------------------------------------------------------ */

#define WITHOUT_NANA
#define L_DEFAULT_GUARD (0)
#define I_DEFAULT_GUARD (0)
#define I(foo)
#define VL(foo)
#define VLP(foo,bar)

#define __attribute__(foo)

#endif /* _WINCONFIG_H_ */
