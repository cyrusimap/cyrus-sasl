/* saslprep.h -- SASLprep (RFC 4013) for plugins
 *
 * See COPYING file for License */

#ifndef _SASLPREP_H_
#define _SASLPREP_H_

#include <stddef.h>
#include <saslplug.h>

/* How usernames and passwords are prepared (RFC 4013 SASLprep), chosen
 * by the "saslprep" option: "icu", "ascii" or "raw".  The default is
 * "icu" when built with ICU, and "raw" otherwise. */
#define SASLPREP_RAW   0	/* use the octets as given */
#define SASLPREP_ASCII 1	/* refuse non-ASCII and control characters */
#define SASLPREP_ICU   2	/* full SASLprep with ICU */

/*
 * Look up the "saslprep" option for plugin_name.  Returns SASL_OK and the
 * mode, or SASL_FAIL (logged) for an unknown value or "icu" without ICU.
 *
 * Defined in plugin_common.c, so plugins that only need the mode (PLAIN)
 * don't have to link saslprep.c, and with it ICU.
 */
int _plug_saslprep_mode(const sasl_utils_t *utils, const char *plugin_name,
			int *mode);

/*
 * Normalize(str) of RFC 5802 section 2.2: SASLprep (RFC 4013), refusing
 * non-US-ASCII, or the octets as given, depending on the "saslprep" option
 * (see _plug_saslprep_mode() above), looked up for plugin_name.
 *
 * On SASL_OK *out is a NUL-terminated copy of *outlen octets, which the
 * caller frees with utils->free().  Returns SASL_BADPROT if the string
 * isn't allowed (invalid UTF-8, prohibited or unassigned code points, bad
 * bidi, or an empty result), SASL_FAIL for a bad option, or SASL_NOMEM.
 *
 * Plugins that use this link libsaslprep, and ICU when built with it.
 */
int _plug_saslprep(const sasl_utils_t *utils, const char *plugin_name,
		   const char *in, size_t inlen, char **out, size_t *outlen);

#endif /* _SASLPREP_H_ */
