/* saslprep.c -- SASLprep (RFC 4013) for plugins
 *
 * See COPYING file for License */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"
#include "saslprep.h"

#ifdef HAVE_ICU
#include <limits.h>
#include <unicode/ustring.h>
#include <unicode/usprep.h>
#endif

/*
 * The "ascii" mode: RFC 5802 lets an implementation without SASLprep
 * refuse non-US-ASCII instead.  The ASCII characters SASLprep prohibits
 * are the controls (RFC 3454 C.2.1).  Returns SASL_OK or SASL_BADPROT.
 */
static int
saslprep_ascii(const char *in, size_t inlen)
{
    size_t i;

    for (i = 0; i < inlen; i++) {
	unsigned char c = (unsigned char) in[i];

	if (c < 0x20 || c >= 0x7f) {
	    return SASL_BADPROT;
	}
    }
    return SASL_OK;
}

#ifdef HAVE_ICU
static int
saslprep_icu (const sasl_utils_t *utils,
	      const char *in,
	      size_t inlen,
	      char **out,
	      size_t *outlen)
{
    UErrorCode err = U_ZERO_ERROR;
    UStringPrepProfile *profile = NULL;
    UChar *src = NULL, *dst = NULL;
    char *res = NULL;
    int32_t srclen = 0, dstlen = 0, reslen = 0;
    int result = SASL_BADPROT;

    if (inlen > INT32_MAX / 4) {
	return SASL_BADPROT;
    }

    /* UTF-8 to UTF-16; invalid UTF-8 is refused */
    u_strFromUTF8(NULL, 0, &srclen, in, (int32_t) inlen, &err);
    if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) goto cleanup;
    err = U_ZERO_ERROR;
    src = utils->malloc((srclen + 1) * sizeof(UChar));
    if (src == NULL) { result = SASL_NOMEM; goto cleanup; }
    u_strFromUTF8(src, srclen + 1, NULL, in, (int32_t) inlen, &err);
    if (U_FAILURE(err)) goto cleanup;

    profile = usprep_openByType(USPREP_RFC4013_SASLPREP, &err);
    if (U_FAILURE(err)) {
	utils->log(utils->conn, SASL_LOG_ERR,
		   "saslprep: can't open the ICU SASLprep profile: %s",
		   u_errorName(err));
	result = SASL_FAIL;
	goto cleanup;
    }

    /* RFC 5802 treats both strings as "stored strings": unassigned code
       points are prohibited (USPREP_DEFAULT) */
    dstlen = usprep_prepare(profile, src, srclen, NULL, 0, USPREP_DEFAULT,
			    NULL, &err);
    if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) goto cleanup;
    err = U_ZERO_ERROR;
    dst = utils->malloc((dstlen + 1) * sizeof(UChar));
    if (dst == NULL) { result = SASL_NOMEM; goto cleanup; }
    usprep_prepare(profile, src, srclen, dst, dstlen + 1, USPREP_DEFAULT,
		   NULL, &err);
    if (U_FAILURE(err)) goto cleanup;

    /* back to UTF-8 */
    u_strToUTF8(NULL, 0, &reslen, dst, dstlen, &err);
    if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) goto cleanup;
    err = U_ZERO_ERROR;
    res = utils->malloc(reslen + 1);
    if (res == NULL) { result = SASL_NOMEM; goto cleanup; }
    u_strToUTF8(res, reslen + 1, NULL, dst, dstlen, &err);
    if (U_FAILURE(err)) goto cleanup;

    *out = res;
    *outlen = reslen;
    res = NULL;
    result = SASL_OK;

  cleanup:
    if (profile) usprep_close(profile);
    if (src) utils->free(src);
    if (dst) utils->free(dst);
    if (res) utils->free(res);
    return result;
}
#endif /* HAVE_ICU */

int
_plug_saslprep (const sasl_utils_t *utils,
		const char *plugin_name,
		const char *in,
		size_t inlen,
		char **out,
		size_t *outlen)
{
    int mode, result;

    *out = NULL;
    *outlen = 0;

    result = _plug_saslprep_mode(utils, plugin_name, &mode);
    if (result != SASL_OK) {
	return result;
    }

    switch (mode) {
#ifdef HAVE_ICU
    case SASLPREP_ICU:
	result = saslprep_icu(utils, in, inlen, out, outlen);
	if (result == SASL_OK && *outlen == 0 && inlen != 0) {
	    /* e.g. only characters that SASLprep maps to nothing */
	    utils->free(*out);
	    *out = NULL;
	    result = SASL_BADPROT;
	}
	return result;
#endif
    case SASLPREP_ASCII:
	if (saslprep_ascii(in, inlen) != SASL_OK) {
	    return SASL_BADPROT;
	}
	break;
    default:
	break;
    }

    /* "ascii" and "raw": the octets as given */
    *out = utils->malloc(inlen + 1);
    if (*out == NULL) {
	return SASL_NOMEM;
    }
    memcpy(*out, in, inlen);
    (*out)[inlen] = '\0';
    *outlen = inlen;
    return SASL_OK;
}

