/* hmac-md5.h -- HMAC_MD5 functions
 */

#ifndef HMAC_MD5_H
#define HMAC_MD5_H 1

#ifdef HAVE_MD5
#include <openssl/md5.h>

#define HMAC_MD5_SIZE 16

/* intermediate MD5 context */
typedef struct HMAC_MD5_CTX_s {
    MD5_CTX ictx, octx;
} HMAC_MD5_CTX;

/* intermediate HMAC state
 *  values stored in network byte order (Big Endian)
 */
typedef struct HMAC_MD5_STATE_s {
    uint32_t istate[4];
    uint32_t ostate[4];
} HMAC_MD5_STATE;

#ifdef __cplusplus
extern "C" {
#endif

/* precalculate intermediate state from key
 */
void _sasl_hmac_md5_precalc(HMAC_MD5_STATE *hmac,
			    const unsigned char *key, int key_len);

/* initialize context from intermediate state
 */
void _sasl_hmac_md5_import(HMAC_MD5_CTX *hmac, HMAC_MD5_STATE *state);

int _sasl_hmac_md5_update(HMAC_MD5_CTX *hmac,
			  const void *data,
			  unsigned long len);

/* finish hmac from intermediate result.  Intermediate result is zeroed.
 */
void _sasl_hmac_md5_final(unsigned char digest[HMAC_MD5_SIZE],
			  HMAC_MD5_CTX *hmac);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_MD5 */
#endif /* HMAC_MD5_H */
