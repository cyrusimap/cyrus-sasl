/* saslutil.h -- various utility functions in SASL library
 */
/*234567890123456789012345678901234567890123456789012345678901234567890123456*/

#ifndef SASLUTIL_H
#define SASLUTIL_H 1

#include "sasl.h"

/* base64 decode
 *  in     -- input data
 *  inlen  -- length of input data
 *  out    -- output data (may be same as in, must have enough space)
 * result:
 *  outlen -- actual output length
 *
 * returns SASL_BADPROT on bad base64, SASL_OK on success
 */
int sasl_decode64(const char *in, int inlen, char *out, int *outlen);

/* base64 encode
 *  in      -- input data
 *  inlen   -- input data length
 *  out     -- output buffer (will be NUL terminated)
 *  outmax  -- max size of output buffer
 * result:
 *  outlen  -- gets actual length of output buffer (optional)
 * 
 * Returns SASL_OK on success, SASL_BUFOVER if result won't fit
 */
int sasl_encode64(const char *in, int inlen,
		  char *out, int outmax, int *outlen);

/* make a challenge string (NUL terminated)
 *  buf      -- buffer for result
 *  maxlen   -- max length of result
 *  hostflag -- 0 = don't include hostname, 1 = include hostname
 * returns final length or 0 if not enough space
 */
int sasl_mkchal(sasl_conn_t *conn, char *buf, int maxlen, int hostflag);

/* verify a string is valid UTF-8
 *  if len == 0, strlen(str) will be used.
 * returns SASL_BADPROT on error, SASL_OK on success
 */
int sasl_utf8verify(const char *str, int len);

/* create random pool seeded with OS-based params
 */
int sasl_randcreate(sasl_rand_t **rpool);

/* free random pool from randcreate
 */
void sasl_randfree(sasl_rand_t **rpool);

/* seed random number generator
 */
void sasl_randseed(sasl_rand_t *rpool, const char *seed, int len);

/* generate random octets
 */
void sasl_rand(sasl_rand_t *rpool, char *buf, int len);

/* churn data into random number generator
 */
void sasl_churn(sasl_rand_t *rpool, const char *data, int len);

#endif /* SASLUTIL_H */
