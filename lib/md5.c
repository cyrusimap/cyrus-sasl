/* md5.c - HMAC based on MD5 message-digest algorithm
 */
/*
 * Copyright (c) 1998-1999 Carnegie Mellon University.  All rights reserved.
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
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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

#include <config.h>
#include "hmac-md5.h"
#include <openssl/crypto.h>

#ifdef HAVE_MD5
#ifndef WIN32
# include <arpa/inet.h>
#endif

static void _sasl_hmac_md5_init(HMAC_MD5_CTX *hmac,
			 const unsigned char *key,
			 int key_len)
{
  unsigned char k_ipad[65];    /* inner padding -
				* key XORd with ipad
				*/
  unsigned char k_opad[65];    /* outer padding -
				* key XORd with opad
				*/
  unsigned char tk[16];
  int i;
  /* if key is longer than 64 bytes reset it to key=MD5(key) */
  if (key_len > 64) {
    
    MD5_CTX      tctx;

    MD5_Init(&tctx);
    MD5_Update(&tctx, key, key_len);
    MD5_Final(tk, &tctx);

    key = tk; 
    key_len = 16; 
  } 

  /*
   * the HMAC_MD5 transform looks like:
   *
   * MD5(K XOR opad, MD5(K XOR ipad, text))
   *
   * where K is an n byte key
   * ipad is the byte 0x36 repeated 64 times
   * opad is the byte 0x5c repeated 64 times
   * and text is the data being protected
   */

  /* start out by storing key in pads */
  OPENSSL_cleanse(k_ipad, sizeof(k_ipad));
  OPENSSL_cleanse(k_opad, sizeof(k_opad));
  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);

  /* XOR key with ipad and opad values */
  for (i=0; i<64; i++) {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  MD5_Init(&hmac->ictx);                   /* init inner context */
  MD5_Update(&hmac->ictx, k_ipad, 64);     /* apply inner pad */

  MD5_Init(&hmac->octx);                   /* init outer context */
  MD5_Update(&hmac->octx, k_opad, 64);     /* apply outer pad */

  /* scrub the pads and key context (if used) */
  OPENSSL_cleanse(&k_ipad, sizeof(k_ipad));
  OPENSSL_cleanse(&k_opad, sizeof(k_opad));
  OPENSSL_cleanse(&tk, sizeof(tk));

  /* and we're done. */
}

/* The precalc and import routines here rely on the fact that we pad
 * the key out to 64 bytes and use that to initialize the md5
 * contexts, and that updating an md5 context with 64 bytes of data
 * leaves nothing left over; all of the interesting state is contained
 * in the state field, and none of it is left over in the count and
 * buffer fields.  So all we have to do is save the state field; we
 * can zero the others when we reload it.  Which is why the decision
 * was made to pad the key out to 64 bytes in the first place. */
void _sasl_hmac_md5_precalc(HMAC_MD5_STATE *state,
			    const unsigned char *key,
			    int key_len)
{
  HMAC_MD5_CTX hmac;

  _sasl_hmac_md5_init(&hmac, key, key_len);

  state->istate[0] = htonl(hmac.ictx.A);
  state->istate[1] = htonl(hmac.ictx.B);
  state->istate[2] = htonl(hmac.ictx.C);
  state->istate[3] = htonl(hmac.ictx.D);

  state->ostate[0] = htonl(hmac.octx.A);
  state->ostate[1] = htonl(hmac.octx.B);
  state->ostate[2] = htonl(hmac.octx.C);
  state->ostate[3] = htonl(hmac.octx.D);

  OPENSSL_cleanse(&hmac, sizeof(hmac));
}


void _sasl_hmac_md5_import(HMAC_MD5_CTX *hmac,
		     HMAC_MD5_STATE *state)
{
  OPENSSL_cleanse(hmac, sizeof(HMAC_MD5_CTX));

  hmac->ictx.A = ntohl(state->istate[0]);
  hmac->ictx.B = ntohl(state->istate[1]);
  hmac->ictx.C = ntohl(state->istate[2]);
  hmac->ictx.D = ntohl(state->istate[3]);

  hmac->octx.A = ntohl(state->ostate[0]);
  hmac->octx.B = ntohl(state->ostate[1]);
  hmac->octx.C = ntohl(state->ostate[2]);
  hmac->octx.D = ntohl(state->ostate[3]);

  /* Init the counts to account for our having applied
   * 64 bytes of key; this works out to 0x200 (64 << 3; see
   * MD5Update above...) */
  hmac->ictx.Nl = hmac->octx.Nl = 0x200;
}

/* hmac_md5_update() is just a call to MD5Update on inner context.
   Returns 1 for success, 0 otherwise. */
int _sasl_hmac_md5_update(HMAC_MD5_CTX *hmac,
			  const void *data,
			  unsigned long len)
{
  return MD5_Update(&(hmac)->ictx, data, len);
}

void _sasl_hmac_md5_final(unsigned char digest[HMAC_MD5_SIZE],
			  HMAC_MD5_CTX *hmac)
{
  MD5_Final(digest, &hmac->ictx);  /* Finalize inner md5 */
  MD5_Update(&hmac->octx, digest, HMAC_MD5_SIZE); /* Update outer ctx */
  MD5_Final(digest, &hmac->octx); /* Finalize outer md5 */
}
#endif /* HAVE_MD5 */
