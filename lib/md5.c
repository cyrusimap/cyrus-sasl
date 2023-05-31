/* MD5C.C - HMAC based on MD5 message-digest algorithm
 */

/* The following RSA-MD license grant stems from RSA's MD5 implementation
that is contained in RFC 1321. All of that code is gone and the only 3rd
party code that is contained in this module is the HMAC MD5 implementation
by Pau-Chen Cheng and Jeff Kraemer that is contained in RFC 2104's Appendix.
Rob Earhart made changes to the code that are possibly copyrightable.

The module should be relicensed, taking into account a possible RFC 2104
license (no restrictions mentioned in the document), and Rob Earhart's consent.
Eliminating this would be a huge benefit for combining cyrus-sasl with GPL
licensed software.
*/

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
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


void _sasl_hmac_md5(text, text_len, key, key_len, digest)
const unsigned char* text; /* pointer to data stream */
int text_len; /* length of data stream */
const unsigned char* key; /* pointer to authentication key */
int key_len; /* length of authentication key */
unsigned char *digest; /* caller digest to be filled in */
{
  MD5_CTX context; 

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
  /*
   * perform inner MD5
   */

  MD5_Init(&context);                   /* init context for 1st
					       * pass */
  MD5_Update(&context, k_ipad, 64);      /* start with inner pad */
  MD5_Update(&context, text, text_len); /* then text of datagram */
  MD5_Final(digest, &context);          /* finish up 1st pass */

  /*
   * perform outer MD5
   */
  MD5_Init(&context);                   /* init context for 2nd
					* pass */
  MD5_Update(&context, k_opad, 64);     /* start with outer pad */
  MD5_Update(&context, digest, 16);     /* then results of 1st
					* hash */
  MD5_Final(digest, &context);          /* finish up 2nd pass */

}
#endif /* HAVE_MD5 */
