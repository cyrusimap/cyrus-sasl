/*
 * Digest MD5 SASL plugin Tim Martin, Alexey Melnikov
 */

/* 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

/* DES currently disabled until we figure out what's wrong */
#undef WITH_DES

/* DES support */
#ifdef WITH_DES
# ifdef WITH_SSL_DES
#  include <openssl/des.h>
# else /* system DES library */
#  include <des.h>
# endif
#endif /* WITH_DES */

#ifdef WIN32
# include <winsock.h>
#else /* Unix */
# include <netinet/in.h>
#endif /* WIN32 */

#include <sasl.h>
#include <saslplug.h>

/* Definitions */

#define NONCE_SIZE (32)		/* arbitrary */
#define DIGEST_NOLAYER    (1)
#define DIGEST_INTEGRITY  (2)
#define DIGEST_PRIVACY    (4)

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
#include "saslDIGESTMD5.h"
#else /* Unix */
extern int      strcasecmp(const char *s1, const char *s2);
#endif /* end WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL "
VERSION " $";

/* external definitions */

#ifdef sun
/* gotta define gethostname ourselves on suns */
extern int      gethostname(char *, int);
#endif

#define bool int

#ifndef TRUE
#define TRUE  (1)
#define FALSE (0)
#endif

#include <assert.h>

/* defines */
#define HASHLEN 16
typedef unsigned char HASH[HASHLEN + 1];
#define HASHHEXLEN 32
typedef unsigned char HASHHEX[HASHHEXLEN + 1];

#define MAC_SIZE 10
#define MAC_OFFS 2

const char *SEALING_CLIENT_SERVER="Digest H(A1) to client-to-server sealing key magic constant";
const char *SEALING_SERVER_CLIENT="Digest H(A1) to server-to-client sealing key magic constant";

const char *SIGNING_CLIENT_SERVER="Digest session key to client-to-server signing key magic constant";
const char *SIGNING_SERVER_CLIENT="Digest session key to server-to-client signing key magic constant";

#define SERVER 0
#define CLIENT 1

#define HT	(9)
#define CR	(13)
#define LF	(10)
#define SP	(32)
#define DEL	(127)

#define SETERRSTR(s) { if (errstr) *errstr = s; }

/* function definitions for cipher encode/decode */
typedef int cipher_function_t(void *,
			      const char *,
			      unsigned,
			      unsigned char[],
			      char *,
			      unsigned *);

typedef int cipher_init_t(void *, sasl_utils_t *,
			  char [16], char [16]);

/* global: if we've already set a pass entry */
static int mydb_initialized = 0;

#ifdef WITH_RC4
typedef struct rc4_context_s rc4_context_t;
#endif

/* context that stores info */
typedef struct context {
  int state;			/* state in the authentication we are in */
  int i_am;			/* are we the client or server? */

  sasl_ssf_t limitssf, requiressf; /* application defined bounds, for the
				      server */
  unsigned char  *nonce;
  int             noncelen;

  unsigned int    last_ncvalue;

  char           *response_value;

  char           *realm;

  unsigned int    seqnum;
  unsigned int    rec_seqnum;	/* for checking integrity */

  HASH            Ki_send;
  HASH            Ki_receive;

  HASH            HA1;		/* Kcc or Kcs */

  /* function pointers */
  void            (*hmac_md5) (const unsigned char *text, int text_len,
			       const unsigned char *key, int key_len,
			       unsigned char[16]);
  sasl_malloc_t  *malloc;
  sasl_free_t    *free;

  /* for decoding */
  char           *buffer;
  char            sizebuf[4];
  int             cursize;
  int             size;
  int             needsize;

  /* Server MaxBuf for Client or Client MaxBuf For Server */
  unsigned int    maxbuf;

  unsigned char  *authid; /* authentication id */
  unsigned char  *userid; /* authorization_id */
  sasl_secret_t  *password;

  /* if privacy mode is used use these functions for encode and decode */
  cipher_function_t *cipher_enc;
  cipher_function_t *cipher_dec;
  cipher_init_t *cipher_init;

#ifdef WITH_DES
  des_key_schedule keysched_enc;   /* key schedule for des initialization */
  des_cblock ivec_enc;		   /* initial vector for encoding */
  des_key_schedule keysched_dec;   /* key schedule for des initialization */
  des_cblock ivec_dec;		   /* init vec for decoding */

  des_key_schedule keysched_enc2;   /* key schedule for 3des initialization */
  des_key_schedule keysched_dec2;   /* key schedule for 3des initialization */
#endif

#ifdef WITH_RC4
  rc4_context_t *rc4_enc_context;
  rc4_context_t *rc4_dec_context;
#endif /* WITH_RC4 */
} context_t;

struct digest_cipher {
    char *name;
    sasl_ssf_t ssf;
    int n; /* bits to make privacy key */
    int flag; /* a bitmask to make things easier for us */
    
    cipher_function_t *cipher_enc;
    cipher_function_t *cipher_dec;
    cipher_init_t *cipher_init;
};

/* this is from the rpc world */
#define IN
#define OUT


static int      htoi(unsigned char *hexin, int *res);

#define DIGEST_MD5_VERSION (3)
#define KEYS_FILE NULL

static unsigned char *COLON = (unsigned char *) ":";

void
CvtHex(
       IN HASH Bin,
       OUT HASHHEX Hex
)
{
  unsigned short  i;
  unsigned char   j;

  for (i = 0; i < HASHLEN; i++) {
    j = (Bin[i] >> 4) & 0xf;
    if (j <= 9)
      Hex[i * 2] = (j + '0');
    else
      Hex[i * 2] = (j + 'a' - 10);
    j = Bin[i] & 0xf;
    if (j <= 9)
      Hex[i * 2 + 1] = (j + '0');
    else
      Hex[i * 2 + 1] = (j + 'a' - 10);
  }
  Hex[HASHHEXLEN] = '\0';
}

bool
UTF8_In_8859_1(const unsigned char *base,
	       int len)
{
  const unsigned char *scan, *end;

  end = base + len;
  for (scan = base; scan < end; ++scan) {
    if (*scan > 0xC3)
      break;			/* abort if outside 8859-1 */
    if (*scan >= 0xC0 && *scan <= 0xC3) {
      if (++scan == end || *scan < 0x80 || *scan > 0xBF)
	break;
    }
  }

  /* if scan >= end, then this is a 8859-1 string. */
  return (scan >= end);
}

/*
 * if the string is entirely in the 8859-1 subset of UTF-8, then translate to
 * 8859-1 prior to MD5
 */
void
MD5_UTF8_8859_1(IN sasl_utils_t * utils,
		MD5_CTX * ctx,
		bool In_ISO_8859_1,
		const unsigned char *base,
		int len)
{
  const unsigned char *scan, *end;
  unsigned char   cbuf;

  end = base + len;

  /* if we found a character outside 8859-1, don't alter string */
  if (!In_ISO_8859_1) {
    utils->MD5Update(ctx, base, len);
    return;
  }
  /* convert to 8859-1 prior to applying hash */
  do {
    for (scan = base; scan < end && *scan < 0xC0; ++scan);
    if (scan != base)
      utils->MD5Update(ctx, base, scan - base);
    if (scan + 1 >= end)
      break;
    cbuf = ((scan[0] & 0x3) << 6) | (scan[1] & 0x3f);
    utils->MD5Update(ctx, &cbuf, 1);
    base = scan + 2;
  }
  while (base < end);
}




static void
DigestCalcSecret(IN sasl_utils_t * utils,
		 IN unsigned char *pszUserName,
		 IN unsigned char *pszRealm,
		 IN unsigned char *Password,
		 IN int PasswordLen,
		 OUT HASH HA1)
{
  bool            In_8859_1;

  MD5_CTX         Md5Ctx;

  /* Chris Newman clarified that the following text in DIGEST-MD5 spec
     is bogus: "if name and password are both in ISO 8859-1 charset"
     We shoud use code example instead */

  utils->MD5Init(&Md5Ctx);

  /* We have to convert UTF-8 to ISO-8859-1 if possible */
  In_8859_1 = UTF8_In_8859_1(pszUserName, strlen((char *) pszUserName));
  MD5_UTF8_8859_1(utils, &Md5Ctx, In_8859_1,
		  pszUserName, strlen((char *) pszUserName));

  utils->MD5Update(&Md5Ctx, COLON, 1);
  
  if (pszRealm != NULL && pszRealm[0] != '\0') {
      /* a NULL realm is equivalent to the empty string */
      utils->MD5Update(&Md5Ctx, pszRealm, strlen((char *) pszRealm));
  }      

  utils->MD5Update(&Md5Ctx, COLON, 1);

  /* We have to convert UTF-8 to ISO-8859-1 if possible */
  In_8859_1 = UTF8_In_8859_1(Password, PasswordLen);
  MD5_UTF8_8859_1(utils, &Md5Ctx, In_8859_1,
		  Password, PasswordLen);

  utils->MD5Final(HA1, &Md5Ctx);
}


/* calculate H(A1) as per spec */
void
DigestCalcHA1(IN context_t * text,
	      IN sasl_utils_t * utils,
	      IN unsigned char *pszUserName,
	      IN unsigned char *pszRealm,
	      IN sasl_secret_t * pszPassword,
	      IN unsigned char *pszAuthorization_id,
	      IN unsigned char *pszNonce,
	      IN unsigned char *pszCNonce,
	      OUT HASHHEX SessionKey)
{
  MD5_CTX         Md5Ctx;
  HASH            HA1;

  DigestCalcSecret(utils,
		   pszUserName,
		   pszRealm,
		   (unsigned char *) pszPassword->data,
		   pszPassword->len,
		   HA1);

  /*  VL(("HA1 is \"%s\"\r\n", HA1));*/

  /* calculate the session key */
  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, HA1, HASHLEN);
  utils->MD5Update(&Md5Ctx, COLON, 1);
  utils->MD5Update(&Md5Ctx, pszNonce, strlen((char *) pszNonce));
  utils->MD5Update(&Md5Ctx, COLON, 1);
  utils->MD5Update(&Md5Ctx, pszCNonce, strlen((char *) pszCNonce));
  if (pszAuthorization_id != NULL) {
      utils->MD5Update(&Md5Ctx, COLON, 1);
      utils->MD5Update(&Md5Ctx, pszAuthorization_id, 
		       strlen((char *) pszAuthorization_id));
  }
  utils->MD5Final(HA1, &Md5Ctx);

  CvtHex(HA1, SessionKey);

  /* xxx rc-* use different n */
  
  /* save HA1 because we'll need it for the privacy and integrity keys */
  memcpy(text->HA1, HA1, sizeof(HASH));

}



/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */

void
DigestCalcResponse(IN sasl_utils_t * utils,
		   IN HASHHEX HA1,	/* H(A1) */
		   IN unsigned char *pszNonce,	/* nonce from server */
		   IN unsigned char *pszNonceCount,	/* 8 hex digits */
		   IN unsigned char *pszCNonce,	/* client nonce */
		   IN unsigned char *pszQop,	/* qop-value: "", "auth",
						 * "auth-int" */
		   IN unsigned char *pszDigestUri,	/* requested URL */
		   IN unsigned char *pszMethod,
		   IN HASHHEX HEntity,	/* H(entity body) if qop="auth-int" */
		   OUT HASHHEX Response	/* request-digest or response-digest */
)
{
  MD5_CTX         Md5Ctx;
  HASH            HA2;
  HASH            RespHash;
  HASHHEX         HA2Hex;

  /* calculate H(A2) */
  utils->MD5Init(&Md5Ctx);

  if (pszMethod != NULL) {
    utils->MD5Update(&Md5Ctx, pszMethod, strlen((char *) pszMethod));
  }
  utils->MD5Update(&Md5Ctx, (unsigned char *) COLON, 1);

  /* utils->MD5Update(&Md5Ctx, (unsigned char *) "AUTHENTICATE:", 13); */
  utils->MD5Update(&Md5Ctx, pszDigestUri, strlen((char *) pszDigestUri));
  if (strcasecmp((char *) pszQop, "auth") != 0) {
      /* append ":00000000000000000000000000000000" */
      utils->MD5Update(&Md5Ctx, COLON, 1);
      utils->MD5Update(&Md5Ctx, HEntity, HASHHEXLEN);
  }
  utils->MD5Final(HA2, &Md5Ctx);
  CvtHex(HA2, HA2Hex);

  /* calculate response */
  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, HA1, HASHHEXLEN);
  utils->MD5Update(&Md5Ctx, COLON, 1);
  utils->MD5Update(&Md5Ctx, pszNonce, strlen((char *) pszNonce));
  utils->MD5Update(&Md5Ctx, COLON, 1);
  if (*pszQop) {
    utils->MD5Update(&Md5Ctx, pszNonceCount, strlen((char *) pszNonceCount));
    utils->MD5Update(&Md5Ctx, COLON, 1);
    utils->MD5Update(&Md5Ctx, pszCNonce, strlen((char *) pszCNonce));
    utils->MD5Update(&Md5Ctx, COLON, 1);
    utils->MD5Update(&Md5Ctx, pszQop, strlen((char *) pszQop));
    utils->MD5Update(&Md5Ctx, COLON, 1);
  }
  utils->MD5Update(&Md5Ctx, HA2Hex, HASHHEXLEN);
  utils->MD5Final(RespHash, &Md5Ctx);
  CvtHex(RespHash, Response);
}


static char    *
calculate_response(context_t * text,
		   sasl_utils_t * utils,
		   IN unsigned char *username,
		   IN unsigned char *realm,
		   IN unsigned char *nonce,
		   IN unsigned char *ncvalue,
		   IN unsigned char *cnonce,
		   IN char *qop,
		   IN unsigned char *digesturi,
		   IN sasl_secret_t * passwd,
		   IN unsigned char *authorization_id,
		   OUT char **response_value)
{
  HASHHEX         SessionKey;
  HASHHEX         HEntity = "00000000000000000000000000000000";
  HASHHEX         Response;
  char           *result;

  /* Verifing that all parameters was defined */
  assert(username != NULL);
  
  if (realm == NULL) {
      /* a NULL realm is equivalent to the empty string */
      realm = (unsigned char *) "";
  }

  if (nonce == NULL) return NULL;
  
  assert(cnonce != NULL);

  assert(ncvalue != NULL);
  assert(digesturi != NULL);

  assert(passwd != NULL);

  if (qop == NULL) {
      /* default to a qop of just authentication */
      qop = "auth";
  }

  VL(("calculate_response assert passed\n"));

  DigestCalcHA1(text,
		utils,
		username,
		realm,
		passwd,
		authorization_id,
		nonce,
		cnonce,
		SessionKey);

  VL(("Session Key is \"%s\"\r\n", SessionKey));

  DigestCalcResponse(utils,
		     SessionKey,/* H(A1) */
		     nonce,	/* nonce from server */
		     ncvalue,	/* 8 hex digits */
		     cnonce,	/* client nonce */
		     (unsigned char *) qop,	/* qop-value: "", "auth",
						 * "auth-int" */
		     digesturi,	/* requested URL */
		     (unsigned char *) "AUTHENTICATE",
		     HEntity,	/* H(entity body) if qop="auth-int" */
		     Response	/* request-digest or response-digest */
    );

  result = utils->malloc(HASHHEXLEN + 1);
  memcpy(result, Response, HASHHEXLEN);
  result[HASHHEXLEN] = 0;

  VL(("Calculated response\n"));


  if (response_value != NULL) {
    DigestCalcResponse(utils,
		       SessionKey,	/* H(A1) */
		       nonce,	/* nonce from server */
		       ncvalue,	/* 8 hex digits */
		       cnonce,	/* client nonce */
		       (unsigned char *) qop,	/* qop-value: "", "auth",
						 * "auth-int" */
		       (unsigned char *) digesturi,	/* requested URL */
		       NULL,
		       HEntity,	/* H(entity body) if qop="auth-int" */
		       Response	/* request-digest or response-digest */
      );

    *response_value = utils->malloc(HASHHEXLEN + 1);
    if (*response_value == NULL)
      return NULL;

    memcpy(*response_value, Response, HASHHEXLEN);
    (*response_value)[HASHHEXLEN] = 0;

  }
  VL(("Calculated response leaving\n"));


  return result;
}

void
DigestCalcHA1FromSecret(IN context_t * text,
			IN sasl_utils_t * utils,
			IN HASH HA1,
			IN unsigned char *authorization_id,
			IN unsigned char *pszNonce,
			IN unsigned char *pszCNonce,
			OUT HASHHEX SessionKey)
{
  MD5_CTX         Md5Ctx;

  VL(("HA1 is \"%s\"\r\n", SessionKey));

  /* calculate session key */
  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, HA1, HASHLEN);
  utils->MD5Update(&Md5Ctx, COLON, 1);
  utils->MD5Update(&Md5Ctx, pszNonce, strlen((char *) pszNonce));
  utils->MD5Update(&Md5Ctx, COLON, 1);
  utils->MD5Update(&Md5Ctx, pszCNonce, strlen((char *) pszCNonce));
  if (authorization_id != NULL) {
    utils->MD5Update(&Md5Ctx, COLON, 1);
    utils->MD5Update(&Md5Ctx, authorization_id, strlen((char *) authorization_id));
  }
  utils->MD5Final(HA1, &Md5Ctx);

  CvtHex(HA1, SessionKey);


  /* save HA1 because we need it to make the privacy and integrity keys */
  memcpy(text->HA1, HA1, sizeof(HASH));
}

static char    *
create_response(context_t * text,
		sasl_utils_t * utils,
		unsigned char *nonce,
		unsigned char *ncvalue,
		unsigned char *cnonce,
		char *qop,
		char *digesturi,
		HASH Secret,
		char *authorization_id,
		OUT char **response_value)
{
  HASHHEX         SessionKey;
  HASHHEX         HEntity = "00000000000000000000000000000000";
  HASHHEX         Response;
  char           *result;

  if (qop == NULL)
    qop = "auth";

  DigestCalcHA1FromSecret(text,
			  utils,
			  Secret,
			  (unsigned char *) authorization_id,
			  nonce,
			  cnonce,
			  SessionKey);


  VL(("Session Key is \"%s\"\r\n", SessionKey));


  DigestCalcResponse(utils,
		     SessionKey,/* H(A1) */
		     nonce,	/* nonce from server */
		     ncvalue,	/* 8 hex digits */
		     cnonce,	/* client nonce */
		     (unsigned char *) qop,	/* qop-value: "", "auth",
						 * "auth-int" */
		     (unsigned char *) digesturi,	/* requested URL */
		     (unsigned char *) "AUTHENTICATE",
		     HEntity,	/* H(entity body) if qop="auth-int" */
		     Response	/* request-digest or response-digest */
    );

  result = utils->malloc(HASHHEXLEN + 1);
  memcpy(result, Response, HASHHEXLEN);
  result[HASHHEXLEN] = 0;

  /* response_value (used for reauth i think */
  if (response_value != NULL) {
    DigestCalcResponse(utils,
		       SessionKey,	/* H(A1) */
		       nonce,	/* nonce from server */
		       ncvalue,	/* 8 hex digits */
		       cnonce,	/* client nonce */
		       (unsigned char *) qop,	/* qop-value: "", "auth",
						 * "auth-int" */
		       (unsigned char *) digesturi,	/* requested URL */
		       NULL,
		       HEntity,	/* H(entity body) if qop="auth-int" */
		       Response	/* request-digest or response-digest */
      );

    *response_value = utils->malloc(HASHHEXLEN + 1);
    if (*response_value == NULL)
      return NULL;
    memcpy(*response_value, Response, HASHHEXLEN);
    (*response_value)[HASHHEXLEN] = 0;
  }
  return result;
}

static char     basis_64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????";

static int
encode64(const char *_in, unsigned inlen,
	 char *_out, unsigned outmax, unsigned *outlen)
{
  const unsigned char *in = (const unsigned char *) _in;
  unsigned char  *out = (unsigned char *) _out;
  unsigned char   oval;
  char           *blah;
  unsigned        olen;

  /* Will it fit? */
  olen = (inlen + 2) / 3 * 4;
  if (outlen)
    *outlen = olen;
  if (outmax < olen)
    return SASL_BUFOVER;

  /* Do the work... */
  blah = (char *) out;
  while (inlen >= 3) {
    /*
     * user provided max buffer size; make sure we don't go over it
     */
    *out++ = basis_64[in[0] >> 2];
    *out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
    *out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
    *out++ = basis_64[in[2] & 0x3f];
    in += 3;
    inlen -= 3;
  }
  if (inlen > 0) {
    /*
     * user provided max buffer size; make sure we don't go over it
     */
    *out++ = basis_64[in[0] >> 2];
    oval = (in[0] << 4) & 0x30;
    if (inlen > 1)
      oval |= in[1] >> 4;
    *out++ = basis_64[oval];
    *out++ = (inlen < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
    *out++ = '=';
  }
  *out = '\0';

  return SASL_OK;
}

static unsigned char *
create_nonce(sasl_utils_t * utils)
{
  unsigned char  *base64buf;
  int             base64len;

  char           *ret = (char *) utils->malloc(NONCE_SIZE);
  if (ret == NULL)
    return NULL;

  utils->rand(utils->rpool, (char *) ret, NONCE_SIZE);

  /* base 64 encode it so it has valid chars */
  base64len = (NONCE_SIZE * 4 / 3) + (NONCE_SIZE % 3 ? 4 : 0);

  base64buf = (unsigned char *) utils->malloc(base64len + 1);
  if (base64buf == NULL) {
    VL(("ERROR: Unable to allocate final buffer\n"));
    return (NULL);
  }
  /*
   * Returns SASL_OK on success, SASL_BUFOVER if result won't fit
   */
  if (encode64(ret, NONCE_SIZE,
	       (char *) base64buf, base64len, NULL) != SASL_OK) {
    utils->free(ret);
    return NULL;
  }
  utils->free(ret);

  return base64buf;
}

static int
add_to_challenge(sasl_utils_t * utils,
		 char **str,
		 char *name,
		 unsigned char *value,
		 bool need_quotes)
{
  int             namesize = strlen(name);
  int             valuesize = strlen((char *) value);

  if (*str == NULL) {
    *str = utils->malloc(namesize + 2 + valuesize + 2);
    if (*str == NULL)
      return SASL_FAIL;
    *str[0] = 0;
  } else {
    int             curlen = strlen(*str);
    *str = utils->realloc(*str, curlen + 1 + namesize + 2 + valuesize + 2);
    if (*str == NULL)
      return SASL_FAIL;
    strcat(*str, ",");
  }

  strcat(*str, name);

  if (need_quotes) {
    strcat(*str, "=\"");
    strcat(*str, (char *) value);	/* XXX. What about quoting??? */
    strcat(*str, "\"");
  } else {
    strcat(*str, "=");
    strcat(*str, (char *) value);
  }

  return SASL_OK;
}


char           *
strend(char *s)
{
  if (s == NULL)
    return NULL;

  return (s + strlen(s));
}

char *skip_lws (char *s)
{
  assert (s != NULL);

  /* skipping spaces: */
  while (s[0] == ' ' || s[0] == HT || s[0] == CR || s[0] == LF) {
    if (s[0]=='\0') break;
    s++;
  }  
    
  return s;
}

char *skip_token (char *s, int caseinsensitive)
{
  assert (s != NULL);
  
  while (s[0]>SP) {
    if (s[0]==DEL || s[0]=='(' || s[0]== ')' || s[0]== '<' || s[0]== '>' ||
        s[0]=='@' || s[0]== ',' || s[0]== ';' || s[0]== ':' || s[0]== '\\' ||
        s[0]=='\'' || s[0]== '/' || s[0]== '[' || s[0]== ']' || s[0]== '?' ||
        s[0]=='=' || s[0]== '{' || s[0]== '}') {
      if (caseinsensitive == 1) {
	if (!isupper((unsigned char) s[0]))
	  break;
      } else {
	break;
      }
    }
    s++;
  }  
  return s;
}

/* NULL - error (unbalanced quotes), otherwise pointer to the first character after value */
char * unquote (char *qstr)
{
  char *endvalue;
  int   escaped = 0;
  char *outptr;
  
  assert (qstr != NULL);
  
  if (qstr[0] == '"') {
    qstr++;
    outptr = qstr;
    
    for (endvalue = qstr; endvalue[0] != '\0'; endvalue++, outptr++) {
      if (escaped) {
        outptr[0] = endvalue[0];
        escaped = 0;
      }
      else if (endvalue[0] == '\\') {
        escaped = 1;
        outptr--; /* Will be incremented at the end of the loop */
      }
      else if (endvalue[0] == '"') {
        break;
      }      
      else {
        outptr[0] = endvalue[0];      
      }
    }
    
    if (endvalue[0] != '"') {
      return NULL;
    }
    
    while (outptr <= endvalue) {
      outptr[0] = '\0';
      outptr++;
    }
    endvalue++;
  }
  else { /* not qouted value (token) */
    endvalue = skip_token(qstr,0);
  };
  
  return endvalue;  
} 

void get_pair(char **in, char **name, char **value)
{
  char  *endpair;
  /* int    inQuotes; */
  char  *curp = *in;
  *name = NULL;
  *value = NULL;

  if (curp == NULL) return;
  if (curp[0] == '\0') return;

  /* skipping spaces: */
  curp = skip_lws(curp);
  
  *name = curp;
  
  curp = skip_token(curp,1);

  /* strip wierd chars */
  if (curp[0] != '=' && curp[0] != '\0') {
    *curp++ = '\0';
  };

  curp = skip_lws(curp);
  
  if (curp[0] != '=') { /* No '=' sign */ 
    *name = NULL;
    return;
  }
  
  curp[0] = '\0';
  curp++;
  
  curp = skip_lws(curp);  
  
  *value = (curp[0] == '"') ? curp+1 : curp;

  endpair = unquote (curp);
  if (endpair == NULL) { /* Unbalanced quotes */ 
    *name = NULL;
    return;
  }
  if (endpair[0] != ',') {
      if (endpair[0]!='\0') {
	  *endpair++ = '\0'; 
      }
  }
    
  endpair = skip_lws(endpair);

  /* syntax check: MUST be '\0' or ',' */  
  if (endpair[0] == ',') {
      endpair[0] = '\0';
      endpair++; /* skipping <,> */
  } else if (endpair[0] != '\0') { 
    *name = NULL;
    return;
  }

  *in = endpair;
}


/* copy a string */
static int
digest_strdup(sasl_utils_t * utils, const char *in, char **out, int *outlen)
{
    if (in) {
	size_t len = strlen(in);
	if (outlen) {
	    *outlen = len;
	}
	*out = utils->malloc(len + 1);
	if (!*out) {
	    return SASL_NOMEM;
	}
	strcpy((char *) *out, in);
	return SASL_OK;
    } else {
	*out = NULL;
	if (outlen) { *outlen = 0; }
	return SASL_OK;
    }
}

#ifdef WITH_DES
/******************************
 *
 * 3DES functions
 *
 *****************************/


static int dec_3des(void *v,
		   const char *input,
		   unsigned inputlen,
		   unsigned char digest[16],
		   char *output,
		   unsigned *outputlen)
{
    context_t *text = (context_t *) v;

    des_ede2_cbc_encrypt((des_cblock *) input,
			 (des_cblock *) output,
			 inputlen,
			 text->keysched_dec,
			 text->keysched_dec2,
			 &text->ivec_enc,
			 DES_DECRYPT);

#if 0
    unsigned int lup;

    for (lup=0;lup<inputlen;lup+=8)
    {
	/* decrypt with 1st key */
	des_ecb_encrypt((des_cblock *) (input+lup),
			(des_cblock *) ((output)+lup),
			text->keysched_dec,
			DES_DECRYPT);

	/* encrypt with 2nd key */
	des_ecb_encrypt((des_cblock *) ((output)+lup),
			(des_cblock *) ((output)+lup),
			text->keysched_dec2,
			DES_ENCRYPT);
	
	/* decrypt with 1st key */
	des_ecb_encrypt((des_cblock *) ((output)+lup),
			(des_cblock *) ((output)+lup),
			text->keysched_dec,
			DES_DECRYPT);
	
    }
#endif
    
    /* now chop off the padding */
    *outputlen=inputlen - (output)[inputlen-11]-10;
    
    /* copy in the HMAC to digest */
    memcpy(digest, (output)+inputlen-10, 10);
  
    return SASL_OK;
}

int enc_3des(void *v,
	     const char *input,
	     unsigned inputlen,
	     unsigned char digest[16],
	     char *output,
	     unsigned *outputlen)
{
    context_t *text = (context_t *) v;
    int len;
    int paddinglen;
    
    /* determine padding length */
    paddinglen= 8 - ((inputlen+10)%8);
    
    /* now construct the full stuff to be ciphered */
    memcpy(output, input, inputlen);                /* text */
    memset(output+inputlen, paddinglen, paddinglen);/* pad  */
    memcpy(output+inputlen+paddinglen, digest, 10); /* hmac */
    
    len=inputlen+paddinglen+10;
    
    des_ede2_cbc_encrypt((des_cblock *) output,
			 (des_cblock *) output,
			 len,
			 text->keysched_enc,
			 text->keysched_enc2,
			 &text->ivec_enc,
			 DES_ENCRYPT);
    
#if 0
    int lup;

  for (lup=0;lup<len;lup+=8)
  {
      /* encrpyt with 1st key */
      des_ecb_encrypt((des_cblock *)(output+lup),
		      (des_cblock *)(output+lup),
		      text->keysched_enc,
		      DES_ENCRYPT);    
    /* decrpyt with 2nd key */
    des_ecb_encrypt((des_cblock *) ((output)+lup),
		    (des_cblock *) ((output)+lup),
		    text->keysched_enc2,
		    DES_DECRYPT);
    /* encrpyt with 1st key */
    des_ecb_encrypt((des_cblock *) ((output)+lup),
		    (des_cblock *) ((output)+lup),
		    text->keysched_enc,
		    DES_ENCRYPT);

  }
#endif

  *outputlen=len;

  return SASL_OK;
}

static int init_3des(void *v, 
		     sasl_utils_t *utils __attribute__((unused)), 
		     char enckey[16],
		     char deckey[16])



{
    context_t *text = (context_t *) v;

    des_key_sched((des_cblock *) enckey, text->keysched_enc);
    des_key_sched((des_cblock *) deckey, text->keysched_dec);
    
    des_key_sched((des_cblock *) (enckey+7), text->keysched_enc2);
    des_key_sched((des_cblock *) (deckey+7), text->keysched_dec2);

    memcpy(text->ivec_enc, ((char *) enckey) + 8, 8);
    memcpy(text->ivec_dec, ((char *) deckey) + 8, 8);

    return SASL_OK;
}


/******************************
 *
 * DES functions
 *
 *****************************/

static int dec_des(void *v, 
		   const char *input,
		   unsigned inputlen,
		   unsigned char digest[16],
		   char *output,
		   unsigned *outputlen)
{
  context_t *text = (context_t *) v;

  des_cbc_encrypt((des_cblock *) input,
		  (des_cblock *) output,
		  inputlen,
		  text->keysched_dec,
		  &text->ivec_dec,
		  DES_DECRYPT);
#if 0
  unsigned int lup;

  for (lup=0;lup<inputlen;lup+=8)
  {
      /* decrypt with 1st key */
      des_ecb_encrypt((des_cblock *)(input+lup),
		      (des_cblock *) ((output)+lup),
		      text->keysched_dec,
		      DES_DECRYPT);
  }
#endif

  /* now chop off the padding */
  *outputlen=inputlen- (output)[inputlen-11]-10;

  /* copy in the HMAC to digest */
  memcpy(digest, (output)+inputlen-10, 10);
  
  return SASL_OK;
}

static int enc_des(void *v, 
		   const char *input,
		   unsigned inputlen,
		   unsigned char digest[16],
		   char *output,
		   unsigned *outputlen)
{
  context_t *text = (context_t *) v;
  int len;
  int paddinglen;

  /* determine padding length */
  paddinglen=8- ((inputlen+10)%8);

  /* now construct the full stuff to be ciphered */
  memcpy(output, input, inputlen);                /* text */
  memset(output+inputlen, paddinglen, paddinglen);/* pad  */
  memcpy(output+inputlen+paddinglen, digest, 10); /* hmac */

  len=inputlen+paddinglen+10;

  des_cbc_encrypt((des_cblock *) output,
		  (des_cblock *) output,
		  len,
		  text->keysched_enc,
		  &text->ivec_enc,
		  DES_ENCRYPT);

#if 0
  int lup;

  for (lup=0;lup<len;lup+=8)
  {
      /* encrpyt with 1st key */
      des_ecb_encrypt((des_cblock *)(output+lup),
		      (des_cblock *)(output+lup),
		      text->keysched_enc,
		      DES_ENCRYPT);    
  }
#endif

  *outputlen=len;

  return SASL_OK;
}

static int init_des(void *v,
		    sasl_utils_t *utils __attribute__((unused)), 
		    char enckey[16],
		    char deckey[16])
{
    context_t *text = (context_t *) v;

    des_key_sched((des_cblock *) enckey, text->keysched_enc);
    memcpy(text->ivec_enc, ((char *) enckey) + 8, 8);

    des_key_sched((des_cblock *) deckey, text->keysched_dec);
    memcpy(text->ivec_dec, ((char *) deckey) + 8, 8);

    return SASL_OK;
}

#endif /* WITH_DES */

#ifdef WITH_RC4
/* quick generic implementation of RC4 */
struct rc4_context_s {
  unsigned char sbox[256];
  int i, j;
};

static void
rc4_init(rc4_context_t *text,
         const unsigned char *key,
         unsigned keylen)
{
    int i, j;
  
    /* fill in linearly s0=0 s1=1... */
    for (i=0;i<256;i++)
	text->sbox[i]=i;
    
    j=0;
    for (i = 0; i < 256; i++) {
	unsigned char tmp;
	/* j = (j + Si + Ki) mod 256 */
	j = (j + text->sbox[i] + key[i % keylen]) % 256;

	/* swap Si and Sj */
	tmp = text->sbox[i];
	text->sbox[i] = text->sbox[j];
	text->sbox[j] = tmp;
    }

    /* counters initialized to 0 */
    text->i = 0;
    text->j = 0;
}

static void
rc4_encrypt(rc4_context_t *text,
	    const char *input,
	    char *output,
	    unsigned len)
{
    int tmp;
    int i = text->i;
    int j = text->j;
    int t;
    int K;
    const char *input_end = input + len;
    
    while (input < input_end) {
	i = (i + 1) % 256;

	j = (j + text->sbox[i]) % 256;

	/* swap Si and Sj */
	tmp = text->sbox[i];
	text->sbox[i] = text->sbox[j];
	text->sbox[j] = tmp;
	
	t = (text->sbox[i] + text->sbox[j]) % 256;
	
	K = text->sbox[t];
	
	/* byte K is Xor'ed with plaintext */
	*output++ = *input++ ^ K;
  }

  text->i = i;
  text->j = j;
}

static void
rc4_decrypt(rc4_context_t *text,
            const char *input,
            char *output,
            unsigned len)
{
    int tmp;
    int i = text->i;
    int j = text->j;
    int t;
    int K;
    const char *input_end = input + len;
    
    while (input < input_end) {
	i = (i + 1) % 256;
	
	j = (j + text->sbox[i]) % 256;
	
	/* swap Si and Sj */
	tmp = text->sbox[i];
	text->sbox[i] = text->sbox[j];
	text->sbox[j] = tmp;
	
	t = (text->sbox[i] + text->sbox[j]) % 256;
	
	K = text->sbox[t];
	
	/* byte K is Xor'ed with plaintext */
	*output++ = *input++ ^ K;
    }

    text->i = i;
    text->j = j;
}

static int
init_rc4(void *v, 
	 sasl_utils_t *utils __attribute__((unused)),
	 char enckey[16],
	 char deckey[16])
{
    context_t *text = (context_t *) v;

    /* allocate rc4 context structures */
    text->rc4_enc_context=
	(rc4_context_t *) text->malloc(sizeof(rc4_context_t));
    if (text->rc4_enc_context==NULL) return SASL_NOMEM;

    text->rc4_dec_context=
	(rc4_context_t *) text->malloc(sizeof(rc4_context_t));
    if (text->rc4_dec_context==NULL) return SASL_NOMEM;

    /* initialize them */
    rc4_init(text->rc4_enc_context,(const unsigned char *) enckey, 16);
    rc4_init(text->rc4_dec_context,(const unsigned char *) deckey, 16);

    return SASL_OK;
}

static int
dec_rc4(void *v,
	const char *input,
	unsigned inputlen,
	unsigned char digest[16],
	char *output,
	unsigned *outputlen)
{
    context_t *text = (context_t *) v;

    /* decrypt the text part */
    rc4_decrypt(text->rc4_dec_context, input, output, inputlen-10);

    /* decrypt the HMAC part */
    rc4_decrypt(text->rc4_dec_context, 
		input+(inputlen-10), (char *) digest, 10);

    /* no padding so we just subtract the HMAC to get the text length */
    *outputlen = inputlen - 10;

    return SASL_OK;
}

static int
enc_rc4(void *v,
	const char *input,
	unsigned inputlen,
	unsigned char digest[16],
	char *output,
	unsigned *outputlen)
{
    context_t *text = (context_t *) v;

    /* pad is zero */
    *outputlen = inputlen+10;

    /* encrypt the text part */
    rc4_encrypt(text->rc4_enc_context, (const char *) input, output, inputlen);

    /* encrypt the HMAC part */
    rc4_encrypt(text->rc4_enc_context, (const char *) digest, 
		(output)+inputlen, 10);

    return SASL_OK;
}

#endif /* WITH_RC4 */

struct digest_cipher available_ciphers[] =
{
#ifdef WITH_RC4
    { "rc4-40", 40, 5, 0x01, &enc_rc4, &dec_rc4, &init_rc4 },
    { "rc4-56", 56, 7, 0x02, &enc_rc4, &dec_rc4, &init_rc4 },
    { "rc4", 128, 16, 0x04, &enc_rc4, &dec_rc4, &init_rc4 },
#endif
#ifdef WITH_DES
    { "des", 55, 16, 0x08, &enc_des, &dec_des, &init_des },
    { "3des", 112, 16, 0x10, &enc_3des, &dec_3des, &init_3des },
#endif
    { NULL, 0, 0, 0, NULL, NULL, NULL }
};

static int create_layer_keys(context_t *text,sasl_utils_t *utils,HASH key, int keylen,
			     char enckey[16], char deckey[16])
{
  MD5_CTX Md5Ctx;

  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, key, keylen);
  if (text->i_am == SERVER) {
      utils->MD5Update(&Md5Ctx, (const unsigned char *) SEALING_SERVER_CLIENT, 
		       strlen(SEALING_SERVER_CLIENT));
  } else {
      utils->MD5Update(&Md5Ctx, (const unsigned char *) SEALING_CLIENT_SERVER,
		       strlen(SEALING_CLIENT_SERVER));
  }
  utils->MD5Final((unsigned char *) enckey, &Md5Ctx);

  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, key, keylen);
  if (text->i_am != SERVER) {
      utils->MD5Update(&Md5Ctx, (const unsigned char *)SEALING_SERVER_CLIENT, 
		       strlen(SEALING_SERVER_CLIENT));
  } else {
      utils->MD5Update(&Md5Ctx, (const unsigned char *)SEALING_CLIENT_SERVER,
		       strlen(SEALING_CLIENT_SERVER));
  }
  utils->MD5Final((unsigned char *) deckey, &Md5Ctx);


  /* create integrity keys */

  /* sending */
  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, text->HA1, HASHLEN);
  if (text->i_am == SERVER) {
      utils->MD5Update(&Md5Ctx, (const unsigned char *)SIGNING_SERVER_CLIENT, 
		       strlen(SIGNING_SERVER_CLIENT));
  } else {
      utils->MD5Update(&Md5Ctx, (const unsigned char *)SIGNING_CLIENT_SERVER,
		       strlen(SIGNING_CLIENT_SERVER));
  }
  utils->MD5Final(text->Ki_send, &Md5Ctx);

  /* receiving */
  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, text->HA1, HASHLEN);
  if (text->i_am != SERVER) {
      utils->MD5Update(&Md5Ctx, (const unsigned char *)SIGNING_SERVER_CLIENT, 
		       strlen(SIGNING_SERVER_CLIENT));
  } else {
      utils->MD5Update(&Md5Ctx, (const unsigned char *)SIGNING_CLIENT_SERVER,
		       strlen(SIGNING_CLIENT_SERVER));
  }
  utils->MD5Final(text->Ki_receive, &Md5Ctx);


  return SASL_OK;
}

static unsigned short version = 1;

/* len, CIPHER(Kc, {msg, pag, HMAC(ki, {SeqNum, msg})[0..9]}), x0001, SeqNum */

static int
privacy_encode(void *context,
	       const char *input,
	       unsigned inputlen,
	       char **output,
	       unsigned *outputlen)
{
  context_t      *text = (context_t *) context;
  int tmp;
  unsigned int tmpnum;
  unsigned short int tmpshort;  
  
  char *out;
  unsigned char   digest[16];
  char *param2;

  assert(text->maxbuf > 0);

  *output = (char *) text->malloc(4+ /* for length */
				  inputlen+ /* for encrypted text */
				  10+ /* for MAC */
				  8+ /* maximum pad */
				  6+ /* for padding */
				  1); /* trailing null */
  if (*output==NULL) return SASL_NOMEM;

  /* skip by the length for now */
  out=(*output)+4;

  /* construct (seqnum, msg) */
  param2 = (char *) text->malloc(inputlen + 4);
  if (param2 == NULL) return SASL_NOMEM;

  tmpnum = htonl(text->seqnum);
  memcpy(param2, &tmpnum, 4);
  memcpy(param2 + 4, input, inputlen);
  
  /* HMAC(ki, (seqnum, msg) ) */
  text->hmac_md5((const unsigned char *) param2, inputlen + 4, 
		 text->Ki_send, HASHLEN, digest);

  text->free(param2);

  /* calculate the encrpyted part */
  text->cipher_enc(text,input,inputlen, digest,
		   out,outputlen);
  out+=(*outputlen);


  /* copy in version */
  tmpshort = htons(version);
  memcpy(out, &tmpshort, 2);	/* 2 bytes = version */

  out+=2;
  (*outputlen)+=2; /* for seqnum */

  /* put in seqnum */
  tmpnum = htonl(text->seqnum);
  memcpy(out, &tmpnum, 4);	/* 4 bytes = version */  

  (*outputlen)+=4; /* for seqnum */

  
  /* put the 1st 4 bytes in */
  tmp=htonl(*outputlen);  
  memcpy(*output, &tmp, 4);
  
  (*outputlen)+=4;
  text->seqnum++;

  return SASL_OK;
}

static int
privacy_decode(void *context,
		 const char *input,
		 unsigned inputlen,
		 char **output,
		 unsigned *outputlen)
{
    int tocopy;
    unsigned diff;
    int result;
    context_t      *text = (context_t *) context;
    char *extra;
    unsigned int extralen=0;
    unsigned char   digest[16];
    char *param2;
    int tmpnum;
    int lup;

    if (text->needsize>0) /* 4 bytes for how long message is */
    {
      /* if less than 4 bytes just copy those we have into text->size */
      if (inputlen<4) 
	tocopy=inputlen;
      else
	tocopy=4;
      
      if (tocopy>text->needsize)
	tocopy=text->needsize;

      memcpy(text->sizebuf+4-text->needsize, input, tocopy);
      text->needsize-=tocopy;

      input+=tocopy;
      inputlen-=tocopy;

      if (text->needsize==0) /* got all of size */
      {
	memcpy(&(text->size), text->sizebuf, 4);
	text->cursize=0;
	text->size=ntohl(text->size);

	/* No, this is not an error! Maximal size used in GSSAPI K5 is
	   0xFFFFFF, but not 0xFFFF 
	   -this is according to john myers at least
	*/
	if ((text->size>0xFFFFFF) || (text->size < 0)) return SASL_FAIL; /* too big probably error */
	
	text->buffer=text->malloc(text->size+5);
	if (text->buffer == NULL) return SASL_NOMEM;
      }
      *outputlen=0;
      *output=NULL;
      if (inputlen==0) /* have to wait until next time for data */
	return SASL_OK;

      if (text->size==0)  /* should never happen */
	return SASL_FAIL;
    }

    diff=text->size - text->cursize; /* bytes need for full message */

    if (! text->buffer)
      return SASL_FAIL;

    if (inputlen < diff) /* not enough for a decode */
    {
      memcpy(text->buffer+text->cursize, input, inputlen);
      text->cursize+=inputlen;
      *outputlen=0;
      *output=NULL;
      return SASL_OK;
    } else {
      memcpy(text->buffer+text->cursize, input, diff);
      input+=diff;      
      inputlen-=diff;
    }

    {
      unsigned short ver;
      unsigned int seqnum;
      unsigned char   checkdigest[16];

      *output = (char *) text->malloc(text->size-6);
      if (*output == NULL) return SASL_NOMEM;
      *outputlen = inputlen;
      
      result=text->cipher_dec(text,text->buffer,text->size-6,digest,
			      *output, outputlen);

      if (result!=SASL_OK)
      {
	text->free(text->buffer);
	return result;
      }


      /* check the version number */
      memcpy(&ver, text->buffer+text->size-6, 2);
      ver=ntohs(ver);
      if (ver != version)
      {
	VL(("Wrong Version\n"));
	return SASL_FAIL;
      }

      /* check the CMAC */

      /* construct (seqnum, msg) */
      param2 = (char *) text->malloc((*outputlen) + 4);
      if (param2 == NULL) return SASL_NOMEM;
      tmpnum = htonl(text->rec_seqnum);
      memcpy(param2, &tmpnum, 4);
      memcpy(param2 + 4, *output, *outputlen);

      /* HMAC(ki, (seqnum, msg) ) */
      text->hmac_md5((const unsigned char *) param2, (*outputlen) + 4, 
		     text->Ki_receive, HASHLEN, checkdigest);
      
      text->free(param2);


      /* now check it */
      for (lup=0;lup<10;lup++)
	if (checkdigest[lup]!=digest[lup])
	{
	  VL(("CMAC doesn't match!\n"));
	  return SASL_FAIL;
	} 


      /* check the sequence number */
      memcpy(&seqnum, text->buffer+text->size-4,4);
      seqnum=ntohl(seqnum);

      if (seqnum!=text->rec_seqnum)
      {
	VL(("Incorrect sequence number\n"));
	return SASL_FAIL;
      }

      text->rec_seqnum++; /* now increment it */

    }



    text->free(text->buffer);

    text->size=-1;
    text->needsize=4;

    /* if received more than the end of a packet */
    if (inputlen!=0)
    {
      extra=NULL;
      privacy_decode(text, input, inputlen,
			   &extra, &extralen);
      if (extra!=NULL) /* if received 2 packets merge them together */
      {	
	*output=realloc( *output, *outputlen+extralen);
	memcpy(*output+*outputlen, extra, extralen); 
	*outputlen+=extralen;	
      }
    }
     
    return SASL_OK;
}


static int
integrity_encode(void *context,
		 const char *input,
		 unsigned inputlen,
		 char **output,
		 unsigned *outputlen)
{
  unsigned char   MAC[16];
  unsigned char  *param2;
  unsigned int    tmpnum;
  unsigned short int tmpshort;
  
  context_t      *text = (context_t *) context;

  assert(inputlen > 0);
  assert(text->maxbuf > 0);

  param2 = (unsigned char *) text->malloc(inputlen + 4);
  if (param2 == NULL)
    return SASL_NOMEM;

  /* construct (seqnum, msg) */
  tmpnum = htonl(text->seqnum);
  memcpy(param2, &tmpnum, 4);
  memcpy(param2 + 4, input, inputlen);

  /* HMAC(ki, (seqnum, msg) ) */
  text->hmac_md5(param2, inputlen + 4, 
		 text->Ki_send, HASHLEN,
		 MAC);

  /* create MAC */
  tmpshort = htons(version);
  memcpy(MAC + 10, &tmpshort, MAC_OFFS);	/* 2 bytes = version */

  tmpnum = htonl(text->seqnum);
  memcpy(MAC + 12, &tmpnum, 4);	/* 4 bytes = sequence number */

  /*
   * for (lup=0;lup<16;lup++) printf("%i. MAC=%i\n",lup,MAC[lup]);
   */

  /* construct output */
  *outputlen = 4 + inputlen + 16;
  *output = (char *) text->malloc((*outputlen));
  if (*output == NULL)
    return SASL_NOMEM;

  /* copy into output */
  tmpnum = htonl((*outputlen) - 4);
  memcpy(*output, &tmpnum, 4);	/* length of message in network byte order */
  memcpy((*output) + 4, input, inputlen);	/* the message text */
  memcpy((*output) + 4 + inputlen, MAC, 16);	/* the MAC */

  text->seqnum++;		/* add one to sequence number */


  /* clean up */
  text->free(param2);

  return SASL_OK;
}

static int
create_MAC(context_t * text,
	   char *input,
	   int inputlen,
	   int seqnum,
	   unsigned char MAC[16])
{
  unsigned char  *param2;
  unsigned int    tmpnum;
  unsigned short int tmpshort;  

  if (inputlen < 0)
    return SASL_FAIL;

  param2 = (unsigned char *) text->malloc(inputlen + 4);
  if (param2 == NULL)
    return SASL_NOMEM;

  /* construct (seqnum, msg) */
  tmpnum = htonl(seqnum);
  memcpy(param2, &tmpnum, 4);
  memcpy(param2 + 4, input, inputlen);

  /* HMAC(ki, (seqnum, msg) ) */
  text->hmac_md5(param2, inputlen + 4, 
		 text->Ki_receive, HASHLEN,
		 MAC);

  /* create MAC */
  tmpshort = htons(version);
  memcpy(MAC + 10, &tmpshort, 2);	/* 2 bytes = version */

  tmpnum = htonl(seqnum);
  memcpy(MAC + 12, &tmpnum, 4);	/* 4 bytes = sequence number */

  /*
   * for (lup=0;lup<16;lup++) printf("%i. MAC=%i\n",lup,MAC[lup]);
   */

  /* clean up */
  text->free(param2);

  return SASL_OK;
}

static int
check_integrity(context_t * text,
		char *buf, int bufsize, char **output, unsigned *outputlen)
{
  unsigned char            MAC[16];
  int             result;

  result = create_MAC(text, buf, bufsize - 16, text->rec_seqnum, MAC);
  if (result != SASL_OK)
    return result;

  /* make sure the MAC is right */
  if (strncmp((char *) MAC, buf + bufsize - 16, 16) != 0)
  {
    VL(("MAC doesn't match\n"));
    return SASL_FAIL;
  }

  text->rec_seqnum++;

  /* ok make output message */
  *output = text->malloc(bufsize - 15);
  if ((*output) == NULL)
    return SASL_NOMEM;

  memcpy(*output, buf, bufsize - 16);
  *outputlen = bufsize - 16;
  (*output)[*outputlen] = 0;


  return SASL_OK;
}

static int
integrity_decode(void *context,
		 const char *input,
		 unsigned inputlen,
		 char **output,
		 unsigned *outputlen)
{
  int             tocopy;
  context_t      *text = context;
  char           *extra;
  unsigned int    extralen = 0;
  unsigned        diff;
  int             result;

  if (text->needsize > 0) {	/* 4 bytes for how long message is */
    /*
     * if less than 4 bytes just copy those we have into text->size
     */
    if (inputlen < 4)
      tocopy = inputlen;
    else
      tocopy = 4;

    if (tocopy > text->needsize)
      tocopy = text->needsize;

    memcpy(text->sizebuf + 4 - text->needsize, input, tocopy);
    text->needsize -= tocopy;

    input += tocopy;
    inputlen -= tocopy;

    if (text->needsize == 0) {	/* got all of size */
      memcpy(&(text->size), text->sizebuf, 4);
      text->cursize = 0;
      text->size = ntohl(text->size);

      if ((text->size > 0xFFFF) || (text->size < 0))
	return SASL_FAIL;	/* too big probably error */
      free(text->buffer);
      text->buffer = malloc(text->size);
    }
    *outputlen = 0;
    *output = NULL;
    if (inputlen == 0)		/* have to wait until next time for data */
      return SASL_OK;

    if (text->size == 0)	/* should never happen */
      return SASL_FAIL;
  }
  diff = text->size - text->cursize;	/* bytes need for full message */

  if (inputlen < diff) {	/* not enough for a decode */
    memcpy(text->buffer + text->cursize, input, inputlen);
    text->cursize += inputlen;
    *outputlen = 0;
    *output = NULL;
    return SASL_OK;
  } else {
    memcpy(text->buffer + text->cursize, input, diff);
    input += diff;
    inputlen -= diff;
  }

  result = check_integrity(text, text->buffer, text->size, output, outputlen);
  if (result != SASL_OK)
    return result;


  text->size = -1;
  text->needsize = 4;

  /* if received more than the end of a packet */
  if (inputlen != 0) {
    integrity_decode(text, input, inputlen,
		     &extra, &extralen);
    if (extra != NULL) {	/* if received 2 packets merge them together */
      *output = realloc(*output, *outputlen + extralen);
      memcpy(*output + *outputlen, extra, extralen);
      *outputlen += extralen;
    }
  }

  return SASL_OK;
}


static int server_start(void *glob_context __attribute__((unused)),
			sasl_server_params_t * sparams,
			const char *challenge __attribute__((unused)),
			int challen __attribute__((unused)),
			void **conn,
			const char **errstr)
{
    context_t *text;

    if (errstr)
	*errstr = NULL;

    /* holds state are in */
    text = sparams->utils->malloc(sizeof(context_t));
    if (text == NULL)
	return SASL_NOMEM;
    memset(text, 0, sizeof(context_t));

    text->i_am = SERVER;
    text->state = 1;

    *conn = text;
    return SASL_OK;
}

static void
dispose(void *conn_context, sasl_utils_t * utils)
{
  context_t *text=(context_t *) conn_context;

  /* free the stuff in the context */
  if (text->nonce!=NULL)
  {
    utils->free(text->nonce);
  }

  if (text->response_value!=NULL)
  {
    utils->free(text->response_value);
  }

  if (text->realm!=NULL)
  {
    utils->free(text->realm);
  }

  if (text->userid!=NULL)
  {
    utils->free(text->userid);
  }
  

  utils->free(conn_context);
}

static void
mech_free(void *global_context, sasl_utils_t * utils)
{

  utils->free(global_context);
}

static int
get_realm(sasl_server_params_t * params,
	  char **realm)
{
  /* look at user realm first */
  if (params->user_realm != NULL) {
      if (*(params->user_realm) != '\0') {
	  *realm = (char *) params->user_realm;
      } else {
	  *realm = NULL;
      }
  } else if (params->serverFQDN != NULL) {
      *realm = (char *) params->serverFQDN;
  } else {
      VL(("No way to obtain domain\n"));
      return SASL_FAIL;
  }

  return SASL_OK;
}

static int
server_continue_step(void *conn_context,
		     sasl_server_params_t * sparams,
		     const char *clientin,
		     int clientinlen,
		     char **serverout,
		     int *serveroutlen,
		     sasl_out_params_t * oparams,
		     const char **errstr)
{
  int             result;
  context_t      *text;
  text = conn_context;

  if (errstr)
    *errstr = NULL;

  if (clientinlen > 2048 || clientinlen < 0) return SASL_BADPARAM;

  if (text->state == 1) {
    char           *challenge = NULL;
    char           *realm;
    unsigned char  *nonce;
    char           *charset = "utf-8";

    char qop[1024], cipheropts[1024];
    struct digest_cipher *cipher;
    int added_conf = 0;

    if (sparams->props.max_ssf < sparams->external_ssf) {
	text->limitssf = 0;
    } else {
	text->limitssf = sparams->props.max_ssf - sparams->external_ssf;
    }
    if (sparams->props.min_ssf < sparams->external_ssf) {
	text->requiressf = 0;
    } else {
	text->requiressf = sparams->props.min_ssf - sparams->external_ssf;
    }

    /* what options should we offer the client? */
    qop[0] = '\0';
    cipheropts[0] = '\0';
    if (text->requiressf == 0) {
	if (*qop) strcat(qop, ",");
	strcat(qop, "auth");
    }
    if (text->requiressf <= 1 && text->limitssf >= 1) {
	if (*qop) strcat(qop, ",");
	strcat(qop, "auth-int");
    }
    
    cipher = available_ciphers;
    while (cipher->name) {
	/* do we allow this particular cipher? */
	if (text->requiressf <= cipher->ssf && text->limitssf >= cipher->ssf) {
	    if (!added_conf) {
		if (*qop) strcat(qop, ",");
		strcat(qop, "auth-conf");
		added_conf = 1;
	    }
	    if (*cipheropts) strcat(cipheropts, ",");
	    strcat(cipheropts, cipher->name);
	}
	cipher++;
    }

    if (*qop == '\0') {
	/* we didn't allow anything?!? we'll return SASL_TOOWEAK, since
	 that's close enough */
	return SASL_TOOWEAK;
    }

    /*
     * digest-challenge  = 1#( realm | nonce | qop-options | stale | maxbuf |
     * charset | cipher-opts | auth-param )
     */

    /* get realm */
    result = get_realm(sparams, &realm);

    /* add to challenge; if we chose not to specify a realm, we won't
     * end one to the client */
    if (realm && add_to_challenge(sparams->utils, &challenge, "realm", (unsigned char *) realm, TRUE) != SASL_OK) {
	SETERRSTR("internal error: add_to_challenge failed");
	return SASL_FAIL;
    }
    /* get nonce XXX have to clean up after self if fail */
    nonce = create_nonce(sparams->utils);
    if (nonce == NULL) {
	SETERRSTR("internal erorr: failed creating a nonce");
	return SASL_FAIL;
    }
    /* add to challenge */
    if (add_to_challenge(sparams->utils, &challenge, "nonce", nonce, TRUE) != SASL_OK) {
	SETERRSTR("internal error: add_to_challenge 2 failed");
	return SASL_FAIL;
    }
    /*
     * qop-options A quoted string of one or more tokens indicating the
     * "quality of protection" values supported by the server.  The value
     * "auth" indicates authentication; the value "auth-int" indicates
     * authentication with integrity protection; the value "auth-conf"
     * indicates authentication with integrity protection and encryption.
     */

    /* add qop to challenge */
    if (add_to_challenge(sparams->utils, &challenge, "qop", 
			 (unsigned char *) qop, TRUE) != SASL_OK) {
	SETERRSTR("internal error: add_to_challenge 3 failed");
	return SASL_FAIL;
    }


    /*
     *  Cipheropts - list of ciphers server supports
     */
    /* add cipher-opts to challenge; only add if there are some */
    if (strcmp(cipheropts,"")!=0)
    {
      if (add_to_challenge(sparams->utils, &challenge, 
			   "cipher", (unsigned char *) cipheropts, 
			   TRUE) != SASL_OK) {
	  SETERRSTR("internal error: add_to_challenge 4 failed");
	  return SASL_FAIL;
      }
    }

    /* "stale" not used in initial authentication */

    /*
     * maxbuf A number indicating the size of the largest buffer the server
     * is able to receive when using "auth-int". If this directive is
     * missing, the default value is 65536. This directive may appear at most
     * once; if multiple instances are present, the client should abort the
     * authentication exchange.
     */

    if (add_to_challenge(sparams->utils, &challenge, "charset", 
			 (unsigned char *) charset, FALSE) != SASL_OK) {
	SETERRSTR("internal error: add_to_challenge 5 failed");
	return SASL_FAIL;
    }


    /*
     * algorithm 
     *  This directive is required for backwards compatibility with HTTP 
     *  Digest., which supports other algorithms. . This directive is 
     *  required and MUST appear exactly once; if not present, or if multiple 
     *  instances are present, the client should abort the authentication 
     *  exchange. 
     *
     * algorithm         = "algorithm" "=" "md5-sess" 
     */
   
    if (add_to_challenge(sparams->utils, &challenge,"algorithm",
			 (unsigned char *) "md5-sess", FALSE)!=SASL_OK) {
	SETERRSTR("internal error: add_to_challenge 6 failed");
	return SASL_FAIL;
    }

    *serverout = challenge;
    *serveroutlen = strlen(*serverout);

    /*
     * The size of a digest-challenge MUST be less than 2048 bytes!!!
     */
    if (*serveroutlen > 2048) {
	SETERRSTR("internal error: challenge larger than 2048 bytes");
	return SASL_FAIL;
    }

    text->noncelen = strlen((char *) nonce);
    text->nonce = nonce;

    text->last_ncvalue = 0;	/* Next must be "nc=00000001" */

    text->state = 2;

    digest_strdup(sparams->utils, realm, (char **) &text->realm, NULL);

    /*
     * sparams->utils->free(realm); - Not malloc'ated!!! No free(...)!!!
     * sparams->utils->free(nonce); Nonce is saved!!! Do not free it!!!
     */

    return SASL_CONTINUE;
  }
  if (text->state == 2) {
    /* verify digest */
    sasl_secret_t  *sec;
    /* int len=sizeof(MD5_CTX); */
    int             result;
    sasl_server_getsecret_t *getsecret;
    void           *getsecret_context;

    char           *serverresponse = NULL;

    char           *username = NULL;

    char           *authorization_id = NULL;

    char           *realm = NULL;
    unsigned char  *cnonce = NULL;

    unsigned char  *ncvalue = NULL;
    int             noncecount;

    char           *qop = NULL;
    char           *digesturi = NULL;
    char           *response = NULL;

     /* setting the default value (65536) */
    unsigned int    client_maxbuf = 65536;
    int             maxbuf_count = 0;	/* How many maxbuf instaces was found */

    char           *charset = NULL;
    char           *cipher = NULL;
    unsigned int   n=0;

    HASH            A1;

    /* can we mess with clientin? copy it to be safe */
    char           *in_start = NULL;
    char           *in = NULL; 

    char *response_auth = NULL;

    in = sparams->utils->malloc(clientinlen + 1);

    memcpy(in, clientin, clientinlen);
    in[clientinlen] = 0;

    in_start = in;


    /* parse what we got */
    while (in[0] != '\0') {
      char           *name = NULL, *value = NULL;
      get_pair(&in, &name, &value);

      if (name == NULL)
	  break;

      VL(("received from client pair: %s - %s\n", name, value));

      /* Extracting parameters */

      /*
       * digest-response  = 1#( username | realm | nonce | cnonce |
       * nonce-count | qop | digest-uri | response | maxbuf | charset |
       * cipher | auth-param )
       */

      VL(("server_start step 2 : received pair: \t"));
      VL(("%s:%s\n", name, value));

      if (strcasecmp(name, "username") == 0) {

	digest_strdup(sparams->utils, value, &username, NULL);

      } else if (strcasecmp(name, "authzid") == 0) {

	digest_strdup(sparams->utils, value, &authorization_id, NULL);

      } else if (strcasecmp(name, "cnonce") == 0) {

	digest_strdup(sparams->utils, value, (char **) &cnonce, NULL);

      } else if (strcasecmp(name, "nc") == 0) {

	if (htoi((unsigned char *) value, &noncecount) != SASL_OK) {
	    SETERRSTR("error converting hex to int");
	    result = SASL_BADAUTH;
	    goto FreeAllMem;
	}
	digest_strdup(sparams->utils, value, (char **) &ncvalue, NULL);

      } else if (strcasecmp(name, "realm") == 0) {
	  if (realm) {
	      SETERRSTR("duplicate realm: authentication aborted");
	      result = SASL_FAIL;
	      goto FreeAllMem;
	  } else if (text->realm && (strcmp(value, text->realm) != 0)) {
	      SETERRSTR("realm changed: authentication aborted");
	      result = SASL_FAIL;
	      goto FreeAllMem;
	  }
	  
	  digest_strdup(sparams->utils, value, &realm, NULL);
	  
      } else if (strcasecmp(name, "nonce") == 0) {
	  if (strcmp(value, (char *) text->nonce) != 0) {
	      /*
	       * Nonce changed: Abort authentication!!!
	       */
	      SETERRSTR("nonce changed: authentication aborted");
	      result = SASL_BADAUTH;
	      goto FreeAllMem;
	  }
      } else if (strcasecmp(name, "qop") == 0) {
	digest_strdup(sparams->utils, value, &qop, NULL);
      } else if (strcasecmp(name, "digest-uri") == 0) {
	/* XXX: verify digest-uri format */
	/*
	 * digest-uri-value  = serv-type "/" host [ "/" serv-name ]
	 */
	digest_strdup(sparams->utils, value, &digesturi, NULL);
      } else if (strcasecmp(name, "response") == 0) {
	digest_strdup(sparams->utils, value, &response, NULL);
      } else if (strcasecmp(name, "cipher") == 0) {
	digest_strdup(sparams->utils, value, &cipher, NULL);
      } else if (strcasecmp(name, "maxbuf") == 0) {
	maxbuf_count++;
	if (maxbuf_count != 1) {
	  result = SASL_BADAUTH;
	  SETERRSTR("duplicate maxbuf: authentication aborted");
	  goto FreeAllMem;
	} else if (sscanf(value, "%u", &client_maxbuf) != 1) {
	  result = SASL_BADAUTH;
	  SETERRSTR("invalid maxbuf parameter");
	  goto FreeAllMem;
	} else {
            if (client_maxbuf <= 16) {
	      result = SASL_BADAUTH;
	      SETERRSTR("maxbuf parameter too small");
	      goto FreeAllMem;
            }
	}
      } else if (strcasecmp(name, "charset") == 0) {
	if (strcasecmp(value, "utf-8") != 0) {
	    SETERRSTR("client doesn't support UTF-8");
	    result = SASL_FAIL;
	    goto FreeAllMem;
	}
	digest_strdup(sparams->utils, value, &charset, NULL);
      } else {
	VL(("unrecognized pair: ignoring\n"));
      }
    }

    /* defaulting qop to "auth" if not specified */
    if (qop == NULL) {
	digest_strdup(sparams->utils, "auth", &qop, NULL);      
    }

    /* check which layer/cipher to use */
    if ((!strcasecmp(qop, "auth-conf")) && (cipher != NULL)) {
	/* see what cipher was requested */
	struct digest_cipher *cptr;

	VL(("Client requested privacy layer\n"));
	VL(("Client cipher=%s\n",cipher));

	cptr = available_ciphers;
	while (cptr->name) {
	    /* find the cipher requested & make sure it's one we're happy
	       with by policy */
	    if (!strcasecmp(cipher, cptr->name) && 
		text->requiressf <= cptr->ssf && text->limitssf >= cptr->ssf) {
		/* found it! */
		break;
	    }
	    cptr++;
	}

	if (cptr->name) {
	    text->cipher_enc = cptr->cipher_enc;
	    text->cipher_dec = cptr->cipher_dec;
	    text->cipher_init = cptr->cipher_init;
	    oparams->mech_ssf = cptr->ssf;
	    n = cptr->n;
	} else {
	    /* erg? client requested something we didn't advertise! */
	    sparams->utils->log(sparams->utils->conn, SASL_LOG_WARNING,
			    "DIGEST_MD5", SASL_FAIL, 0,
		    "protocol violation: client requested invalid cipher");
	    SETERRSTR("client requested invalid cipher");
	    result = SASL_FAIL;
	    goto FreeAllMem;
	}

	oparams->encode=&privacy_encode;
	oparams->decode=&privacy_decode;
    } else if (!strcasecmp(qop, "auth-int") &&
	       text->requiressf <= 1 && text->limitssf >= 1) {
	VL(("Client requested integrity layer\n"));
	oparams->encode = &integrity_encode;
	oparams->decode = &integrity_decode;
	oparams->mech_ssf = 1;
    } else if (!strcasecmp(qop, "auth") && text->requiressf == 0) {
	VL(("Client requested no layer\n"));
	oparams->encode = NULL;
	oparams->decode = NULL;
	oparams->mech_ssf = 0;
    } else {
	sparams->utils->log(sparams->utils->conn, SASL_LOG_WARNING,
			    "DIGEST_MD5", SASL_FAIL, 0,
                          "protocol violation: client requested invalid qop");
	SETERRSTR("client requested invalid qop");
	result = SASL_FAIL;
	goto FreeAllMem;
    }

    /*
     * username         = "username" "=" <"> username-value <">
     * username-value   = qdstr-val cnonce           = "cnonce" "=" <">
     * cnonce-value <"> cnonce-value     = qdstr-val nonce-count      = "nc"
     * "=" nc-value nc-value         = 8LHEX qop              = "qop" "="
     * qop-value digest-uri = "digest-uri" "=" digest-uri-value
     * digest-uri-value  = serv-type "/" host [ "/" serv-name ] serv-type
     * = 1*ALPHA host             = 1*( ALPHA | DIGIT | "-" | "." ) service
     * = host response         = "response" "=" <"> response-value <">
     * response-value   = 32LHEX LHEX = "0" | "1" | "2" | "3" | "4" | "5" |
     * "6" | "7" | "8" | "9" | "a" | "b" | "c" | "d" | "e" | "f" cipher =
     * "cipher" "=" cipher-value
     */
    /* Verifing that all parameters was defined */
    if ((username == NULL) ||
	(ncvalue == NULL) ||
	(cnonce == NULL) ||
	(digesturi == NULL) ||
	(response == NULL)) {
	SETERRSTR("required parameters missing");
	result = SASL_BADAUTH;
	goto FreeAllMem;
    }

    result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_GETSECRET,
					 (int (**) ()) &getsecret, /* ??? */
					 &getsecret_context);
    if ((result != SASL_OK) || (!getsecret)) {
	SETERRSTR("internal error: couldn't get 'getsecret' callback");
	result = SASL_FAIL;
	goto FreeAllMem;
    }

    if (!realm) {
	/* if no realm specified use empty string realm */
	digest_strdup(sparams->utils, "", &realm, NULL);
    }

    /* We use the user's DIGEST secret */
    result = getsecret(getsecret_context, "DIGEST-MD5", username,
		       realm, &sec);
    if (result != SASL_OK) {
	SETERRSTR("unable to get user's secret");
	goto FreeAllMem;
    }
    if (!sec) {
	SETERRSTR("unable to get user's secret");
	result = SASL_FAIL;
	goto FreeAllMem;
    }
    /*
     * Verifying response obtained from client
     * 
     * H_URP = H( { username-value, ":", realm-value, ":", passwd } ) sec->data
     * contains H_URP
     */


    /*
     * Verifying that we really store A1 in our authentication database
     */
    if (sec->len != HASHLEN) {
	SETERRSTR("internal error: stored secret of wrong length");
	result = SASL_FAIL;
	goto FreeAllMem;
    }
    /*
     * A1       = { H( { username-value, ":", realm-value, ":", passwd } ),
     * ":", nonce-value, ":", cnonce-value }
     */
    memcpy(A1, sec->data, HASHLEN);
    A1[HASHLEN] = '\0';

    /* We're done with sec now. Let's get rid of it XXX should be
       zero'ed out */
    sparams->utils->free(sec);

    serverresponse = create_response(text,
				     sparams->utils,
				     text->nonce,
				     ncvalue,
				     cnonce,
				     qop,
				     digesturi,
				     A1,
				     authorization_id,
				     &text->response_value);


    if (serverresponse == NULL) {
	SETERRSTR("internal error: unable to create response");
	result = SASL_NOMEM;
	goto FreeAllMem;
    }

    /* if ok verified */
    if (strcmp(serverresponse, response) != 0) {
	SETERRSTR("client response doesn't match what we generated");
	result = SASL_BADAUTH;
	
	VL(("Client Sent: %s\n", response));
	VL(("Server calculated: %s\n", serverresponse));
	/* XXX stuff for reauth */
	goto FreeAllMem;
    }
    VL(("MATCH! (authenticated) \n"));

    /*
     * nothing more to do; authenticated set oparams information
     */

    if (digest_strdup(sparams->utils, realm, 
		      &oparams->realm, NULL) == SASL_NOMEM) {
      result = SASL_NOMEM;
      goto FreeAllMem;
    }
    if (digest_strdup(sparams->utils, username, 
		      &oparams->authid, NULL) == SASL_NOMEM) {
      result = SASL_NOMEM;
      goto FreeAllMem;
    }

    if (! authorization_id || !*authorization_id)
      authorization_id = username;

    if (digest_strdup(sparams->utils, authorization_id, 
		      &oparams->user, NULL) == SASL_NOMEM) {
      result = SASL_NOMEM;
      goto FreeAllMem;
    };

    oparams->doneflag = 1;
    oparams->maxoutbuf = client_maxbuf;

    oparams->param_version = 0;

    text->seqnum = 0;		/* for integrity/privacy */
    text->rec_seqnum = 0;	/* for integrity/privacy */
    text->maxbuf = client_maxbuf;
    text->hmac_md5 = sparams->utils->hmac_md5;
    text->malloc = sparams->utils->malloc;
    text->free = sparams->utils->free;

    /* used by layers */
    text->size = -1;
    text->needsize = 4;
    text->buffer = NULL;

    { /* xxx if layers */

      char enckey[16];
      char deckey[16];


      create_layer_keys(text, sparams->utils,text->HA1,n,enckey,deckey);
      
      /* initialize cipher if need be */
      if (text->cipher_init!=NULL)
      {

	text->cipher_init(text, sparams->utils,
			  enckey,deckey);
	
      }

    }

    /*
     * The server receives and validates the "digest-response". The server
     * checks that the nonce-count is "00000001". If it supports subsequent
     * authentication, it saves the value of the nonce and the nonce-count.
     */

    /*
     * The "username-value", "realm-value" and "passwd" are encoded according
     * to the value of the "charset" directive. If "charset=UTF-8" is
     * present, and all the characters of either "username-value" or "passwd"
     * are in the ISO 8859-1 character set, then it must be converted to
     * UTF-8 before being hashed. A sample implementation of this conversion
     * is in section 8.
     */

    /* add to challenge */
    if (add_to_challenge(sparams->utils, &response_auth, "rspauth", 
			 (unsigned char *) text->response_value, FALSE) 
	    != SASL_OK) {
	SETERRSTR("add_to_challenge failed");
	result = SASL_FAIL;
	goto FreeAllMem;
    }
    *serverout = response_auth;
    *serveroutlen = strlen(response_auth);

    /* self check */
    if (*serveroutlen > 2048) {
      result = SASL_FAIL;
      goto FreeAllMem;
    }
    result = SASL_CONTINUE; /* xxx this should be SASL_OK but would cause applications to fail
			       will fix for 2.0 */

  FreeAllMem:
    /* free everything */
    /*
     * sparams->utils->free (authorization_id);
     */

    if (in_start) sparams->utils->free (in_start);

    if (username != NULL) {
	sparams->utils->free (username);
    }
    if (realm != NULL) {
	sparams->utils->free (realm);
    }
    if (cnonce != NULL) {
	sparams->utils->free (cnonce);
    }
    if (response != NULL) {
	sparams->utils->free (response);
    }
    if (serverresponse != NULL) {
	sparams->utils->free(serverresponse);
    }
    if (charset != NULL) {
	sparams->utils->free (charset);
    }
    if (digesturi != NULL) {
	sparams->utils->free (digesturi);
    }
    if (ncvalue != NULL) {
	sparams->utils->free (ncvalue);
    }
    if (qop!=NULL) {
	sparams->utils->free (qop);  
    }

    if (result == SASL_CONTINUE)
      text->state = 3;

    return result;
  }

  if (text->state == 3) {
    VL(("Digest-MD5 Step 3\n"));
    /*
     * Send additional information for reauthentication
     */
    if (clientinlen != 0) {
	SETERRSTR("no more data expected from client");
	return SASL_FAIL;
    }
    *serverout = NULL;
    *serveroutlen = 0;

    text->state = 1;

    return SASL_OK;
  }


  return SASL_FAIL;		/* should never get here */
}

/*
 * See if there's at least one secret in the database
 *
 * Note: this function is duplicated in multiple plugins. If you fix
 * something here please update the other files
 */

static int mechanism_db_filled(char *mech_name, sasl_utils_t *utils)
{
  sasl_secret_t *sec=NULL;
  int result;
  sasl_server_getsecret_t *getsecret;
  void *getsecret_context;
  long tmpversion = -1;

  /* get callback so we can request the secret */
  result = utils->getcallback(utils->conn,
			      SASL_CB_SERVER_GETSECRET,
			      &getsecret,
			      &getsecret_context);

  if (result != SASL_OK) {
    VL(("result = %i trying to get secret callback\n",result));
    return result;
  }

  if (! getsecret) {
    VL(("Received NULL getsecret callback\n"));
    return SASL_FAIL;
  }

  /* Request secret */
  result = getsecret(getsecret_context, mech_name, "", "", &sec);

  /* check version */
  if (sec != NULL)
  {
      if (sec->len >= 4) {
	  memcpy(&tmpversion, sec->data, 4); 
	  tmpversion = ntohl(tmpversion);
      }
      free(sec);
  }
  if (result == SASL_NOUSER || result == SASL_FAIL) {
      return result;
  }

  if (tmpversion != DIGEST_MD5_VERSION)
  {
      utils->log(utils->conn,
		 0,
		 mech_name,
		 SASL_FAIL,
		 0,
		 "DIGEST-MD5 secrets database has incompatible version (%ld). My version (%d)",
		 tmpversion, DIGEST_MD5_VERSION);

      return SASL_FAIL;
  }
  
  mydb_initialized = 1;

  return result;
}

/*
 * Put a DUMMY entry in the db to show that there is at least one entry in the db
 *
 * Note: this function is duplicated in multiple plugins. If you fix
 * something here please update the other files
 */

static int mechanism_fill_db(char *mech_name, sasl_server_params_t *sparams)
{
  int result;
  long tmpversion;
  sasl_server_putsecret_t *putsecret;
  void *putsecret_context;
  sasl_secret_t *sec = NULL;

  /* don't do this again if it's already set */
  if (mydb_initialized == 1)
  {
      return SASL_OK;
  }

  /* get the callback for saving to the password db */
  result = sparams->utils->getcallback(sparams->utils->conn,
				       SASL_CB_SERVER_PUTSECRET,
				       &putsecret,
				       &putsecret_context);
  if (result != SASL_OK) {
    return result;
  }

  /* allocate a secret structure that we're going to save to disk */  
  sec=(sasl_secret_t *) sparams->utils->malloc(sizeof(sasl_secret_t)+
					       4);
  if (sec == NULL) {
    result = SASL_NOMEM;
    return result;
  }

  /* set the size */
  sec->len = 4;

  /* and insert the data */
  tmpversion = htonl(DIGEST_MD5_VERSION);
  memcpy(sec->data, &tmpversion, 4);

  /* do the store */
  result = putsecret(putsecret_context,
		     mech_name, 
		     "",
		     "",
		     sec);

  sparams->utils->free(sec);

  if (result == SASL_OK)
  {
      mydb_initialized = 1;
  }

  return result;
}

static int
setpass(void *glob_context __attribute__((unused)),
	sasl_server_params_t * sparams,
	const char *user,
	const char *pass,
	unsigned passlen,
	int flags __attribute__((unused)),
	const char **errstr) {
  int             result;
  sasl_server_putsecret_t *putsecret;
  void           *putsecret_context;
  sasl_secret_t  *sec;
  HASH            HA1;
  char           *realm;
  union {
    char buf[sizeof(sasl_secret_t) + HASHLEN + 1];
    long align_long;
    double align_float;
  } secbuf;

  /* make sure we have everything we need */
  if (!sparams || !user)
    return SASL_BADPARAM;

  /* get the realm */
  result = get_realm(sparams, &realm);

  if ((result!=SASL_OK) || (realm==NULL)) {
    VL(("Digest-MD5 requires a domain\n"));
    return SASL_NOTDONE;
  }

  if (errstr) {
      *errstr = NULL;
  }

  if ((flags & SASL_SET_DISABLE) || pass == NULL) {
      /* delete user */
      sec = NULL;
  } else {
      DigestCalcSecret(sparams->utils,
		       (unsigned char *) user,
		       (unsigned char *) realm,
		       (unsigned char *) pass,
		       passlen,
		       HA1);

      /* construct sec to store on disk */
      sec = (sasl_secret_t *) &secbuf;
      sec->len = HASHLEN;
      memcpy(sec->data, HA1, HASHLEN);
  }

  /* get the callback so we can set the password */
  result = sparams->utils->getcallback(sparams->utils->conn,
				       SASL_CB_SERVER_PUTSECRET,
				       &putsecret,
				       &putsecret_context);
  if (result != SASL_OK) {
      return result;
  }

  result = putsecret(putsecret_context, "DIGEST-MD5",
		     user, realm, sec);

  if (sec != NULL) {
      memset(&secbuf, 0, sizeof(secbuf));
  }

  if (result != SASL_OK) {
      return result;
  }

  /* put entry in db to say we have at least one user */
  result = mechanism_fill_db("DIGEST-MD5", sparams);

  return result;
}

const sasl_server_plug_t plugins[] =
{
  {
    "DIGEST-MD5",
#ifdef WITH_RC4
    128,				/* max ssf */
#elif WITH_DES
    112,
#else 
    0,
#endif
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
    NULL,
    &server_start,
    &server_continue_step,
    &dispose,
    &mech_free,
    &setpass,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
  }
};

int sasl_server_plug_init(sasl_utils_t * utils __attribute__((unused)),
			  int maxversion __attribute__((unused)),
			  int *out_version,
			  const sasl_server_plug_t ** pluglist,
			  int *plugcount) 
{
  /*  if (maxversion < DIGESTMD5_VERSION)
      return SASL_BADVERS;*/

  *pluglist = plugins;

  *plugcount = 1;
  *out_version = DIGEST_MD5_VERSION;

  if ( mechanism_db_filled("DIGEST-MD5",utils) != SASL_OK) {
      return SASL_NOUSER;
  }

  return SASL_OK;
}

/* put in sasl_wrongmech */
static int c_start(void *glob_context __attribute__((unused)),
		   sasl_client_params_t * params,
		   void **conn) {
    context_t *text;

    /* holds state are in */
    text = params->utils->malloc(sizeof(context_t));
    if (text == NULL)
	return SASL_NOMEM;
    memset(text, 0, sizeof(context_t));

    text->i_am = CLIENT;
    text->state = 1;

    *conn = text;
    return SASL_OK;
}


/*
 * Convert hex string to int
 */

static int
htoi(unsigned char *hexin, int *res)
{
  int             lup, inlen;
  inlen = strlen((char *) hexin);

  *res = 0;
  for (lup = 0; lup < inlen; lup++) {
    switch (hexin[lup]) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      *res = (*res << 4) + (hexin[lup] - '0');
      break;

    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
      *res = (*res << 4) + (hexin[lup] - 'a' + 10);
      break;

    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
      *res = (*res << 4) + (hexin[lup] - 'A' + 10);
      break;

    default:
      return SASL_BADPARAM;
    }

  }

  return SASL_OK;
}

/*
 * Trys to find the prompt with the lookingfor id in the prompt list Returns
 * it if found. NULL otherwise
 */

static sasl_interact_t *
find_prompt(sasl_interact_t ** promptlist,
	    unsigned int lookingfor)
{
  sasl_interact_t *prompt;

  if (promptlist && *promptlist)
    for (prompt = *promptlist;
	 prompt->id != SASL_CB_LIST_END;
	 ++prompt)
      if (prompt->id==lookingfor)
	return prompt;

  return NULL;
}

static int
get_authid(sasl_client_params_t * params,
	   char **authid,
	   sasl_interact_t ** prompt_need)
{

  int             result;
  sasl_getsimple_t *getauth_cb;
  void           *getauth_context;
  sasl_interact_t *prompt;
  const char *ptr;

  /* see if we were given the authname in the prompt */
  prompt = find_prompt(prompt_need, SASL_CB_AUTHNAME);
  if (prompt != NULL) {
      if (!prompt->result) {
	  return SASL_BADPARAM;
      }

      /* copy it */
      *authid=params->utils->malloc(prompt->len+1);
      if ((*authid)==NULL) return SASL_NOMEM;

      strncpy(*authid, prompt->result, prompt->len+1);      
      return SASL_OK;
  }
  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_AUTHNAME,
				      &getauth_cb,
				      &getauth_context);
  switch (result) {
  case SASL_INTERACT:
    return SASL_INTERACT;
  case SASL_OK:
    if (!getauth_cb)
      return SASL_FAIL;
    result = getauth_cb(getauth_context,
			SASL_CB_AUTHNAME,
			&ptr,
			NULL);
    if (result != SASL_OK)
      return result;
    if (!ptr) return SASL_BADPARAM;

    *authid = params->utils->malloc(strlen(ptr)+1);
    if ((*authid)==NULL) return SASL_NOMEM;
    strcpy(*authid, ptr);

    break;
  default:
    /* sucess */
    break;
  }

  return result;

}

/*
 * Somehow retrieve the userid
 * This is the same as in digest-md5 so change both
 */

static int
get_userid(sasl_client_params_t *params,
		      char **userid,
		      sasl_interact_t **prompt_need)
{
  int result;
  sasl_getsimple_t *getuser_cb;
  void *getuser_context;
  sasl_interact_t *prompt;
  const char *ptr;

  /* see if we were given the userid in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_USER);
  if (prompt!=NULL) {
      if (!prompt->result) {
	  return SASL_BADPARAM;
      }

      /* copy it */
      *userid=params->utils->malloc(prompt->len+1);
      if ((*userid)==NULL) return SASL_NOMEM;

      strncpy(*userid, prompt->result, prompt->len+1);
      return SASL_OK;
    }

  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_USER,
				      &getuser_cb,
				      &getuser_context);
  switch (result) {
  case SASL_INTERACT:
    return SASL_INTERACT;
  case SASL_OK:
    if (!getuser_cb)
      return SASL_FAIL;
    result = getuser_cb(getuser_context,
			SASL_CB_USER,
			&ptr,
			NULL);
    if (result != SASL_OK)
      return result;
    if (!ptr) return SASL_BADPARAM;

    *userid=params->utils->malloc(strlen(ptr)+1);
    if ((*userid)==NULL) return SASL_NOMEM;
    strcpy(*userid, ptr);

    break;
  default:
    /* sucess */
    break;
  }

  return result;
}

static int
get_password(sasl_client_params_t * params,
	     sasl_secret_t ** password,
	     sasl_interact_t ** prompt_need)
{
  int             result;
  sasl_getsecret_t *getpass_cb;
  void           *getpass_context;
  sasl_interact_t *prompt;

  /* see if we were given the password in the prompt */
  prompt = find_prompt(prompt_need, SASL_CB_PASS);
  if (prompt != NULL) {
    /* We prompted, and got. */

    if (!prompt->result)
      return SASL_FAIL;

    /* copy what we got into a secret_t */
    *password = (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t) +
							prompt->len + 1);
    if (!*password)
      return SASL_NOMEM;

    (*password)->len = prompt->len;
    memcpy((*password)->data, prompt->result, prompt->len);
    (*password)->data[(*password)->len] = 0;

    return SASL_OK;
  }
  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_PASS,
				      &getpass_cb,
				      &getpass_context);

  switch (result) {
  case SASL_INTERACT:
    return SASL_INTERACT;
  case SASL_OK:
    if (!getpass_cb)
      return SASL_FAIL;
    result = getpass_cb(params->utils->conn,
			getpass_context,
			SASL_CB_PASS,
			password);
    if (result != SASL_OK)
      return result;

    break;
  default:
    /* sucess */
    break;
  }

  return result;
}

static int
c_get_realm(sasl_client_params_t * params,
	    char ** myrealm,
	    char ** realms,
	    sasl_interact_t ** prompt_need)
{
    int result;
    sasl_getrealm_t *getrealm_cb;
    void *getrealm_context;
    sasl_interact_t *prompt;
    char *tmp;

    prompt = find_prompt(prompt_need, SASL_CB_GETREALM);
    if (prompt != NULL) {
	if (!prompt->result) {
	    return SASL_BADPARAM;
	}

	/* copy it */
	*myrealm=params->utils->malloc(prompt->len+1);
	if ((*myrealm)==NULL) return SASL_NOMEM;

	strncpy(*myrealm, prompt->result, prompt->len+1);
	return SASL_OK;
    }

    /* ok, let's use a callback? */
    result = params->utils->getcallback(params->utils->conn,
					SASL_CB_GETREALM,
					&getrealm_cb,
					&getrealm_context);
    switch (result) {
    case SASL_INTERACT:
	return SASL_INTERACT;
    case SASL_OK:
	if (!getrealm_cb)
	    return SASL_FAIL;
	result = getrealm_cb(getrealm_context,
			     SASL_CB_GETREALM,
			     (const char **) realms,
			     (const char **) &tmp);
	if (result != SASL_OK) {
	    return result;
	}
	if (!tmp) return SASL_BADPARAM;

	*myrealm = params->utils->malloc(strlen(tmp)+1);
	if ((*myrealm) == NULL) return SASL_NOMEM;
	strcpy(*myrealm, tmp);
	break;
    default:
	/* success */
	break;
    }
    return result;
}


static void
free_prompts(sasl_client_params_t * params,
	     sasl_interact_t * prompts)
{
  sasl_interact_t *ptr = prompts;
  if (ptr == NULL)
    return;

  do {
    if (ptr->result != NULL)
      params->utils->free(ptr->result);

    ptr++;
  } while (ptr->id != SASL_CB_LIST_END);

  params->utils->free(prompts);
  prompts = NULL;
}

/*
 * Make the necessary prompts
 */

static int
make_prompts(sasl_client_params_t * params,
	     sasl_interact_t ** prompts_res,
	     int user_res, /* authorization id */
	     int auth_res, /* authentication id */
	     int pass_res,
	     int realm_res)
{
  int             num = 1;
  sasl_interact_t *prompts;

  if (auth_res == SASL_INTERACT) num++;
  if (user_res == SASL_INTERACT) num++;
  if (pass_res == SASL_INTERACT) num++;
  if (realm_res == SASL_INTERACT) num++;

  if (num == 1)
    return SASL_FAIL;

  prompts = params->utils->malloc(sizeof(sasl_interact_t) * num);
  if ((prompts) == NULL) return SASL_NOMEM;
  *prompts_res = prompts;

  if (auth_res == SASL_INTERACT) {
    /*
     * We weren't able to get the callback; let's try a SASL_INTERACT
     */
    (prompts)->id = SASL_CB_AUTHNAME;
    (prompts)->challenge = "Authentication Name";
    (prompts)->prompt = "Please enter your authentication name";
    (prompts)->defresult = NULL;

    VL(("authid callback added\n"));
    prompts++;
  }
  if (user_res == SASL_INTERACT) {
    /*
     * We weren't able to get the callback; let's try a SASL_INTERACT
     */
    (prompts)->id=SASL_CB_USER;
    (prompts)->challenge="Authorization Name";
    (prompts)->prompt="Please enter your authorization name";
    (prompts)->defresult=NULL;

    VL(("userid callback added\n"));
    prompts++;
  }
  if (pass_res == SASL_INTERACT) {
    /*
     * We weren't able to get the callback; let's try a SASL_INTERACT
     */
    (prompts)->id = SASL_CB_PASS;
    (prompts)->challenge = "Password";
    (prompts)->prompt = "Please enter your password";
    (prompts)->defresult = NULL;

    VL(("password callback added\n"));
    prompts++;
  }
  if (realm_res == SASL_INTERACT) {
      (prompts)->id = SASL_CB_GETREALM;
      /* xxx this leaks memory */
      if (params->serverFQDN==NULL)
      {
	(prompts)->challenge = "{}";
      } else {
	(prompts)->challenge = (char *) params->utils->malloc(3+strlen(params->serverFQDN));
	sprintf((char *) (prompts)->challenge,"{%s}",params->serverFQDN);
      }
	
      (prompts)->prompt = "Please enter your realm";
      (prompts)->defresult = NULL;

      VL(("realm callback added\n"));
  }
  /* add the ending one */
  (prompts)->id = SASL_CB_LIST_END;
  (prompts)->challenge = NULL;
  (prompts)->prompt = NULL;
  (prompts)->defresult = NULL;

  return SASL_OK;
}


static int
c_continue_step(void *conn_context,
		sasl_client_params_t * params,
		const char *serverin,
		int serverinlen,
		sasl_interact_t ** prompt_need,
		char **clientout,
		int *clientoutlen,
		sasl_out_params_t * oparams)
{
  char           *in = NULL;
  char           *in_start;
  context_t      *text;
  text = conn_context;

  /* check params */
  if (serverinlen < 0)
      return SASL_BADPARAM;

  if (!clientout && text->state == 1) {
      /* initial client challenge not allowed */
      text->state++;
      return SASL_CONTINUE;
  }

  *clientout = NULL;
  *clientoutlen = 0;

  if (text->state == 1) {
    VL(("Digest-MD5 Step 1\n"));

    /* here's where we'd attempt fast reauth if possible */
    /* if we can, then goto text->state=3!!! */

    *clientout = params->utils->malloc(1);	/* text->malloc(1); */
    if (!*clientout) {
	return SASL_NOMEM;
    }
    **clientout = '\0';
    *clientoutlen = 0;

    text->state = 2;
    return SASL_CONTINUE;
  }

  if (text->state == 2) {
    sasl_ssf_t limit, musthave = 0;
    sasl_ssf_t external;
    unsigned char  *digesturi = NULL;
    unsigned char  *nonce = NULL;
    unsigned char  *ncvalue = (unsigned char *) "00000001";
    unsigned char  *cnonce = NULL;
    char           *qop = NULL;
    char           *qop_list = NULL;
    int             protection = 0;
    char           *usecipher = NULL;
    int             ciphers=0;
    unsigned int    n = 0;
    char           *response = NULL;
    char          **realm = NULL;
    int             nrealm = 0;
    unsigned int    server_maxbuf = 65536; /* Default value for maxbuf */
    int             maxbuf_count = 0;
    bool            IsUTF8 = FALSE;
    char           *charset = NULL;
    int             result = SASL_FAIL;
    char           *client_response = NULL;
    int             user_result = SASL_OK;
    int             auth_result = SASL_OK;
    int             pass_result = SASL_OK;
    int            realm_result = SASL_OK;
    int            algorithm_count = 0;

    VL(("Digest-MD5 Step 2\n"));

    if (params->props.min_ssf > params->props.max_ssf) {
	return SASL_BADPARAM;
    }

    in = params->utils->malloc(serverinlen + 1);
    if (in == NULL) return SASL_NOMEM;

    memcpy(in, serverin, serverinlen);
    in[serverinlen] = 0;

    in_start = in;

    /* parse what we got */
    while (in[0] != '\0') {
	char *name, *value;

	get_pair(&in, &name, &value);

	/* if parse error */
	if (name == NULL) {
	    VL (("Parse error\n"));
	    result = SASL_FAIL;
	    goto FreeAllocatedMem;
	}

	VL(("received pair: %s - %s\n", name, value));

	if (strcasecmp(name, "realm") == 0) {
	    nrealm++;

	    realm = params->utils->realloc(realm, 
					   sizeof(char *) * (nrealm + 1));
	    if (realm == NULL) {
		result = SASL_NOMEM;
		goto FreeAllocatedMem;
	    }

	    digest_strdup(params->utils, value, &realm[nrealm-1], NULL);
	    realm[nrealm] = NULL;
	} else if (strcasecmp(name, "nonce") == 0) {
	    digest_strdup(params->utils, value, (char **) &nonce, NULL);
	} else if (strcasecmp(name, "qop") == 0) {
	    digest_strdup(params->utils, value, &qop_list, NULL);
	    while (value && *value) {
		char *comma = strchr(value, ',');
		if (comma != NULL) {
		    *comma++ = '\0';
		}

		if (strcasecmp(value, "auth-conf") == 0) {
		    VL(("Server supports privacy layer\n"));
		    protection |= DIGEST_PRIVACY;
		} else if (strcasecmp(value, "auth-int") == 0) {
		    VL(("Server supports integrity layer\n"));
		    protection |= DIGEST_INTEGRITY;
		} else if (strcasecmp(value, "auth") == 0) {
		    VL(("Server supports no layer\n"));
		    protection |= DIGEST_NOLAYER;
		} else {
		    VL(("Server supports unknown layer: %s\n", value));
		}

		value = comma;
	    }
	    
	    if (protection == 0) {
		result = SASL_BADAUTH;
		VL(("Server doesn't support known qop level\n"));
		goto FreeAllocatedMem;
	    }
	} else if (strcasecmp(name, "cipher") == 0) {
	    while (value && *value) {
		char *comma = strchr(value, ',');
		struct digest_cipher *cipher = available_ciphers;

		if (comma != NULL) {
		    *comma++ = '\0';
		}

		/* do we support this cipher? */
		while (cipher->name) {
		    if (!strcasecmp(value, cipher->name)) break;
		    cipher++;
		}
		if (cipher->name) {
			ciphers |= cipher->flag;
		} else {
		    VL(("Server supports unknown cipher: %s\n", value));
		}
		
		value = comma;
	    }
	} else if (strcasecmp(name, "stale") == 0) {
	    /* since we never fast reauth, this should fail */
	    result = SASL_BADAUTH;
	    goto FreeAllocatedMem;
	} else if (strcasecmp(name, "maxbuf") == 0) {
	    /* maxbuf A number indicating the size of the largest
	     * buffer the server is able to receive when using
	     * "auth-int". If this directive is missing, the default
	     * value is 65536. This directive may appear at most once;
	     * if multiple instances are present, the client should
	     * abort the authentication exchange.  
	     */
	    maxbuf_count++;

	    if (maxbuf_count != 1) {
		result = SASL_BADAUTH;
		VL(("At least two maxbuf directives found. Authentication aborted\n"));
		goto FreeAllocatedMem;
	    } else if (sscanf(value, "%u", &server_maxbuf) != 1) {
		result = SASL_BADAUTH;
		VL(("Invalid maxbuf parameter received from server\n"));
		goto FreeAllocatedMem;
	    } else {
		if (server_maxbuf<=16) {
		    result = SASL_BADAUTH;
		    VL(("Invalid maxbuf parameter received from server (too small)\n"));
		    goto FreeAllocatedMem;
		}
	    }
	} else if (strcasecmp(name, "charset") == 0) {
	    if (strcasecmp(value, "utf-8") != 0) {
		result = SASL_BADAUTH;
		VL(("Charset must be UTF-8\n"));
		goto FreeAllocatedMem;
	    } else {
		IsUTF8 = TRUE;
	    }
	} else if (strcasecmp(name,"algorithm")==0) {

	    VL (("Seeing algorithm now!\n"));

	  if (strcasecmp(value, "md5-sess") != 0)
	  {
	    VL(("'algorithm' isn't 'md5-sess'\n"));
	    result = SASL_FAIL;
	    goto FreeAllocatedMem;
	  }

	  algorithm_count++;
	  if (algorithm_count > 1)
	  {
	    VL(("Must see 'algorithm' only once\n"));
	    result = SASL_FAIL;
	    goto FreeAllocatedMem;
	  }
	} else {
	    VL(("unrecognized pair: ignoring\n"));
	}
    }

    if (algorithm_count != 1)
    {
      VL(("Must see 'algoirthm' once. Didn't see at all\n"));
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }

    /* make sure we have everything we require */
    if (nonce == NULL) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }

    /* make callbacks */

    /* try to get the userid */
    if (text->userid == NULL) {
      VL(("Trying to get authorization id\n"));
      user_result = get_userid(params,
			       (char **) &text->userid,
			       prompt_need);

      if ((user_result != SASL_OK) && (user_result != SASL_INTERACT))
      {
	result = user_result;
	goto FreeAllocatedMem;
      }
    }

    /* try to get the authid */
    if (text->authid == NULL) {
      VL(("Trying to get authentication id\n"));
      auth_result = get_authid(params,
			       (char **) &text->authid,
			       prompt_need);

      if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
      {
	result = auth_result;
	goto FreeAllocatedMem;
      }

    }
    /* try to get the password */
    if (text->password == NULL) {
      VL(("Trying to get password\n"));
      pass_result = get_password(params,
				 &text->password,
				 prompt_need);
      if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
      {
	result = pass_result;
	goto FreeAllocatedMem;
      }
    }
    /* try to get the realm, if needed */
    if (nrealm == 1 && text->realm == NULL) {
      /* only one choice! */
      VL(("Realm copying\n"));
      if (digest_strdup(params->utils, realm[0], 
			&text->realm, NULL) == SASL_NOMEM) {
	result = SASL_NOMEM;
	goto FreeAllocatedMem;
      }
    }
    if (text->realm == NULL) {
	VL(("Trying to get realm\n"));
	realm_result = c_get_realm(params, &text->realm, realm,
				   prompt_need);

	if ((realm_result != SASL_OK) && (realm_result != SASL_INTERACT)) {
	    result = realm_result;
	    goto FreeAllocatedMem;
	}
	/* if realm_result == SASL_OK, text->realm has been filled in */
    }

    /* free prompts we got */
    if (prompt_need)
      free_prompts(params, *prompt_need);


    /* if there are prompts not filled in */
    if ((user_result == SASL_INTERACT) ||
	(auth_result == SASL_INTERACT) ||
	(pass_result == SASL_INTERACT) ||
	(realm_result == SASL_INTERACT)) {
      int result;
      /* make the prompt list */
      result = make_prompts(params, prompt_need,
			    user_result, auth_result, pass_result,
			    realm_result);

      if (in_start) params->utils->free(in_start);
      if (nonce) params->utils->free(nonce);
      if (qop_list) params->utils->free(qop_list);
      if (realm)
      {
	  int lup;
	  
	  /* need to free all the realms */
	  for (lup=0;lup<nrealm;lup++)
	      params->utils->free(realm[lup]);
	  
	  params->utils->free(realm);
      }

      if (result != SASL_OK)
	return result;



      VL(("returning prompt(s)\n"));
      return SASL_INTERACT;
    }

    /*
     * (username | realm | nonce | cnonce | nonce-count | qop digest-uri |
      * response | maxbuf | charset | auth-param )
     */

    /* get requested ssf */
    external = params->external_ssf;

    /* what do we _need_?  how much is too much? */
    if (params->props.max_ssf > external) {
	limit = params->props.max_ssf - external;
    } else {
	limit = 0;
    }
    if (params->props.min_ssf > external) {
	musthave = params->props.min_ssf - external;
    } else {
	musthave = 0;
    }

    /* we now go searching for an option that gives us at least "musthave"
       and at most "limit" bits of ssf. */
    if ((limit > 1) && (protection & DIGEST_PRIVACY)) {
	struct digest_cipher *cipher, *bestcipher;

	/* let's find an encryption scheme that we like */
	cipher = available_ciphers;
	bestcipher = NULL;
	while (cipher->name) {
	    /* examine each cipher we support, see if it meets our security
	       requirements, and see if the server supports it.
	       choose the best one of these */
	    if ((limit >= cipher->ssf) && (musthave <= cipher->ssf) &&
		(ciphers & cipher->flag) &&
		(!bestcipher || (cipher->ssf > bestcipher->ssf))) {
		bestcipher = cipher;
	    }
	    cipher++;
	}

	if (bestcipher) {
	    /* we found a cipher we like */
	    oparams->encode = &privacy_encode; 
	    oparams->decode = &privacy_decode;
	    oparams->mech_ssf = bestcipher->ssf;

	    qop = "auth-conf";
	    n = bestcipher->n;
	    usecipher = bestcipher->name;
	    text->cipher_enc = bestcipher->cipher_enc;
	    text->cipher_dec = bestcipher->cipher_dec;
	    text->cipher_init = bestcipher->cipher_init;
	} else {
	    /* we didn't find any ciphers we like */
	    VL(("No good privacy layers\n"));
	    qop = NULL;
	}
    }

    if (qop==NULL) {
	/* we failed to find an encryption layer we liked;
	   can we use integrity or nothing? */

	if ((limit >= 1) && (musthave <= 1) 
	    && (protection & DIGEST_INTEGRITY)) {
	    /* integrity */
	    oparams->encode = &integrity_encode;
	    oparams->decode = &integrity_decode;
	    oparams->mech_ssf = 1;
	    qop = "auth-int";
	    VL(("Using integrity layer\n"));
	} else if (musthave <= 0) {
	    /* no layer */
	    oparams->encode = NULL;
	    oparams->decode = NULL;
	    oparams->mech_ssf = 0;
	    qop = "auth";
	    VL(("Using no layer\n"));
	    
	    /* See if server supports not having a layer */
	    if ((protection & DIGEST_NOLAYER) != DIGEST_NOLAYER) {
		VL(("Server doesn't support \"no layer\"\n"));
		result = SASL_FAIL;
		goto FreeAllocatedMem;
	    }
	} else {
	    VL(("Can't find an acceptable layer\n"));
	    result = SASL_TOOWEAK;
	    goto FreeAllocatedMem;
	}
    }

    /* get nonce XXX have to clean up after self if fail */
    cnonce = create_nonce(params->utils);
    if (cnonce == NULL) {
      VL(("failed to create cnonce\n"));
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    /* XXX nonce count */

    digesturi = params->utils->malloc(strlen(params->service) + 1 +
				      strlen(params->serverFQDN) + 1 +
				      1);
    if (digesturi == NULL) {
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
    };

    /* allocated exactly this. safe */
    strcpy((char *) digesturi, params->service);
    strcat((char *) digesturi, "/");
    strcat((char *) digesturi, params->serverFQDN);
    /*
     * strcat (digesturi, "/"); strcat (digesturi, params->serverFQDN);
     */

    if ((text->authid!=NULL) && !strcmp((const char *) text->authid,(const char *) text->userid)) {
	if (text->userid) {
	    params->utils->free(text->userid);
	    text->userid = NULL;
	}
    }

    /* response */
    response = calculate_response(text,
				  params->utils,
				  text->authid,
				  (unsigned char *) text->realm,
				  nonce,
				  ncvalue,
				  cnonce,
				  qop,
				  digesturi,
				  text->password,
				  text->userid, /* authorization_id */
				  &text->response_value);

    VL(("Constructing challenge\n"));

    if (add_to_challenge(params->utils, &client_response, 
			 "username", text->authid, TRUE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils, &client_response, 
		 "realm", (unsigned char *) text->realm, TRUE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (text->userid != NULL) {
      if (add_to_challenge(params->utils, &client_response, 
			   "authzid", text->userid, TRUE) != SASL_OK) {
        result = SASL_FAIL;
        goto FreeAllocatedMem;
      }
    }
    if (add_to_challenge(params->utils, &client_response, "nonce", nonce, TRUE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils, &client_response, "cnonce", cnonce, TRUE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils, &client_response, "nc", ncvalue, FALSE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils, &client_response, "qop", (unsigned char *) qop, FALSE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (usecipher!=NULL)
      if (add_to_challenge(params->utils, &client_response, "cipher", 
			   (unsigned char *) usecipher, TRUE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
      }

    if (IsUTF8) {
      if (add_to_challenge(params->utils, &client_response, "charset", (unsigned char *) "utf-8", FALSE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
      }
    }
    if (add_to_challenge(params->utils, &client_response, "digest-uri", digesturi, TRUE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils, &client_response, "response", (unsigned char *) response, FALSE) != SASL_OK) {

      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    VL(("adding things\n"));

    *clientout = client_response;
    *clientoutlen = strlen(client_response);
    if (*clientoutlen > 2048) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }

    if (digest_strdup(params->utils, text->realm, 
		      &oparams->realm, NULL) == SASL_NOMEM) {
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
    }

    if (! text->userid || !*(text->userid))
      text->userid = text->authid;
    if (digest_strdup(params->utils, (char *) text->userid, &
		      oparams->user, NULL) == SASL_NOMEM) {
      params->utils->free(oparams->realm);
      oparams->realm = NULL;
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
    }
    if (digest_strdup(params->utils, (char *) text->authid, 
		      &oparams->authid, NULL) == SASL_NOMEM) {
      params->utils->free(oparams->realm);
      oparams->realm = NULL;
      params->utils->free(oparams->user);
      oparams->user = NULL;
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
    }

    /* set oparams */
    oparams->doneflag = 1;
    oparams->maxoutbuf = server_maxbuf;
    oparams->param_version = 0;

    text->seqnum = 0;		/* for integrity/privacy */
    text->rec_seqnum = 0;	/* for integrity/privacy */
    text->hmac_md5 = params->utils->hmac_md5;
    text->malloc = params->utils->malloc;
    text->free = params->utils->free;

    text->maxbuf = server_maxbuf;

    /* used by layers */
    text->size = -1;
    text->needsize = 4;
    text->buffer = NULL;

    {
      char enckey[16];
      char deckey[16];
      
      create_layer_keys(text, params->utils,text->HA1,n,enckey,deckey);

      /* initialize cipher if need be */
      if (text->cipher_init != NULL)
      {
	text->cipher_init(text, params->utils,
			  enckey,deckey);		       
      }
    }

    result = SASL_CONTINUE;

    text->state = 3;

FreeAllocatedMem:
    if (response) { params->utils->free(response); }
    if (text->password) { params->utils->free(text->password); }
    if (in_start) { params->utils->free(in_start); }

    if (realm)
    {
      int lup;

      /* need to free all the realms */
      for (lup=0;lup<nrealm;lup++)
	params->utils->free(realm[lup]);

      params->utils->free(realm);
    }

    if (nonce) { params->utils->free(nonce); }

    if (charset) { params->utils->free(charset); }
    if (digesturi) { params->utils->free(digesturi); }
    if (cnonce) { params->utils->free(cnonce); }

    if (qop_list!=NULL)
    {
      params->utils->free(qop_list);
    }

    if ((result != SASL_CONTINUE) && (client_response))
	params->utils->free(client_response);

    VL(("All done. exiting DIGEST-MD5\n"));

    return result;
 }

  if (text->state == 3) {	
     /* Verify that server is really what he claims to be */

    VL(("Digest-MD5: In Reauth state\n"));

    in = params->utils->malloc(serverinlen + 1);
    if (in == NULL) return SASL_NOMEM;
    memcpy(in, serverin, serverinlen);
    in[serverinlen] = 0;

    in_start = in;

    /* parse what we got */
    while (in[0] != '\0') {
      char           *name, *value;
      get_pair(&in, &name, &value);

      if (name == NULL)
      {
	  VL (("Received garbage\n"));
	  params->utils->free(in_start);
	  return SASL_FAIL;
      }

      VL(("received pair: %s - %s\n", name, value));

      if (strcasecmp(name, "rspauth") == 0) {

	if (strcmp(text->response_value, value) != 0) {
	  VL(("This server wants us to believe that he knows shared secret\n"));
	  params->utils->free(in_start);
	  return SASL_FAIL;
	} else {
	  VL(("Ok I think we can re-auth\n"));
	  params->utils->free(in_start);

 	  *clientout = params->utils->malloc(1);
	  (*clientout)[0] = '\0';
	  *clientoutlen = 0;
	  text->state = 4;
	  return SASL_CONTINUE;
	}
      } else {
	VL(("unrecognized pair: ignoring\n"));
      }
    }

    params->utils->free(in_start);

    return SASL_FAIL;
  }

  /* xxx note: this state is for compatability reasons. will be elimated in sasl 2.0 */
  if (text->state == 4)
  {
      *clientout = NULL;
      *clientoutlen = 0;
      VL(("Verify we're done step"));
      text->state++;
      return SASL_OK;      
  }


  return SASL_FAIL;		/* should never get here */
}

static const long client_required_prompts[] = {
  SASL_CB_AUTHNAME,
  SASL_CB_PASS,
  SASL_CB_GETREALM,
  SASL_CB_LIST_END
};


const sasl_client_plug_t client_plugins[] =
{
  {
    "DIGEST-MD5",
#ifdef WITH_RC4
    128,				/* max ssf */
#elif WITH_DES
    112,
#else
    0,
#endif
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS,
    client_required_prompts,
    NULL,
    &c_start,
    &c_continue_step,
    &dispose,
    &mech_free,
    NULL,
    NULL
  }
};

int             sasl_client_plug_init(sasl_utils_t * utils __attribute__((unused)),
				      int maxversion,
				      int *out_version,
				      const sasl_client_plug_t ** pluglist,
				      int *plugcount) {
  if (maxversion < DIGEST_MD5_VERSION)
    return SASL_BADVERS;

  *pluglist = client_plugins;

  *plugcount = 1;
  *out_version = DIGEST_MD5_VERSION;

  return SASL_OK;
}
