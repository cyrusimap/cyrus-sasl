/*
 * Digest MD5 SASL plugin Tim Martin, Alexey Melnikov
 */
/***********************************************************
        Copyright 1998-1999 by Alexey Melnikov and
        Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

#define IM_BROKEN		/* integrity/encryption are very broken
				   in this implementation */

#include <config.h>
//#include <des.h> //moved below for win32 since it clobbers definitions in stdio.h
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef WIN32
# include <winsock.h>
#else /* Unix */
# include <netinet/in.h>
#endif /* WIN32 */

#ifdef WITH_RC4
#include <rc4.h>
#endif /* WITH_RC4 */

#include <des.h>

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

#ifdef L_DEFAULT_GUARD
#undef L_DEFAULT_GUARD
#define L_DEFAULT_GUARD (1)
#endif

/* external definitions */

#ifdef sun
/* gotta define gethostname ourselves on suns */
extern int      gethostname(char *, int);
#endif


#define bool int

#define TRUE  1
#define FALSE 0

#include <assert.h>

/* defines */
#define HASHLEN 16
typedef unsigned char HASH[HASHLEN + 1];
#define HASHHEXLEN 32
typedef unsigned char HASHHEX[HASHHEXLEN + 1];


#define CIPHER_DES   2
#define CIPHER_3DES  4
#define CIPHER_RC4   8
#define CIPHER_RC440 16
#define CIPHER_RC456 32  /* xxx this still here? */

#ifdef DIGEST_DRAFT_2
#define MAC_SIZE 8
#else
#define MAC_SIZE 10
#endif

#define SEALING_CLIENT_SERVER "Digest H(A1) to client-to-server sealing key magic constant"
#define SEALING_SERVER_CLIENT "Digest H(A1) to server-to-client sealing key magic constant"

#define SIGNING_CLIENT_SERVER "Digest session key to client-to-server signing key magic constant"
#define SIGNING_SERVER_CLIENT "Digest session key to server-to-client signing key magic constant"

#define SERVER 0
#define CLIENT 1

/* function definitions for cipher encode/decode */
typedef int cipher_function_t(void *,
			      const char *,
			      unsigned,
			      char **,
			      unsigned *);

typedef int cipher_init_t(void *, sasl_utils_t *,
			  char *, int);

/* context that stores info */
typedef struct context {
  int             state;	/* state in the authentication we are in */
  int i_am;			/* are we the client or server? */

  unsigned char  *nonce;
  int             noncelen;

  int             last_ncvalue;

  char           *response_value;

  char           *realm;

  unsigned int    seqnum;
  unsigned int    rec_seqnum;	/* for checking integrity */

  HASH            Ki;		/* Kic or Kis */

  HASH            Kc;		/* Kcc or Kcs */

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

  unsigned char  *authid;
  sasl_secret_t  *password;

  /* if privacy mode is used use these functions for encode and decode */
  cipher_function_t *cipher_enc;
  cipher_function_t *cipher_dec;
  cipher_init_t *cipher_init;

  des_key_schedule keysched_enc;   /* key schedule for des initialization */
  des_key_schedule keysched_dec;   /* key schedule for des initialization */

  des_key_schedule keysched_enc2;   /* key schedule for 3des initialization */
  des_key_schedule keysched_dec2;   /* key schedule for 3des initialization */

#ifdef WITH_RC4
  rc4_context_t *rc4_enc_context;
  rc4_context_t *rc4_dec_context;
#endif /* WITH_RC4 */
} context_t;

/* this is from the rpc world */
#define IN
#define OUT


static int      htoi(unsigned char *hexin, int *res);

#define DIGESTMD5_VERSION (3)
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
  /* if we found a character outside 8859-1, don't alter string */
  if (scan < end) {
    return FALSE;
  } else {
    return TRUE;
  }

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
  for (scan = base; scan < end; ++scan) {
    if (*scan > 0xC3)
      break;			/* abort if outside 8859-1 */
    if (*scan >= 0xC0 && *scan <= 0xC3) {
      if (++scan == end || *scan < 0x80 || *scan > 0xBF)
	break;
    }
  }
  /* if we found a character outside 8859-1, don't alter string */
  if (In_ISO_8859_1 == FALSE) {
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

  /* figure out if name and password are in 8859 */
  In_8859_1 = UTF8_In_8859_1(pszUserName, strlen((char *) pszUserName)) &&
    UTF8_In_8859_1(Password, PasswordLen);

  /* We have to convert UTF-8 to ISO-8859-1 if possible */
  MD5_UTF8_8859_1(utils, &Md5Ctx, In_8859_1,
		  pszUserName, strlen((char *) pszUserName));

  utils->MD5Init(&Md5Ctx);

  MD5_UTF8_8859_1(utils, &Md5Ctx, In_8859_1,
		  pszUserName, strlen((char *) pszUserName));

  utils->MD5Update(&Md5Ctx, COLON, 1);
  utils->MD5Update(&Md5Ctx, pszRealm, strlen((char *) pszRealm));
  utils->MD5Update(&Md5Ctx, COLON, 1);

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
	      IN unsigned char *pszNonce,
	      IN unsigned char *pszCNonce,
	      IN unsigned char *pszMagic_i,	/* Magic constant used to
						 * create Kic or Kis */
	      IN unsigned char *pszMagic_c,	/* Magic constant used to
						 * create Kcc or Kcs */
	      IN unsigned int  n,         /* number of bits to use for the
					     privacy key */
	      OUT HASHHEX SessionKey)
{
  MD5_CTX         Md5Ctx;
  HASH            HA1;

  DigestCalcSecret(utils,
		   pszUserName,
		   pszRealm,
		   pszPassword->data,
		   pszPassword->len,
		   HA1);

  VL(("HA1 is \"%s\"\r\n", HA1));

  /* calculate the session key */
  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, HA1, HASHLEN);
  utils->MD5Update(&Md5Ctx, COLON, 1);
  utils->MD5Update(&Md5Ctx, pszNonce, strlen((char *) pszNonce));
  utils->MD5Update(&Md5Ctx, COLON, 1);
  utils->MD5Update(&Md5Ctx, pszCNonce, strlen((char *) pszCNonce));
  utils->MD5Final(HA1, &Md5Ctx);

  CvtHex(HA1, SessionKey);

  /* for integrity protection calc Kic = MD5(H(A1),"session key") */
  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, HA1, HASHLEN);
  utils->MD5Update(&Md5Ctx, pszMagic_i, strlen((char *) pszMagic_i));
  utils->MD5Final(text->Ki, &Md5Ctx);
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
  if (strcasecmp((char *) pszQop, "auth-int") == 0) {
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
		   unsigned char *username,
		   unsigned char *realm,
		   unsigned char *nonce,
		   unsigned char *ncvalue,
		   unsigned char *cnonce,
		   char *qop,
		   unsigned char *digesturi,
		   sasl_secret_t * passwd,
		   IN unsigned char *magic_i,	/* Magic constant used to
						 * create Kic or Kis */
		   IN unsigned char *magic_c,	/* Magic constant used to
						 * create Kcc or Kcs */
		   IN unsigned int n, /* number of bits to use for privacy key */
		   OUT char **response_value)
{
  HASHHEX         SessionKey;
  HASHHEX         HEntity = "00000000000000000000000000000000";
  HASHHEX         Response;
  char           *result;

  /* Verifing that all parameters was defined */
  assert(username != NULL);
  assert(realm != NULL);
  assert(nonce != NULL);
  assert(cnonce != NULL);

  assert(ncvalue != NULL);
  assert(digesturi != NULL);

  assert(passwd != NULL);

  if (qop == NULL)
    qop = "auth";

  VL(("calculate_response assert passed\n"));

  DigestCalcHA1(text,
		utils,
		username,
		realm,
		passwd,
		nonce,
		cnonce,
		magic_i,
		magic_c,
		n,
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
			IN unsigned char *pszNonce,
			IN unsigned char *pszCNonce,
			IN unsigned char *pszMagic_i,	/* Magic constant used
							 * to create Kic or Kis */
			IN unsigned char *pszMagic_c,	/* Magic constant used
							 * to create Kic or Kis */
			IN unsigned int n, /* number of bits to use for privacy key */
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
  utils->MD5Final(HA1, &Md5Ctx);

  CvtHex(HA1, SessionKey);


  /* for integrity protection calc Kis = MD5(H(A1),"session key") */
  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, HA1, HASHLEN);
  utils->MD5Update(&Md5Ctx, pszMagic_i, strlen((char *) pszMagic_i));
  utils->MD5Final(text->Ki, &Md5Ctx);
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
		IN unsigned char *magici,	/* Magic constant used to
						 * create Kic or Kis */
		IN unsigned char *magicc,	/* Magic constant used to
						 * create Kcc or Kcs */
		IN unsigned int n,  /* number of bits used for privacy key */
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
			  nonce,
			  cnonce,
			  magici,
			  magicc,
			  n,
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

void
get_pair(char **in, char **name, char **value)
{
  char           *endvalue;
  char           *endpair;
  char           *curp = *in;
  *name = NULL;
  *value = NULL;

  if (curp == NULL) {
      *name = NULL;
      return;
  }
  if (curp[0] == '\0') {
      *name = NULL;
      return;
  }

  /* skipping spaces: */
  while (curp[0] == ' ')
    curp++;

  *name = curp;

  *value = strchr(*name, '=');
  if (*value == NULL) {
      *name = NULL;
      return;
  }
  (*value)[0] = '\0';
  (*value)++;

  if (**value == '"') {
    (*value)++;
    endvalue = strchr(*value, '"');
    endvalue[0] = '\0';
    endvalue++;
  } else {
    endvalue = *value;
  }

  endpair = strchr(endvalue, ',');
  if (endpair == NULL) {
    endpair = strend(endvalue);
  } else {
    endpair[0] = '\0';
    endpair++;			/* skipping <,> */
  }

  *in = endpair;
}

/* copy a string */
static int
digest_strdup(sasl_utils_t * utils, const char *in, char **out, int *outlen)
{
  size_t          len = strlen(in);
  if (outlen)
    *outlen = len;

  *out = utils->malloc(len + 1);
  if (!*out)
    return SASL_NOMEM;

  strcpy((char *) *out, in);
  return SASL_OK;
}

/******************************
 *
 * 3DES functions
 *
 *****************************/

static int dec_3des(context_t *text,
		   const char *input,
		   unsigned inputlen,
		   char **output,
		   unsigned *outputlen)
{
  int len;
  int lup;

  if (inputlen%8==0)
    len=inputlen;
  else
    len=((inputlen/8)+1)*8; /* des encrpytes 8 bytes chunks */

  *output = (char *) text->malloc(len);
  if (*output==NULL) return SASL_NOMEM;
  memset(*output, 0, len);
  *outputlen=inputlen;  

  for (lup=0;lup<len;lup+=8)
  {
    /* decrypt with 1st key */
    des_ecb_encrypt((des_cblock *)(input+lup),
		    (des_cblock *) ((*output)+lup),
		    text->keysched_dec,
		    DES_DECRYPT);

    /* encrypt with 2nd key */
    des_ecb_encrypt((des_cblock *) ((*output)+lup),
		    (des_cblock *) ((*output)+lup),
		    text->keysched_dec2,
		    DES_ENCRYPT);

    /* decrypt with 1st key */
    des_ecb_encrypt((des_cblock *) ((*output)+lup),
		    (des_cblock *) ((*output)+lup),
		    text->keysched_dec,
		    DES_DECRYPT);

  }

  while( (*output)[(*outputlen)-1]==0)
    (*outputlen)--;

  return SASL_OK;
}

int enc_3des(struct context *text,
	     const char *input,
	     unsigned inputlen,
	     char **output,
	     unsigned *outputlen)
{
  int len;
  int lup;
  char last[8];

  if (inputlen%8==0)
    len=inputlen;
  else
    len=((inputlen/8)+1)*8; /* des encrpytes 8 bytes chunks */

  for (lup=0;lup<len;lup+=8)
  {
    if (inputlen-lup<8)
    {
      memset(last,0,8);
      memcpy(last,input+lup,inputlen-lup);
      /* encrpyt with 1st key */
      des_ecb_encrypt((des_cblock *) last,
		      (des_cblock *) ((*output)+lup),
		      text->keysched_enc,
		      DES_ENCRYPT);
    } else {
      /* encrpyt with 1st key */
      des_ecb_encrypt((des_cblock *)(input+lup),
		      (des_cblock *) ((*output)+lup),
		      text->keysched_enc,
		      DES_ENCRYPT);
    }

    /* decrpyt with 2nd key */
    des_ecb_encrypt((des_cblock *) ((*output)+lup),
		    (des_cblock *) ((*output)+lup),
		    text->keysched_enc2,
		    DES_DECRYPT);
    /* encrpyt with 1st key */
    des_ecb_encrypt((des_cblock *) ((*output)+lup),
		    (des_cblock *) ((*output)+lup),
		    text->keysched_enc,
		    DES_ENCRYPT);
  }

  *outputlen=len;

  return SASL_OK;
}

static int init_3des(context_t *text, sasl_utils_t *utils, 
		     char *key, int keylen)
{
    char enckey[16];
    char deckey[16];
    MD5_CTX Md5Ctx;
    
    if (text == NULL) return SASL_BADPARAM;
    if (key == NULL) return SASL_BADPARAM;
    
    VL(("initializing 3des\n"));
  
    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, key, keylen);
    if (text->i_am == SERVER) {
	utils->MD5Update(&Md5Ctx, SEALING_SERVER_CLIENT, 
			 strlen(SEALING_SERVER_CLIENT));
    } else {
	utils->MD5Update(&Md5Ctx, SEALING_CLIENT_SERVER,
			 strlen(SEALING_SERVER_CLIENT));
    }
    utils->MD5Final(enckey, &Md5Ctx);
    
    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, key, keylen);
    if (text->i_am == SERVER) {
	utils->MD5Update(&Md5Ctx, SEALING_CLIENT_SERVER, 
			 strlen(SEALING_CLIENT_SERVER));
    } else {
	utils->MD5Update(&Md5Ctx, SEALING_SERVER_CLIENT,
			 strlen(SEALING_CLIENT_SERVER));
    }
    utils->MD5Final(deckey, &Md5Ctx);
    
    des_key_sched((des_cblock *) enckey, text->keysched_enc);
    des_key_sched((des_cblock *) deckey, text->keysched_dec);
    
    des_key_sched((des_cblock *) (enckey+7), text->keysched_enc2);
    des_key_sched((des_cblock *) (deckey+7), text->keysched_dec2);

    return SASL_OK;
}


/******************************
 *
 * DES functions
 *
 *****************************/

static int dec_des(context_t *text,
		   const char *input,
		   unsigned inputlen,
		   char **output,
		   unsigned *outputlen)
{
  int len;
  int lup;

  if (inputlen%8==0)
    len=inputlen;
  else
    len=((inputlen/8)+1)*8; /* des encrpytes 8 bytes chunks */

  *output = (char *) text->malloc(len);
  if (*output==NULL) return SASL_NOMEM;
  memset(*output, 0, len);
  *outputlen=inputlen;  

  for (lup=0;lup<len;lup+=8)
  {
    /* decrypt with 1st key */
    des_ecb_encrypt((des_cblock *)(input+lup),
		    (des_cblock *) ((*output)+lup),
		    text->keysched_dec,
		    DES_DECRYPT);
  }

  /* HOW CAN WE STRIP OFF THE PADDING?!?!? */

  return SASL_OK;
}

static int enc_des(context_t *text,
		   const char *input,
		   unsigned inputlen,
		   char **output,
		   unsigned *outputlen)
{
  int len;
  int lup;
  char last[8];

  if (inputlen%8==0)
    len=inputlen;
  else
    len=((inputlen/8)+1)*8; /* des encrpytes 8 bytes chunks */

  for (lup=0;lup<len;lup+=8)
  {
    if (inputlen-lup<8)
    {
      memset(last,8-(inputlen-lup),8); /* "padding prefix is one or more 
					  octets each containing 
					  the number of padding bytes" */
      memcpy(last,input+lup,inputlen-lup);
      /* encrpyt with 1st key */
      des_ecb_encrypt((des_cblock *) last,
		      (des_cblock *) ((*output)+lup),
		      text->keysched_enc,
		      DES_ENCRYPT);
    } else {
      /* encrpyt with 1st key */
      des_ecb_encrypt((des_cblock *)(input+lup),
		      (des_cblock *) ((*output)+lup),
		      text->keysched_enc,
		      DES_ENCRYPT);
    }

  }

  *outputlen=len;

  return SASL_OK;
}

static int init_des(context_t *text, sasl_utils_t *utils,
		    char *key, int keylen)
{
    char enckey[16];
    char deckey[16];
    MD5_CTX Md5Ctx;
    
    if (text == NULL) return SASL_BADPARAM;
    if (key == NULL) return SASL_BADPARAM;
    
    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, key, keylen);
    if (text->i_am == SERVER) {
	utils->MD5Update(&Md5Ctx, SEALING_SERVER_CLIENT, 
			 strlen(SEALING_SERVER_CLIENT));
    } else {
	utils->MD5Update(&Md5Ctx, SEALING_CLIENT_SERVER,
			 strlen(SEALING_SERVER_CLIENT));
    }
    utils->MD5Final(enckey, &Md5Ctx);
    
    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, key, keylen);
    if (text->i_am == SERVER) {
	utils->MD5Update(&Md5Ctx, SEALING_CLIENT_SERVER, 
			 strlen(SEALING_CLIENT_SERVER));
    } else {
	utils->MD5Update(&Md5Ctx, SEALING_SERVER_CLIENT,
			 strlen(SEALING_CLIENT_SERVER));
    }
    utils->MD5Final(deckey, &Md5Ctx);
    
    VL(("initializing DES\n"));
    
    des_key_sched((des_cblock *) enckey, text->keysched_enc);
    des_key_sched((des_cblock *) deckey, text->keysched_dec);
    
    return SASL_OK;
}

#ifdef WITH_RC4
static int
init_rc4(void *v, sasl_utils_t *utils,
	 char *key, int keylen)
{
  context_t *text = (context_t *) v;
  char enckey[16];
  char deckey[16];
  MD5_CTX Md5Ctx;

  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, key, keylen);
  if (text->i_am == SERVER) {
      utils->MD5Update(&Md5Ctx, SEALING_SERVER_CLIENT, 
		       strlen(SEALING_SERVER_CLIENT));
  } else {
      utils->MD5Update(&Md5Ctx, SEALING_CLIENT_SERVER,
		       strlen(SEALING_SERVER_CLIENT));
  }
  utils->MD5Final(enckey, &Md5Ctx);

  utils->MD5Init(&Md5Ctx);
  utils->MD5Update(&Md5Ctx, key, keylen);
  if (text->i_am == SERVER) {
      utils->MD5Update(&Md5Ctx, SEALING_CLIENT_SERVER, 
		       strlen(SEALING_CLIENT_SERVER));
  } else {
      utils->MD5Update(&Md5Ctx, SEALING_SERVER_CLIENT,
		       strlen(SEALING_CLIENT_SERVER));
  }
  utils->MD5Final(deckey, &Md5Ctx);

  text->rc4_enc_context=(rc4_context_t *) text->malloc(sizeof(rc4_context_t));
  if (text->rc4_enc_context==NULL) return SASL_NOMEM;

  text->rc4_dec_context=(rc4_context_t *) text->malloc(sizeof(rc4_context_t));
  if (text->rc4_dec_context==NULL) return SASL_NOMEM;

  rc4_init(text->rc4_enc_context, enckey, 16);
  rc4_init(text->rc4_dec_context, deckey, 16);

  return SASL_OK;
}

static int
dec_rc4(context_t *text,
	const char *input,
	unsigned inputlen,
	char **output,
	unsigned *outputlen)
{
  *output = (char *) text->malloc(inputlen);
  if (*output == NULL) return SASL_NOMEM;
  *outputlen = inputlen;
  rc4_decrypt(text->rc4_dec_context, input, *output, inputlen);
  return SASL_OK;
}

static int
enc_rc4(context_t *text,
	const char *input,
	unsigned inputlen,
	char **output,
	unsigned *outputlen)
{
  *outputlen = inputlen;
  rc4_encrypt(text->rc4_enc_context, input, *output, inputlen);
  return SASL_OK;
}

#else

static int
init_rc4(void *v, sasl_utils_t *utils, char *key, int keylen)
{
    return SASL_FAIL;
}

static int
dec_rc4(context_t *text,
	const char *input,
	unsigned inputlen,
	char **output,
	unsigned *outputlen)
{
    return SASL_FAIL;
}

static int
enc_rc4(context_t *text,
	const char *input,
	unsigned inputlen,
	char **output,
	unsigned *outputlen)
{
    return SASL_FAIL;
}

#endif /* WITH_RC4 */

static unsigned int version = 1;

static int
privacy_encode(void *context,
	       const char *input,
	       unsigned inputlen,
	       char **output,
	       unsigned *outputlen)
{
  context_t      *text = (context_t *) context;
  int tmp;
  int tmpnum;
  char *out;
  unsigned char   digest[16];
  char *param2;

  *output = (char *) text->malloc(4+ /* for length */
				  inputlen+7+ /* for encrypted text */
				  16+ /* for MAC */
				  10); /* for padding */
  if (*output==NULL) return SASL_NOMEM;



  /* put the encrpyed text in */
  out=(*output)+4;
  
  text->cipher_enc(text,input,inputlen,
		   &out,outputlen);
  out+=(*outputlen);

  /* copy in version */
  tmpnum = htonl(version);
  memcpy(out, &tmpnum, 4);	/* 4 bytes = version */  
  out+=4;

  /* construct (seqnum, msg) */
  param2 = (unsigned char *) text->malloc(inputlen + 4);
  if (param2 == NULL) return SASL_NOMEM;

  tmpnum = htonl(text->seqnum);
  memcpy(param2, &tmpnum, 4);
  memcpy(param2 + 4, input, inputlen);


  /* HMAC(ki, (seqnum, msg) ) */
  text->hmac_md5(text->Ki, HASHLEN,
		 param2, inputlen + 4, digest);

  text->free(param2);

  /* MAC foo */
  text->cipher_enc(text, digest, MAC_SIZE,
		   &out, &tmpnum);

  out+=MAC_SIZE;

  /* put in seqnum */
  tmpnum = htonl(text->seqnum);
  memcpy(out, &tmpnum, 4);	/* 4 bytes = version */  

  (*outputlen)+=16; /* for CMAC */

  
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
    unsigned char *macmid;
    int tmpnum;
    int lup;
    unsigned char *tmpbuf;

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
	if (text->size>0xFFFFFF) return SASL_FAIL; /* too big probably error */
	
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

    result=text->cipher_dec(text,text->buffer,text->size-16,
		     output,outputlen);
  
    if (result!=SASL_OK)
    {
      text->free(text->buffer);
      return result;
    }

    /* check the CMAC */

    /* xxx check version number */

    /* construct (seqnum, msg) */
    param2 = (unsigned char *) text->malloc((*outputlen) + 4);
    if (param2 == NULL) return SASL_NOMEM;
    tmpnum = htonl(text->rec_seqnum);
    memcpy(param2, &tmpnum, 4);
    memcpy(param2 + 4, *output, *outputlen);

    /* HMAC(ki, (seqnum, msg) ) */
    text->hmac_md5(text->Ki, HASHLEN,
		   param2, (*outputlen) + 4, digest);

    text->free(param2);




    /* MAC foo */

    /* this sucks. we want to encode but we want to use rc4's decode sbox's 
     * so stuff doesn't get out of sync 
     */
#if HAVE_RC4
    if (text->cipher_init==(&init_rc4))
#else
    if (0)
#endif
    {
      text->cipher_dec(text, digest, MAC_SIZE,
		       (char **) &macmid, &tmpnum);
    } else { /* else is DES */
      macmid=(char *)malloc(MAC_SIZE+12);
      text->cipher_enc(text, digest, MAC_SIZE,
		       (char **) &macmid, &tmpnum);
    }
  /*    text->cipher_dec(text, (text->buffer)+text->size-(MAC_SIZE+4), MAC_SIZE,
	(char **) &macmid, &tmpnum);*/

      /*      printf("%i. %i %i\n",lup,macmid[lup],((unsigned char *)(text->buffer)+text->size-(MAC_SIZE+4))[lup]);*/

  tmpbuf=((unsigned char *)(text->buffer)+text->size-(MAC_SIZE+4));

  for (lup=0;lup<MAC_SIZE;lup++) /*     printf("%i %i %i\n",lup,macmid[lup],tmpbuf[lup]);
				  */
    if (macmid[lup]!=tmpbuf[lup])
    {
      text->free(macmid);
      VL(("CMAC doesn't match!\n"));
      return SASL_FAIL;
    }
    
    text->free(macmid);
    text->free(text->buffer);

    text->size=-1;
    text->needsize=4;
    text->rec_seqnum++;

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
  char            MAC[16];
  unsigned char   digest[16];
  unsigned char  *param2;
  unsigned int    tmpnum;
  context_t      *text = (context_t *) context;

  assert(text->maxbuf > 0);
  assert(inputlen > 0);


  param2 = (unsigned char *) text->malloc(inputlen + 4);
  if (param2 == NULL)
    return SASL_NOMEM;

  /* construct (seqnum, msg) */
  tmpnum = htonl(text->seqnum);
  memcpy(param2, &tmpnum, 4);
  memcpy(param2 + 4, input, inputlen);

  /* HMAC(ki, (seqnum, msg) ) */
  text->hmac_md5(text->Ki, HASHLEN,
		 param2, inputlen + 4, digest);


  /* create MAC */
  tmpnum = htonl(version);
#ifdef DIGEST_DRAFT_2
  memcpy(MAC, &tmpnum, 4);	/* 4 bytes = version */
#else
  memcpy(MAC, &tmpnum, 2);	/* 2 bytes = version */
#endif
  /* xxx i think this is wrong */
  memcpy(MAC + 4, digest, MAC_SIZE);	/* n bytes = first n bytes of the hmac */
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
	   char MAC[16])
{
  unsigned char   digest[16];
  unsigned char  *param2;
  unsigned int    tmpnum;

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
  text->hmac_md5(text->Ki, HASHLEN,
		 param2, inputlen + 4, digest);


  /* create MAC */
  tmpnum = htonl(version);
#ifdef DIGEST_DRAFT_2
  memcpy(MAC, &tmpnum, 4);	/* 4 bytes = version */
  memcpy(MAC + 4, digest, 8);	/* 8 bytes = first 8 bytes of the hmac */
#else
  memcpy(MAC, &tmpnum, 2);	/* 2 bytes = version */
  memcpy(MAC + 2, digest, 10);	/* 10 bytes = first 10 bytes of the hmac */
#endif

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
  char            MAC[16];
  int             result;

  /*
   * for (lup=0;lup<bufsize;lup++) printf("%i buf %i\n",lup,buf[lup]);
   */

  result = create_MAC(text, buf, bufsize - 16, text->rec_seqnum, MAC);
  if (result != SASL_OK)
    return result;

  /* make sure the MAC is right */
  if (strncmp(MAC, buf + bufsize - 16, 16) != 0)
    return SASL_FAIL;

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

      if (text->size > 0xFFFF)
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

    text->i_am = SERVER;
    text->state = 1;
    text->cipher_init=NULL;
    *conn = text;

    return SASL_OK;
}

static void
dispose(void *conn_context, sasl_utils_t * utils)
{

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
  if (params->user_realm != NULL)
  {
    *realm = (char *) params->user_realm;  

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

  if (text->state == 1) {
    char           *challenge = NULL;
    char           *realm;
    unsigned char  *nonce;
    char           *qop = "auth,auth-int,auth-conf";
#ifdef WITH_RC4
    char           *cipheropts="3des,des,rc4,rc4-40,rc4-56";
#else
    char           *cipheropts="3des,des";
#endif
    char           *charset = "utf-8";
    /* char *algorithm="md5-sess"; */

    /*
     * digest-challenge  = 1#( realm | nonce | qop-options | stale | maxbuf |
     * charset | cipher-opts | auth-param )
     */

#ifdef IM_BROKEN
    cipheropts = "frog";
    qop = "auth";
#endif

    /* get realm */
    result = get_realm(sparams, &realm);

    /* add to challenge */
    if (add_to_challenge(sparams->utils, &challenge, "realm", (unsigned char *) realm, TRUE) != SASL_OK) {
      VL(("add_to_challenge failed\n"));
      return SASL_FAIL;
    }
    /* get nonce XXX have to clean up after self if fail */
    nonce = create_nonce(sparams->utils);
    if (nonce == NULL) {
      VL(("failed creating a nonce\n"));
      return SASL_FAIL;
    }
    /* add to challenge */
    if (add_to_challenge(sparams->utils, &challenge, "nonce", nonce, TRUE) != SASL_OK) {
      VL(("add_to_challenge 2 failed\n"));
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
    if (add_to_challenge(sparams->utils, &challenge, "qop", (unsigned char *) qop, TRUE) != SASL_OK) {
      VL(("add_to_challenge 3 failed\n"));
      return SASL_FAIL;
    }

    /*
     *  Cipheropts - list of ciphers server supports
     */
    /* add cipher-opts to challenge */
    if (add_to_challenge(sparams->utils, &challenge, "cipher", (unsigned char *) cipheropts, 
			 TRUE) != SASL_OK) {
      VL(("add_to_challenge 3 failed\n"));
      return SASL_FAIL;
    }


    /* "stale" not used in initial authentication */

    /*
     * maxbuf A number indicating the size of the largest buffer the server
     * is able to receive when using "auth-int". If this directive is
     * missing, the default value is 65536. This directive may appear at most
     * once; if multiple instances are present, the client should abort the
     * authentication exchange.
     */

    if (add_to_challenge(sparams->utils, &challenge, "charset", (unsigned char *) charset, TRUE) != SASL_OK) {
      VL(("add_to_challenge 4 failed\n"));
      return SASL_FAIL;
    }
    /*
     * if (add_to_challenge(sparams->utils, &challenge,"algorithm",
     * algorithm, TRUE)!=SASL_OK) // return SASL_FAIL;
     */




    *serverout = challenge;
    *serveroutlen = strlen(*serverout);


    /*
     * The size of a digest-challenge MUST be less than 2048 bytes.!!!
     */
    if (*serveroutlen > 2048)
      return SASL_FAIL;

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
    char           *userid = NULL;
    sasl_secret_t  *sec;
    /* int len=sizeof(MD5_CTX); */
    int             result;
    sasl_server_getsecret_t *getsecret;
    void           *getsecret_context;

    char           *serverresponse = NULL;

    char           *username = NULL;
    bool            gotrealm = FALSE;
    char           *realm = NULL;
    /* unsigned char *nonce = NULL; */
    unsigned char  *cnonce = NULL;

    unsigned char  *ncvalue = NULL;
    int             noncecount;

    char           *qop = NULL;
    char           *digesturi = NULL;
    char           *response = NULL;

    char           *maxbufstr = NULL;

    unsigned int    client_maxbuf = 2096;	/* xxx is this right??? */
    int             maxbuf_count = 0;	/* How many maxbuf instaces was found */

    char           *charset = NULL;
    char           *cipher = NULL;
    unsigned int   n=0;

    HASH            A1;

    int             usernamelen;
    int             realm_len;

    /* can we mess with clientin? copy it to be safe */
    char           *in_start;
    char           *in = sparams->utils->malloc(clientinlen + 1);

    char *response_auth = NULL;

    memcpy(in, clientin, clientinlen);
    in[clientinlen] = 0;

    in_start = in;


    /* parse what we got */
    while (in[0] != '\0') {
      char           *name = NULL, *value = NULL;
      get_pair(&in, &name, &value);

      if (name == NULL)
	  break;

      VL(("received form client pair: %s - %s\n", name, value));

      /* Extracting parameters */

      /*
       * digest-response  = 1#( username | realm | nonce | cnonce |
       * nonce-count | qop | digest-uri | response | maxbuf | charset |
       * cipher | auth-param )
       */

      VL(("server_start step 2 : received pair: \t"));
      VL(("%s:%s\n", name, value));

      if (strcmp(name, "username") == 0) {

	digest_strdup(sparams->utils, value, &username, NULL);

      } else if (strcmp(name, "cnonce") == 0) {

	digest_strdup(sparams->utils, value, (char **) &cnonce, NULL);

      } else if (strcmp(name, "nc") == 0) {

	if (htoi((unsigned char *) value, &noncecount) != SASL_OK) {
	  result = SASL_BADAUTH;
	  goto FreeAllMem;
	}
	digest_strdup(sparams->utils, value, (char **) &ncvalue, NULL);

      } else if (strcmp(name, "realm") == 0) {

	if (strcmp(value, text->realm) != 0) {
	  VL(("Realm ws changed by client. Authentication aborted\n"));
	  result = SASL_FAIL;
	  goto FreeAllMem;
	} else {
	  gotrealm = TRUE;
	}
	digest_strdup(sparams->utils, value, &realm, NULL);

      } else if (strcmp(name, "nonce") == 0) {


	if (strcmp(value, (char *) text->nonce) != 0) {
	  /*
	   * Nonce changed: Abort authentication!!!
	   */
	  VL(("Nonce changed: Aborting authentication\n"));
	  result = SASL_BADAUTH;
	  goto FreeAllMem;
	}
      } else if (strcmp(name, "qop") == 0) {

	digest_strdup(sparams->utils, value, &qop, NULL);

      } else if (strcmp(name, "digest-uri") == 0) {

	/* XXX: verify digest-uri format */
	/*
	 * digest-uri-value  = serv-type "/" host [ "/" serv-name ]
	 */
	digest_strdup(sparams->utils, value, &digesturi, NULL);

      } else if (strcmp(name, "response") == 0) {

	digest_strdup(sparams->utils, value, &response, NULL);

      } else if (strcmp(name, "cipher") == 0) {

	digest_strdup(sparams->utils, value, &cipher, NULL);

      } else if (strcmp(name, "maxbuf") == 0) {

	maxbuf_count++;

	if (maxbuf_count != 1) {
	  result = SASL_BADAUTH;
	  VL(("At least two maxbuf directives found. Authentication aborted\n"));
	  goto FreeAllMem;
	} else if (sscanf(value, "%u", &client_maxbuf) != 1) {
	  result = SASL_BADAUTH;
	  VL(("Invalid maxbuf parameter received from client\n"));
	  goto FreeAllMem;
	}
	digest_strdup(sparams->utils, value, &maxbufstr, NULL);

      } else if (strcmp(name, "charset") == 0) {

	if (strcmp(value, "utf-8") != 0) {
	  VL(("Client doesn't support UTF-8. Server can't accept it\n"));
	  result = SASL_FAIL;
	  goto FreeAllMem;
	}
	digest_strdup(sparams->utils, value, &charset, NULL);

      } else {
	VL(("unrecognized pair: ignoring\n"));
      }

    }


    /* defaulting qop to "auth" if not specified */

    if (qop == NULL)
      digest_strdup(sparams->utils, "auth", &qop, NULL);      



    /* check which layer/cipher to use */

    if (strcmp(qop, "auth-conf") == 0) {
      /*      VL(("Privacy layer not supported\n"));
      result = SASL_FAIL;
      goto FreeAllMem;*/
      
      /* for when privacy supported */
      VL(("Client requested privacy layer\n"));
      VL(("Client cipher=%s\n",cipher));
      if (strcmp(cipher,"des")==0)
      {
	text->cipher_enc=(cipher_function_t *) &enc_des;
	text->cipher_dec=(cipher_function_t *) &dec_des;
	text->cipher_init=(cipher_init_t *) &init_des;	
	oparams->mech_ssf = 55;
	n=16; /* number of bits to make privacy key */

      } else if (strcmp(cipher,"3des")==0) {
	text->cipher_enc=(cipher_function_t *) &enc_3des;
	text->cipher_dec=(cipher_function_t *) &dec_3des;
	text->cipher_init=(cipher_init_t *) &init_3des;
	oparams->mech_ssf = 112;
	n=16;

#ifdef WITH_RC4
      } else if (strcmp(cipher,"rc4")==0) {
	text->cipher_enc=(cipher_function_t *) &enc_rc4;
	text->cipher_dec=(cipher_function_t *) &dec_rc4;
	text->cipher_init=&init_rc4;
	oparams->mech_ssf = 128;
 	n = 16;
 
      } else if (strcmp(cipher,"rc4-40")==0) {
 	text->cipher_enc=(cipher_function_t *) &enc_rc4;
 	text->cipher_dec=(cipher_function_t *) &dec_rc4;
 	text->cipher_init=&init_rc4;
 	oparams->mech_ssf = 40;
 	n = 5;

      } else if (strcmp(cipher,"rc4-56")==0) {
 	text->cipher_enc=(cipher_function_t *) &enc_rc4;
 	text->cipher_dec=(cipher_function_t *) &dec_rc4;
 	text->cipher_init=&init_rc4;
 	oparams->mech_ssf = 56;
 	n = 7;
 
#endif /* WITH_RC4 */
      } else {
	VL(("Invalid or no cipher chosen\n"));
	result = SASL_FAIL;
	goto FreeAllMem;
      }

    
      oparams->encode=&privacy_encode;
      oparams->decode=&privacy_decode;
      
    } else if (strcmp(qop, "auth-int") == 0) {
      VL(("Client requested integrity layer\n"));
      oparams->encode = &integrity_encode;
      oparams->decode = &integrity_decode;
      oparams->mech_ssf = 1;
    } else if (strcmp(qop, "auth") == 0) {
      VL(("Client requested no layer\n"));
      oparams->encode = NULL;
      oparams->decode = NULL;
      oparams->mech_ssf = 0;
    } else {
      VL(("Client requested undefined layer\n"));
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
	!gotrealm ||
    /* (nonce==NULL) ||  */
	(ncvalue == NULL) ||
	(cnonce == NULL) ||
	(digesturi == NULL) ||
	(response == NULL)) {
      VL(("Didn't get enough parameters\n"));
      result = SASL_BADAUTH;	/* Not enough parameters!!! */
      goto FreeAllMem;
    }
    /*
     * alexey: I removed charset check, because I've misunderstood it purpose
     */

    /* xxx not sure about this */
    if (qop == NULL)
      qop = "auth";


    usernamelen = strlen(username);
    realm_len = strlen(realm);

    userid = sparams->utils->malloc(usernamelen + 1 + realm_len + 1);

    if (userid == NULL) {
      result = SASL_NOMEM;
      goto FreeAllMem;
    }
    memcpy(userid, username, usernamelen);
    userid[usernamelen] = (char) ':';

    memcpy(userid + usernamelen + 1, realm, realm_len);
    userid[usernamelen + realm_len + 1] = '\0';


    VL(("userid constructed %s\n", userid));


    result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_GETSECRET,
    /* &getsecret, */
					 (int (**) ()) &getsecret,	/* ??? */
					 &getsecret_context);
    if ((result != SASL_OK) || (!getsecret)) {
      result = SASL_FAIL;
      goto FreeAllMem;
    }
    /* We use the user's DIGEST secret */

    result = getsecret(getsecret_context, "DIGEST-MD5", userid /* not username!!! */ , &sec);
    if (result != SASL_OK) {
      VL(("Unable to getsecret for %s\n", userid));
      goto FreeAllMem;
    }
    if (!sec) {
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
      VL(("stored secret of wrong length\n"));
      result = SASL_FAIL;
      goto FreeAllMem;
    }
    /*
     * A1       = { H( { username-value, ":", realm-value, ":", passwd } ),
     * ":", nonce-value, ":", cnonce-value }
     */



    memcpy(A1, sec->data, HASHLEN);
    A1[HASHLEN] = '\0';

    VL(("A1 is %s\n", A1));

    serverresponse = create_response(text,
				     sparams->utils,
				     text->nonce,
				     ncvalue,
				     cnonce,
				     qop,
				     digesturi,
				     A1,
				     SIGNING_SERVER_CLIENT,
				     SEALING_SERVER_CLIENT,
				     n,
				     &text->response_value);


    if (serverresponse == NULL) {
      result = SASL_NOMEM;
      goto FreeAllMem;
    }
    /* xxx   sasl_free_secret(&sec);*/	/* sparams->utils->free(sec);??? */

    /* if ok verified */
    if (strcmp(serverresponse, response) != 0) {
      result = SASL_BADAUTH;

      VL(("Client Sent: %s\n", response));

      VL(("Server calculated: %s\n", serverresponse));

      /* XXX stuff for reauth */
      VL(("Don't matche\n"));
      goto FreeAllMem;
    }
    VL(("MATCH! (authenticated) \n"));

    /*
     * nothing more to do; authenticated set oparams information
     */

    if (digest_strdup(sparams->utils, realm, &oparams->realm, NULL) == SASL_NOMEM) {
      result = SASL_NOMEM;
      goto FreeAllMem;
    }
    if (digest_strdup(sparams->utils, username, &oparams->user, NULL) == SASL_NOMEM) {
      result = SASL_NOMEM;
      goto FreeAllMem;
    }
    if (digest_strdup(sparams->utils, username, &oparams->authid, NULL) == SASL_NOMEM) {
      result = SASL_NOMEM;
      goto FreeAllMem;
    }

    oparams->doneflag = 1;
    oparams->maxoutbuf = client_maxbuf;

    oparams->param_version = 0;

    text->seqnum = 0;		/* for integrity/privacy */
    text->rec_seqnum = 0;	/* for integrity/privacy */
    text->hmac_md5 = sparams->utils->hmac_md5;
    text->malloc = sparams->utils->malloc;
    text->free = sparams->utils->free;

    /* used by layers */
    text->size = -1;
    text->needsize = 4;
    text->buffer = NULL;
    text->maxbuf = 65000;

    /* initialize cipher if need be */
    if (text->cipher_init!=NULL)
      text->cipher_init(text, sparams->utils,
			text->Kc, /* the privacy key */
			n); /* number of bytes of key we made */

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
    if (add_to_challenge(sparams->utils, &response_auth, "rspauth", (unsigned char *) text->response_value, TRUE) != SASL_OK) {
      VL(("add_to_challenge failed\n"));
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
    result = SASL_CONTINUE;

FreeAllMem:

    /* free everything */
    /*
     * sparams->utils->free (in_start);
     * 
     * sparams->utils->free (username); sparams->utils->free (realm);
     */

    /* sparams->utils->free (nonce); */
    /*
     * sparams->utils->free (cnonce); sparams->utils->free (ncvalue);
     * sparams->utils->free (qop); sparams->utils->free (digesturi);
     * sparams->utils->free (response); sparams->utils->free (maxbufstr);
     * sparams->utils->free (charset); sparams->utils->free (cipher);
     */

    /* sparams->utils->free(userid); */

    /* sparams->utils->free(serverresponse); */

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
      VL(("No more data expected from client\n"));
      return SASL_FAIL;
    }
    *serverout = NULL;
    *serveroutlen = 0;

    text->state = 1;

    return SASL_OK;
  }


  return SASL_FAIL;		/* should never get here */
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
  char           *userid;
  int             userlen;
  char           *realm;
  int             realmlen;
  union {
    char buf[sizeof(sasl_secret_t) + HASHLEN + 1];
    long align_long;
    double align_float;
  } secbuf;

  /* make sure we have everything we need */
  if (!sparams
      || !user
      || !pass)
    return SASL_BADPARAM;

  /* get the realm */
  result=get_realm(sparams,
		   &realm);

  if ((result!=SASL_OK) || (realm==NULL)) {
    VL(("Digest-MD5 requires a domain\n"));
    return SASL_NOTDONE;
  }

  realmlen = strlen(realm);
  userlen = strlen(user);

  DigestCalcSecret(sparams->utils,
		   (unsigned char *) user,
		   (unsigned char *) realm,
		   (char *) pass,
		   passlen,
		   HA1);

  /* construct sec to store on disk */
  sec = (sasl_secret_t *) &secbuf;
  sec->len = HASHLEN;
  memcpy(sec->data, HA1, HASHLEN);

  if (errstr)
    *errstr = NULL;

  /* get the callback so we can set the password */
  result = sparams->utils->getcallback(sparams->utils->conn,
				       SASL_CB_SERVER_PUTSECRET,
				       &putsecret,
				       &putsecret_context);
  if (result != SASL_OK)
    return result;

  userid = sparams->utils->malloc(userlen + 1 + realmlen + 1);

  if (userid == NULL)
    return SASL_NOMEM;

  memcpy(userid, user, userlen);
  userid[userlen] = (char) ':';

  memcpy(userid + userlen + 1, realm, realmlen);
  userid[userlen + realmlen + 1] = '\0';


  VL(("userid constructed %s\n", userid));

  /* We're actually constructing a SCRAM secret... */
  result = putsecret(putsecret_context,
		     "DIGEST-MD5",
		     userid,
		     sec);

  memset(&secbuf, 0, sizeof(secbuf));

  sparams->utils->free(userid);

  return result;
}

const sasl_server_plug_t plugins[] =
{
  {
    "DIGEST-MD5",
#ifndef IM_BROKEN
#ifdef WITH_RC4
    128,				/*xxx max ssf */
#else
    112,
#endif
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
  *out_version = DIGESTMD5_VERSION;

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

    text->i_am = CLIENT;
    text->authid = NULL;
    text->password = NULL;
    text->cipher_init=NULL;
    text->state = 1;

    *conn = text;

    return SASL_OK;
}




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

  /* see if we were given the authname in the prompt */
  prompt = find_prompt(prompt_need, SASL_CB_AUTHNAME);
  if (prompt != NULL) {
    /* copy it */
    *authid = params->utils->malloc(strlen(prompt->result) + 1);
    if ((*authid) == NULL)
      return SASL_NOMEM;

    strcpy(*authid, prompt->result);
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
			(const char **) authid,
			NULL);
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
	     int auth_res,
	     int pass_res)
{
  int             num = 1;
  sasl_interact_t *prompts;

  if (auth_res == SASL_INTERACT)
    num++;
  if (pass_res == SASL_INTERACT)
    num++;

  if (num == 1)
    return SASL_FAIL;

  prompts = params->utils->malloc(sizeof(sasl_interact_t) * num);
  if ((prompts) == NULL)
    return SASL_NOMEM;
  *prompts_res = prompts;

  if (auth_res == SASL_INTERACT) {
    /*
     * We weren't able to get the callback; let's try a SASL_INTERACT
     */
    (prompts)->id = SASL_CB_AUTHNAME;
    (prompts)->challenge = "Authorization Name";
    (prompts)->prompt = "Please enter your authorization name";
    (prompts)->defresult = NULL;

    VL(("authid callback added\n"));
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

  if (text->state == 1) {

    VL(("Digest-MD5 Step 1\n"));

    /* XXX reauth if possible */
    /* XXX if reauth is successfull - goto text->state=3!!! */

    *clientout = params->utils->malloc(1);	/* text->malloc(1); */

    if (!*clientout)
      return SASL_NOMEM;
    **clientout = '\0';
    *clientoutlen = 0;

    text->state = 2;

    return SASL_CONTINUE;
  }
  if (text->state == 2) {
    unsigned char  *digesturi = NULL;
    unsigned char  *nonce = NULL;
    unsigned char  *ncvalue = (unsigned char *) "00000001";
    unsigned char  *cnonce = NULL;
    char           *qop = NULL;
    char           *qop_list = NULL;
    int             protection = 0;
    char           *cipher = NULL;
    char           *cipher_list = NULL;
    int             ciphers=0;
    unsigned int  n=0;
    char           *response = NULL;
    char           *realm = NULL;
    unsigned int    server_maxbuf = 2096;
    int             maxbuf_count = 0;
    bool            IsUTF8 = FALSE;
    char           *charset = NULL;
    char           *xxx;
    char           *prev_xxx;
    int             result = SASL_FAIL;
    char           *client_response = NULL;
    sasl_security_properties_t secprops;
    int             external;
    int             auth_result = SASL_OK;
    int             pass_result = SASL_OK;

    VL(("Digest-MD5 Step 2\n"));

    /*
     * first thing: let's get authname and password this is the same code as
     * cram-md5 so change both accordingly
     */


    /* try to get the userid */
    if (text->authid == NULL) {
      VL(("Trying to get authid\n"));
      auth_result = get_authid(params,
			       (char **) &text->authid,
			       prompt_need);

      if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
	return auth_result;

    }
    /* try to get the password */
    if (text->password == NULL) {
      VL(("Trying to get password\n"));
      pass_result = get_password(params,
				 &text->password,
				 prompt_need);

      if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
	return pass_result;
    }
    /* free prompts we got */
    if (prompt_need)
      free_prompts(params, *prompt_need);

    /* if there are prompts not filled in */
    if ((auth_result == SASL_INTERACT) ||
	(pass_result == SASL_INTERACT)) {
      /* make the prompt list */
      int             result = make_prompts(params, prompt_need,
					    auth_result, pass_result);
      if (result != SASL_OK)
	return result;

      VL(("returning prompt(s)\n"));
      return SASL_INTERACT;
    }
    /* can we mess with serverin? copy it to be safe */
    /* char *in=serverin; //char *in=*serverin;??? */


    /* printf ("c_start step 2 : password is \"%s\"\n", passwd); */

    /*
     * params->utils->free((void *) (*prompt_need)->result); //This doesn't
     * work!!!
     */


    in = params->utils->malloc(serverinlen + 1);
    memcpy(in, serverin, serverinlen);
    in[serverinlen] = 0;

    in_start = in;

    /* printf ("Server data is \"%s\"\r\n", in); */

    /* parse what we got */
    while (in[0] != '\0') {	/* ??? */
      char           *name, *value;
      get_pair(&in, &name, &value);

      VL(("received pair: %s - %s\n", name, value));

      if (strcmp(name, "realm") == 0) {

	digest_strdup(params->utils, value, &realm, NULL);

      } else if (strcmp(name, "nonce") == 0) {

	digest_strdup(params->utils, value, (char **) &nonce, NULL);

      } else if (strcmp(name, "qop") == 0) {
	digest_strdup(params->utils, value, &qop_list, NULL);

	xxx = qop_list;
	while (1) {
	  prev_xxx = xxx;

	  xxx = strchr(xxx, ',');

	  if (xxx != NULL) {
	    xxx[0] = '\0';
	    xxx++;
	  }
	  if (strcmp(prev_xxx, "auth-conf") == 0) {
	    VL(("Server supports privacy layer\n"));
	    protection |= DIGEST_PRIVACY;

	  } else if (strcmp(prev_xxx, "auth-int") == 0) {
	    VL(("Server supports integrity layer\n"));
	    protection |= DIGEST_INTEGRITY;

	  } else if (strcmp(prev_xxx, "auth") == 0) {
	    VL(("Server supports no layer\n"));
	    protection |= DIGEST_NOLAYER;

	  } else {
	    VL(("Server supports unknown layer\n"));
	  }

	  if (xxx == NULL)
	    break;

	}

	if (protection == 0) {
	  result = SASL_BADAUTH;
	  VL(("Server doesn't support known qop level\n"));
	  goto FreeAllocatedMem;
	}
      } else if (strcmp(name, "cipher") == 0) {
	digest_strdup(params->utils, value, &cipher_list, NULL);

	xxx = cipher_list;
	while (1) {
	  prev_xxx = xxx;

	  xxx = strchr(xxx, ',');

	  if (xxx != NULL) {
	    xxx[0] = '\0';
	    xxx++;
	  }
	  if (strcmp(prev_xxx, "des") == 0) {
	    VL(("Server supports DES\n"));
	    ciphers |= CIPHER_DES;

	  } else if (strcmp(prev_xxx, "3des") == 0) {
	    VL(("Server supports 3DES\n"));
	    ciphers |= CIPHER_3DES;

#ifdef WITH_RC4
  	  } else if (strcmp(prev_xxx, "rc4") == 0) {
 	    VL(("Server supports rc4\n"));
  	    ciphers |= CIPHER_RC4;
 
 	  } else if (strcmp(prev_xxx, "rc4-40") == 0) {
 	    VL(("Server supports rc4-40\n"));
 	    ciphers |= CIPHER_RC440;
 
 	  } else if (strcmp(prev_xxx, "rc4-56") == 0) {
 	    VL(("Server supports rc4-56\n"));
 	    ciphers |= CIPHER_RC456;
 
#endif /* WITH_RC4 */
	  } else {

	    VL(("Not understood layer: %s\n",prev_xxx));
	  }

	  if (xxx == NULL)
	    break;

	}

	/* xxx if no ciphers don't fail right? */
      } else if (strcmp(name, "stale") == 0) {

	/*
	 * XXX //_sasl_plugin_strdup(params->utils, value, &stale_str, NULL);
	 * //XXX
	 */

      } else if (strcmp(name, "maxbuf") == 0) {

	/*
	 * maxbuf A number indicating the size of the largest buffer the
	 * server is able to receive when using "auth-int". If this directive
	 * is missing, the default value is 65536. This directive may appear
	 * at most once; if multiple instances are present, the client should
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
	}
      } else if (strcmp(name, "charset") == 0) {

	if (strcmp(value, "utf-8") != 0) {
	  result = SASL_BADAUTH;
	  VL(("Charset must be UTF-8\n"));
	  goto FreeAllocatedMem;
	} else {
	  IsUTF8 = TRUE;
	}


      } else {
	VL(("unrecognized pair: ignoring\n"));
      }
    }

    /*
     * (username | realm | nonce | cnonce | nonce-count | qop digest-uri |
     * response | maxbuf | charset | auth-param )
     */


    /* get requested ssf */
    secprops = params->props;
    external = params->external_ssf;
    VL(("external ssf=%i\n", external));

    if (secprops.min_ssf > 56) {
      VL(("Minimum ssf too strong min_ssf=%i\n", secprops.min_ssf));
      return SASL_TOOWEAK;
    }
    /*
     * this isn't necessary right? if (secprops.max_ssf<0) { VL (("ssf too
     * strong")); return SASL_FAIL; }
     */

    VL(("minssf=%i maxssf=%i\n", secprops.min_ssf, secprops.max_ssf));

    params->utils->free(qop);

    /* if client didn't set use strongest layer */
    if ((secprops.max_ssf > 1) &&
	((protection & DIGEST_PRIVACY) == DIGEST_PRIVACY)) {

      /*	VL(("Server doesn't support privacy layer\n"));
	result = SASL_FAIL;
	goto FreeAllocatedMem;*/

      oparams->encode = &privacy_encode; 
      oparams->decode = &privacy_decode;
      qop = "auth-conf";
      VL(("Using encryption layer\n"));

      /* Client request encryption, server support it */
      /* encryption */
#ifdef WITH_RC4
      if ((secprops.max_ssf>=128)  && 
	  ((ciphers & CIPHER_RC4) == CIPHER_RC4)) { /* rc4 */
#else
      if (0) {
#endif /* WITH_RC4 */
	VL(("Trying to use rc4"));
	cipher = "rc4";
	text->cipher_enc=(cipher_function_t *) &enc_rc4; /* uses same function both ways */
	text->cipher_dec=(cipher_function_t *) &dec_rc4;
	text->cipher_init=&init_rc4;
	oparams->mech_ssf = 128;
	n=16;

      } else if ((secprops.max_ssf>=112) && ((ciphers & CIPHER_3DES) == CIPHER_3DES)) {
	VL(("Trying to use 3des"));
	cipher = "3des";
	text->cipher_enc=(cipher_function_t *) &enc_3des;
	text->cipher_dec=(cipher_function_t *) &dec_3des;
	text->cipher_init=(cipher_init_t *) &init_3des;
	oparams->mech_ssf = 112; 
	n=16; /* number of bits to use for privacy key */



#ifdef WITH_RC4
      } else if ((secprops.max_ssf>=56)  && ((ciphers & CIPHER_RC456) == CIPHER_RC456)) { /* rc4-56 */
 	VL(("Trying to use rc4-56"));
 	cipher = "rc4-56";
 	text->cipher_enc=(cipher_function_t *) &enc_rc4;
 	text->cipher_dec=(cipher_function_t *) &dec_rc4;
 	text->cipher_init=&init_rc4;
 	oparams->mech_ssf = 56;
 	n = 7;
#endif /* WITH_RC4 */


      } else if ((secprops.max_ssf>=55)  && ((ciphers & CIPHER_DES) == CIPHER_DES)) { /* des */
	VL(("Trying to use des"));
	cipher = "des";
	text->cipher_enc=(cipher_function_t *) &enc_des;
	text->cipher_dec=(cipher_function_t *) &dec_des;
	text->cipher_init=(cipher_init_t *) &init_des;
	oparams->mech_ssf = 55; 
	n=16;

#ifdef WITH_RC4
      } else if ((secprops.max_ssf>=40)  && ((ciphers & CIPHER_RC440) == CIPHER_RC440)) { /* rc4-40 */
 	VL(("Trying to use rc4-40"));
 	cipher = "rc4-40";
 	text->cipher_enc=(cipher_function_t *) &enc_rc4;
 	text->cipher_dec=(cipher_function_t *) &dec_rc4;
 	text->cipher_init=&init_rc4;
 	oparams->mech_ssf = 40;
 	n = 5;
 
#endif /* WITH_RC4 */

      } else {
	/* should try integrity or plain */
	VL(("No good privacy layers\n"));
	qop=NULL;
      }


    }

    if (qop==NULL)
      {
      if ((secprops.min_ssf <= 1) && (secprops.max_ssf >= 1) &&
	  ((protection & DIGEST_INTEGRITY) == DIGEST_INTEGRITY)) {
	/* integrity */
	oparams->encode = &integrity_encode;
	oparams->decode = &integrity_decode;
	oparams->mech_ssf = 1;
	qop = "auth-int";
	VL(("Using integrity layer\n"));
	
      } else {
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

    /* serv-type */
    /* ervtype=params->service; */
    /* host */
    /* ost=params->serverFQDN; //params->params->serverFQDN; */
    /* XXX serv-name */
    /* servname=params->serverFQDN; //params->params->serverFQDN; */
    /* XXX digest uri */

    digesturi = params->utils->malloc(strlen(params->service) + 1 +
				      strlen(params->serverFQDN) + 1 +
    /* strlen(params->serverFQDN)+1 */
				      1
      );
    if (digesturi == NULL) {
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
    };

    strcpy((char *) digesturi, params->service);
    strcat((char *) digesturi, "/");
    strcat((char *) digesturi, params->serverFQDN);
    /*
     * strcat (digesturi, "/"); strcat (digesturi, params->serverFQDN);
     */

    /* response */
    response = calculate_response(text,
				  params->utils,
				  text->authid,
				  (unsigned char *) realm,
				  nonce,
				  ncvalue,
				  cnonce,
				  qop,
				  digesturi,
				  text->password,
				  SIGNING_CLIENT_SERVER,
				  SEALING_CLIENT_SERVER,
				  n, /* bytes to use to make privacy key */
				  &text->response_value);

    VL(("Constructing challenge\n"));

    if (add_to_challenge(params->utils, &client_response, "username", text->authid, TRUE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils, &client_response, "realm", (unsigned char *) realm, TRUE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
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
    if (add_to_challenge(params->utils, &client_response, "qop", (unsigned char *) qop, TRUE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (cipher!=NULL)
      if (add_to_challenge(params->utils, &client_response, "cipher", 
			   (unsigned char *) cipher, TRUE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
      }

    if (IsUTF8) {
      if (add_to_challenge(params->utils, &client_response, "charset", (unsigned char *) "utf-8", FALSE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
      }				/* What to do otherwise??? Convert UserName
				 * and Password from UTF-8 to ISO-8859-1? */
    }
    if (add_to_challenge(params->utils, &client_response, "digest-uri", digesturi, TRUE) != SASL_OK) {
      result = SASL_FAIL;
      goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils, &client_response, "response", (unsigned char *) response, TRUE) != SASL_OK) {

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

    result = SASL_CONTINUE;

    text->state = 3;

    if (digest_strdup(params->utils, realm, &oparams->realm, NULL) == SASL_NOMEM) {
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
    }
    if (digest_strdup(params->utils, (char *) text->authid, &oparams->user, NULL) == SASL_NOMEM) {
      params->utils->free(oparams->realm);
      oparams->realm = NULL;
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
    }
    if (digest_strdup(params->utils, (char *) text->authid, &oparams->authid, NULL) == SASL_NOMEM) {
      params->utils->free(oparams->realm);
      oparams->realm = NULL;
      params->utils->free(oparams->user);
      oparams->user = NULL;
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
    }
    /* set oparams */

    oparams->doneflag = 1;
    oparams->maxoutbuf = 4096;

    oparams->param_version = 0;


    text->seqnum = 0;		/* for integrity/privacy */
    text->rec_seqnum = 0;	/* for integrity/privacy */
    text->hmac_md5 = params->utils->hmac_md5;
    text->malloc = params->utils->malloc;
    text->free = params->utils->free;

    text->maxbuf = server_maxbuf;	/* xxx is this right??? */

    /* used by layers */
    text->size = -1;
    text->needsize = 4;
    text->buffer = NULL;

    /* initialize cipher if need be */
    if (text->cipher_init!=NULL)
      text->cipher_init(text, params->utils, text->Kc, n);

FreeAllocatedMem:
    params->utils->free(response);	/* !!! */

    params->utils->free(text->password);
    params->utils->free(in_start);

    /*
     * They wasn't malloc-ated //params->utils->free(username);
     */

    /* Realm is got from server!!! */
    params->utils->free(realm);
    params->utils->free(nonce);


    /*
     * params->utils->free(stale_str); //params->utils->free(maxbuf_str);
     */

    params->utils->free(charset);
    params->utils->free(digesturi);

    /*
     * params->utils->free(ncvalue); //Only for multiple authentications
     */

    params->utils->free(cnonce);

    VL(("Add done. exiting DIGEST-MD5\n"));

    return result;
  }

  if (text->state == 3) {	/* Verify that server is really what he
     * claims to be *//* ReAUTH. NTI!!! */

    VL(("Digest-MD5: In Reauth state\n"));

    in = params->utils->malloc(serverinlen + 1);
    memcpy(in, serverin, serverinlen);
    in[serverinlen] = 0;

    in_start = in;

    /* parse what we got */
    while (in[0] != '\0') {	/* ??? */
      char           *name, *value;
      get_pair(&in, &name, &value);

      VL(("received pair: %s - %s\n", name, value));

      if (strcmp(name, "rspauth") == 0) {

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
	  return SASL_OK;
	}
      } else {
	VL(("unrecognized pair: ignoring\n"));
      }
    }

    params->utils->free(in_start);

    return SASL_FAIL;
  }


  return SASL_FAIL;		/* should never get here */
}

static const long client_required_prompts[] = {
  SASL_CB_AUTHNAME,
  SASL_CB_PASS,
  SASL_CB_LIST_END
};


const sasl_client_plug_t client_plugins[] =
{
  {
    "DIGEST-MD5",
#ifndef IM_BROKEN
#ifdef WITH_RC4
    128,				/*xxx max ssf */
#else
    112,
#endif
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
  if (maxversion < DIGESTMD5_VERSION)
    return SASL_BADVERS;

  *pluglist = client_plugins;

  *plugcount = 1;
  *out_version = DIGESTMD5_VERSION;

  return SASL_OK;
}
