/* SRP SASL plugin
 * Ken Murchison
 * Tim Martin  3/17/00
 * $Id: srp.c,v 1.3 2001/12/04 02:06:49 rjs3 Exp $
 */
/* 
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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
#include <assert.h>
#include <ctype.h>

/* for big number support */
#include <gmp.h>

#ifdef WITH_SHA1
# ifdef WITH_SSL_SHA1
#  include <openssl/sha.h>
# else /* any other SHA1? */
# endif
#endif /* WITH_SHA1 */

#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"
#include "../sasldb/sasldb.h"

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
#include "saslSRP.h"
#endif

#ifdef macintosh
#include <sasl_srp_plugin_decl.h>
#endif 

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#undef L_DEFAULT_GUARD
#define L_DEFAULT_GUARD (0)

#define SRP_VERSION (5)

/* Size of N in bits */
#define BITSFORN 128
/* Size of diffie-hellman secrets a and b */
#define BITSFORab 64
/* How many bytes big should the salt be? */
#define SRP_SALT_SIZE 16

#include <stdio.h>
#define VL(x) printf x

/* Generic Hash function definitions */
typedef int  (*srp_hash_len_t)(const sasl_utils_t *utils);
typedef int  (*srp_hash_init_t)(const sasl_utils_t *utils,
				char *key, int keylen, void **ctx);
typedef void (*srp_hash_update_t)(const sasl_utils_t *utils,
				  void *ctx, char *data, int datalen);
typedef void (*srp_hash_final_t)(const sasl_utils_t *utils,
				 char *outdata, void *ctx);

#define OPTION_REPLAY_DETECTION	"replay detection"
#define OPTION_INTEGRITY	"integrity="
#define OPTION_CONFIDENTIALITY	"confidentiality="

/* Forward decl */
static int
ReadUserInfo(const sasl_utils_t *utils, char *authid, char *realm,
	     const char *propName,
	     mpz_t *N, mpz_t *g, char **salt, int *saltlen, mpz_t *v);


/***************** SHA1 Hash Functions ****************/

#ifdef WITH_SHA1
static int
srp_sha1Len(const sasl_utils_t *utils __attribute__((unused)))
{
    return 20;
}

static int
srp_sha1Init(const sasl_utils_t *utils __attribute__((unused)),
	     char *key __attribute__((unused)),
	     int keylen __attribute__((unused)), void **ctx)
{
    SHA_CTX *ret;

    ret = utils->malloc(sizeof(SHA_CTX));
    if (!ret) return SASL_NOMEM;

    SHA1_Init(ret);

    *ctx = ret;

    return SASL_OK;
}

static void
srp_sha1Update(const sasl_utils_t *utils __attribute__((unused)),
	       void *context, char *data, int datalen)
{
    SHA_CTX *ctx = (SHA_CTX *)context;

    SHA1_Update(ctx, data, datalen);    
}

static void
srp_sha1Final(const sasl_utils_t *utils __attribute__((unused)),
	      char *outdata, void *context)
{
    SHA_CTX *ctx = (SHA_CTX *)context;

    SHA1_Final(outdata, ctx);

    utils->free(ctx);
}
#endif /* WITH_SHA1 */

/***************** MD5 Hash Functions ****************/

static int
srp_md5Len(const sasl_utils_t *utils __attribute__((unused)))
{
    return 16;
}

static int
srp_md5Init(const sasl_utils_t *utils, char *key __attribute__((unused)),
	    int keylen __attribute__((unused)), void **ctx)
{
    MD5_CTX *ret;

    ret = utils->malloc(sizeof(MD5_CTX));
    if (!ret) return SASL_NOMEM;

    utils->MD5Init(ret);

    *ctx = ret;

    return SASL_OK;
}

static void
srp_md5Update(const sasl_utils_t *utils, void *context, char *data,
	      int datalen)
{
    MD5_CTX *ctx = (MD5_CTX *)context;

    utils->MD5Update(ctx, data, datalen);    
}

static void
srp_md5Final(const sasl_utils_t *utils, char *outdata, void *context)
{
    MD5_CTX *ctx = (MD5_CTX *)context;

    utils->MD5Final(outdata, ctx);

    utils->free(ctx);
}

/***************** MD5 Hash Functions for Integrity Layer ****************/

static int
srp_hmac_md5Len(const sasl_utils_t *utils __attribute__((unused)))
{
    return 16;
}

static int
srp_hmac_md5Init(const sasl_utils_t *utils, char *key, int keylen, void **ctx)
{
    HMAC_MD5_CTX *ret;

    ret = utils->malloc(sizeof(HMAC_MD5_CTX));
    if (!ret) return SASL_NOMEM;

    utils->hmac_md5_init(ret, key, keylen);

    *ctx = ret;

    return SASL_OK;
}

static void
srp_hmac_md5Update(const sasl_utils_t *utils, void *context, char *data,
		   int datalen)
{
    HMAC_MD5_CTX *ctx = (HMAC_MD5_CTX *)context;

    utils->MD5Update(&ctx->ictx, data, datalen);    
}

static void
srp_hmac_md5Final(const sasl_utils_t *utils, char *outdata, void *context)
{
    HMAC_MD5_CTX *ctx = (HMAC_MD5_CTX *)context;

    utils->hmac_md5_final(outdata, ctx);

    utils->free(ctx);
}

/******************** Options *************************/

typedef struct layer_option_s {
    char *name;
    int bit;
    int ssf;

    srp_hash_len_t    HashLen;
    srp_hash_init_t   HashInit;
    srp_hash_update_t HashUpdate;
    srp_hash_final_t  HashFinal;

} layer_option_t;

static layer_option_t integrity_options[] = {
    {"hmac-md5", 0x1, 0,	&srp_hmac_md5Len,	&srp_hmac_md5Init,
     &srp_hmac_md5Update,	&srp_hmac_md5Final},
    {NULL,       0x0, 0,	NULL,			NULL,
     NULL,			NULL}
};

static layer_option_t confidentiality_options[] = {
    /* nothing yet */
    {NULL,       0x0, 0,        NULL,         NULL,           NULL,          NULL}
};


typedef struct srp_options_s {

    int replay_detection;

    int integrity;
    int confidentiality;

} srp_options_t;

/* The main SRP context */
typedef struct context_s {
    int state;

    mpz_t N;
    mpz_t g;

    mpz_t S; /* shared secret */

    mpz_t v; /* verifier */

    mpz_t b;
    mpz_t B;

    mpz_t a;
    mpz_t A;

    char *K;
    int Klen;

    char *M1;
    int M1len;

    char *authid; /* authentication id */
    char *userid; /* authorization id */
    char *realm;
    sasl_secret_t *password;

    char *client_options;
    char *server_options;

    srp_options_t client_opts;

    char *salt;
    int saltlen;

    const char *propName; /* property name in sasldb */

    /* Hash functions */
    int               HashLen;
    srp_hash_init_t   HashInit;
    srp_hash_update_t HashUpdate;
    srp_hash_final_t  HashFinal;

    /* used by hash functions */
    const sasl_utils_t *utils;

    /* Layer foo */
    int enabled_integrity_layer;
    int enabled_replay_detection;

    int seqnum_out;
    int seqnum_in;

    /* Intergrity layer hash functions */
    int               IntegHashLen;
    srp_hash_init_t   IntegHashInit;
    srp_hash_update_t IntegHashUpdate;
    srp_hash_final_t  IntegHashFinal;

    /* encode and decode need these */
    char *buffer;                    
    int bufsize;
    buffer_info_t * enc_in_buf;

    char sizebuf[4];
    int cursize;
    int size;
    int needsize;

} context_t;

/*******************************************
 *	Layer Functions	 	           *
 *                                         *
 *******************************************/


static int
layer_encode(void *context,
		 const struct iovec *invec,
		 unsigned numiov,
		 const char **output,
		 unsigned *outputlen)
{
  context_t      *text = (context_t *) context;
  int hashlen = 0;
  char hashdata[text->IntegHashLen]; /* xxx */
  int tmpnum;
  int ret;
  char *input;
  unsigned inputlen;

  assert(numiov > 0);

  ret = _plug_iovec_to_buf(text->utils, invec, numiov, &text->enc_in_buf);
  if(ret != SASL_OK) return ret;
  
  input = text->enc_in_buf->data;
  inputlen = text->enc_in_buf->curlen;

  if (text->enabled_integrity_layer) {
    void *hmac_ctx = NULL;

    text->IntegHashInit(text->utils, text->K, text->Klen, &hmac_ctx);

    text->IntegHashUpdate(text->utils, hmac_ctx, input, inputlen);

    if (text->enabled_replay_detection) {
      tmpnum = htonl(text->seqnum_out);
      text->IntegHashUpdate(text->utils, hmac_ctx, (char *) &tmpnum, 4);
      
      text->seqnum_out++;	  
    }
    
    text->IntegHashFinal(text->utils, hashdata, hmac_ctx);
    hashlen = text->IntegHashLen; /* xxx */
  }

  /* 4 for length + input size + hashlen for integrity (could be zero) */
  *outputlen = 4 + inputlen + hashlen;

  *output = text->utils->malloc(*outputlen);
  if (!*output) return SASL_NOMEM;
  
  tmpnum = inputlen+hashlen;
  tmpnum = htonl(tmpnum);
  memcpy( (char *) *output,     &tmpnum, 4);
  memcpy( (char *) (*output)+4, input, inputlen);
  memcpy( (char *) (*output)+4+inputlen, hashdata, hashlen);
  
  return SASL_OK;
}


static int
decode(context_t *text,
       const char *input,
       unsigned inputlen,
       const char **output,
       unsigned *outputlen)
{
    int hashlen = 0;

    if (text->enabled_integrity_layer) {
	int tmpnum;
	char hashdata[text->IntegHashLen];
	int i;
	void *hmac_ctx = NULL;

	text->IntegHashInit(text->utils, text->K, text->Klen, &hmac_ctx);

	hashlen = text->IntegHashLen; /* xxx */

	if ((int)inputlen < hashlen) {
	    VL(("Input is smaller than hash length: %d vs %d\n",inputlen, hashlen));
	    return SASL_FAIL;
	}

	/* create my version of the hash */
	text->IntegHashUpdate(text->utils, hmac_ctx,
			      (char *)input, inputlen - hashlen);

	if (text->enabled_replay_detection) {
	    tmpnum = htonl(text->seqnum_in);
	    text->IntegHashUpdate(text->utils, hmac_ctx,
				  (char *) &tmpnum, 4);
	    
	    text->seqnum_in ++;
	}
	
	text->IntegHashFinal(text->utils, hashdata, hmac_ctx);

	/* compare to hash given */
	for (i = 0; i < hashlen; i++) {
	    if (hashdata[i] != input[inputlen - hashlen + i]) {
		VL(("Hash is incorrect\n"));
		return SASL_FAIL;
	    }
	}
    }

    *output = text->utils->malloc(inputlen - hashlen);
    if (!*output) return SASL_NOMEM;

    *outputlen = inputlen - hashlen;
    memcpy( (char *) *output, input, *outputlen);

    return SASL_OK;
}

static int
layer_decode(void *context,
	     const char *input,
	     unsigned inputlen,
	     const char **output,
	     unsigned *outputlen)
{
    int tocopy;
    unsigned diff;
    context_t *text=context;
    const char *extra;
    unsigned int extralen=0;
    int r;

    if (text->needsize>0) { /* 4 bytes for how long message is */
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
	    
	    /* too big? */
	    if ((text->size>0xFFFF) || (text->size < 0)) {
		VL(("Size out of range: %d\n",text->size));
		return SASL_FAIL;
	    }
	    
	    if (text->bufsize < text->size + 5) {
		text->buffer = text->utils->realloc(text->buffer,
						    text->size + 5);
		text->bufsize = text->size + 5;
	    }
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
    
    if (inputlen < diff) { /* not enough for a decode */
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

    /* We have enough data to return something */
    r = decode(text, text->buffer, text->size, output, outputlen);
    if (r) return r;

    text->size = -1;
    text->needsize = 4;

    /* if received more than the end of a packet */
    if (inputlen!=0) {
	extra = NULL;
	layer_decode(text, input, inputlen,
		       &extra, &extralen);
	if (extra != NULL) {
	    /* if received 2 packets merge them together */
	    *output = text->utils->realloc( (char *) *output,
					    *outputlen+extralen);
	    memcpy( (char *) *output + *outputlen, extra, extralen); 
	    *outputlen += extralen;
	    text->utils->free( (char *) extra);
	}
    }
    
    return SASL_OK;
}

/*******************************************
 *	Helper Functions		   *
 *                                         *
 *******************************************/

/* Dispose of a SRP context (could be server or client)
 *
 *
 */ 
static void srp_both_mech_dispose(void *conn_context,
				  const sasl_utils_t *utils)
{
  context_t *text = conn_context;

  if (!text)
    return;

  mpz_clear(text->N);
  mpz_clear(text->g);
  mpz_clear(text->S);
  mpz_clear(text->v);
  mpz_clear(text->b);
  mpz_clear(text->B);
  mpz_clear(text->a);
  mpz_clear(text->A);

  if (text->K)                utils->free(text->K);
  if (text->M1)               utils->free(text->M1);

  if (text->authid)           utils->free(text->authid);
  if (text->userid)           utils->free(text->userid);
  if (text->realm)            utils->free(text->realm);
  if (text->password)         _plug_free_secret(utils, &(text->password));
  if (text->salt)             utils->free(text->salt);

  if (text->client_options)   utils->free(text->client_options);
  if (text->server_options)   utils->free(text->server_options);
  if (text->buffer)           utils->free(text->buffer);

  utils->free(text);
}

static void srp_both_mech_free(void *global_context,
			       const sasl_utils_t *utils)
{
    if(global_context) utils->free(global_context);  
}


/* copy a string */
static int
srp_strdup(const sasl_utils_t * utils, const char *in, char **out, int *outlen)
{
  size_t len = strlen(in);

  if (outlen!=NULL) {
      *outlen = len;
  }

  *out = utils->malloc(len + 1);
  if (!*out) {
      return SASL_NOMEM;
  }

  strcpy((char *) *out, in);
  return SASL_OK;
}

/* returns the realm we should pretend to be in */
static int parseuser(const sasl_utils_t *utils,
		     char **user, char **realm, const char *user_realm, 
		     const char *serverFQDN, const char *input)
{
    int ret;
    char *r;

    assert(user);
    assert(realm);
    assert(serverFQDN);
    assert(input);

    if (!user_realm) {
	ret = srp_strdup(utils, serverFQDN, realm, NULL);
	if (ret == SASL_OK) {
	    ret = srp_strdup(utils, input, user, NULL);
	}
    } else if (user_realm[0]) {
	ret = srp_strdup(utils, user_realm, realm, NULL);
	if (ret == SASL_OK) {
	    ret = srp_strdup(utils, input, user, NULL);
	}
    } else {
	/* otherwise, we gotta get it from the user */
	r = strchr(input, '@');
	if (!r) {
	    /* hmmm, the user didn't specify a realm */
	    /* we'll default to the serverFQDN */
	    ret = srp_strdup(utils, serverFQDN, realm, NULL);
	    if (ret == SASL_OK) {
		ret = srp_strdup(utils, input, user, NULL);
	    }
	} else {
	    int i;

	    r++;
	    ret = srp_strdup(utils, r, realm, NULL);
	    *user = utils->malloc(r - input + 1);
	    if (*user) {
		for (i = 0; input[i] != '@'; i++) {
		    (*user)[i] = input[i];
		}
		(*user)[i] = '\0';
	    } else {
		ret = SASL_NOMEM;
	    }
	}
    }

    return ret;
}

#define MAX_BUFFER_LEN 2147483643
#define MAX_UTF8_LEN 65535
#define MAX_OS_LEN 255


/*
 * Make a SRP buffer
 *
 * in1 must exist but the rest may be NULL
 *
 */
static int
MakeBuffer(const sasl_utils_t *utils, 
	   char *in1, int in1len,
	   char *in2, int in2len,
	   char *in3, int in3len,
	   char *in4, int in4len,
	   const char **out,
	   unsigned *outlen)
{
    int len;
    int inbyteorder;
    char *out2;

    if (!in1) {
	VL(("At least one buffer must be active\n"));
	return SASL_FAIL;
    }

    len = in1len + in2len + in3len + in4len;

    if (len > MAX_BUFFER_LEN) {
	VL(("String too long to create SRP buffer string\n"));
	return SASL_FAIL;
    }

    out2 = utils->malloc(len + 4);
    if (!out2) return SASL_NOMEM;

    /* put length in */
    inbyteorder = htonl(len);
    memcpy(out2, &inbyteorder, 4);

    /* copy in data */
    memcpy((out2)+4, in1, in1len);

    if (in2len)
	memcpy((out2)+4+in1len, in2, in2len);

    if (in3len)
	memcpy((out2)+4+in1len+in2len, in3, in3len);

    if (in4len)
	memcpy((out2)+4+in1len+in2len+in3len, in4, in4len);

    *outlen = len + 4;

    *out = out2;

    return SASL_OK;
}

/* Un'buffer' a string
 *
 * 'out' becomes a pointer into 'in' not an allocation
 */
static int
UnBuffer(char *in, int inlen, char **out, int *outlen)
{
    int lenbyteorder;
    int len;

    if ((!in) || (inlen < 4)) {
	VL(("Buffer is not big enough to be SRP buffer: %d\n", inlen));
	return SASL_FAIL;
    }

    /* get the length */
    memcpy(&lenbyteorder, in, 4);
    len = ntohl(lenbyteorder);

    /* make sure it's right */
    if (len + 4 != inlen) {
	VL(("SRP Buffer isn't of the right length\n"));
	return SASL_FAIL;
    }

    *out = in+4;
    *outlen = len;
    
    return SASL_OK;
}

static int
MakeUTF8(const sasl_utils_t *utils,
	 char *in,
	 char **out,
	 int *outlen)
{
    int llen;
    short len;
    short inbyteorder;

    if (!in) {
	VL(("Can't create utf8 string from null"));
	return SASL_FAIL;
    }

    /* xxx actual utf8 conversion */

    llen = strlen(in);

    if (llen > MAX_UTF8_LEN) {
	VL(("String too long to create utf8 string\n"));
	return SASL_FAIL;
    }
    len = (short)llen;

    *out = utils->malloc(len+2);
    if (!*out) return SASL_NOMEM;

    /* put in len */
    inbyteorder = htons(len);
    memcpy(*out, &inbyteorder, 2);

    /* put in data */
    memcpy((*out)+2, in, len);

    *outlen = len+2;

    return SASL_OK;
}

static int
GetUTF8(const sasl_utils_t *utils, char *data, int datalen,
	char **outstr, char **left, int *leftlen)
{
    short lenbyteorder;
    int len;

    if ((!data) || (datalen < 2)) {
	VL(("Buffer is not big enough to be SRP UTF8\n"));
	return SASL_FAIL;
    }

    /* get the length */
    memcpy(&lenbyteorder, data, 2);
    len = ntohs(lenbyteorder);

    /* make sure it's right */
    if (len + 2 > datalen) {
	VL(("Not enough data for this SRP UTF8\n"));
	return SASL_FAIL;
    }

    *outstr = (char *)utils->malloc(len+1);
    if (!*outstr) return SASL_NOMEM;

    memcpy(*outstr, data+2, len);
    (*outstr)[len] = '\0';
    
    *left = data+len+2;
    *leftlen = datalen - (len+2);

    return SASL_OK;
}

static int
MakeOS(const sasl_utils_t *utils,
       char *in, 
       int inlen,
       char **out,
       int *outlen)
{
    if (!in) {
	VL(("Can't create SRP os string from null"));
	return SASL_FAIL;
    }

    if (inlen > MAX_OS_LEN) {
	VL(("String too long to create SRP os string\n"));
	return SASL_FAIL;
    }

    *out = utils->malloc(inlen+1);
    if (!*out) return SASL_NOMEM;

    /* put in len */
    (*out)[0] = inlen & 0xFF;

    /* put in data */
    memcpy((*out)+1, in, inlen);

    *outlen = inlen+1;

    return SASL_OK;
}

static int
GetOS(const sasl_utils_t *utils, char *data, int datalen,
      char **outstr, int *outlen, char **left, int *leftlen)
{
    int len;

    if ((!data) || (datalen < 1)) {
	VL(("Buffer is not big enough to be SRP os\n"));
	return SASL_FAIL;
    }

    /* get the length */
    len = (unsigned char)data[0];

    /* make sure it's right */
    if (len + 1 > datalen) {
	VL(("Not enough data for this SRP os\n"));
	return SASL_FAIL;
    }

    *outstr = (char *)utils->malloc(len+1);
    if (!*outstr) return SASL_NOMEM;

    memcpy(*outstr, data+1, len);
    (*outstr)[len] = '\0';

    *outlen = len;
    
    *left = data+len+1;
    *leftlen = datalen - (len+1);

    return SASL_OK;
}

static int 
tobits(char c)
{
    if ((int) isdigit(c))
	return c-'0';

    if ((c>='a') && (c<='f'))
	return c-'a'+10;

    if ((c>='A') && (c<='F'))
	return c-'A'+10;

    return 0;
}

/* Convert a big integer to it's byte representation
 *
 *
 */
static int
BigIntToBytes(mpz_t num, char *out, int maxoutlen, int *outlen)
{
    char buf[4096];
    char *bufp = buf;
    int len;
    int prefixlen = 0;
    int i;

    len = mpz_sizeinbase (num, 16);

    if (len > maxoutlen) return SASL_FAIL;

    mpz_get_str (buf, 16, num);

    if (len%2!=0) {
	out[0]=tobits(*bufp);
	bufp++;
	len--;
	prefixlen=1;
    }

    for (i=0; i< len/2; i++ )
    {
	out[prefixlen+i] = (tobits(*bufp) << 4);
	bufp++;
	out[prefixlen+i] |= tobits(*bufp);
	bufp++;
    }

    *outlen = prefixlen+(len/2);

    return SASL_OK;    
}

static int
MakeMPI(const sasl_utils_t *utils,
	mpz_t num,
	char **out,
	int *outlen)
{
    int shortlen;
    int len;
    short inbyteorder;
    int alloclen;
    int r;

    alloclen = mpz_sizeinbase (num, 16);
   
    *out = utils->malloc(alloclen+2);
    if (!*out) return SASL_NOMEM;

    r = BigIntToBytes(num, (*out)+2, alloclen, &len);
    if (r) {
	utils->free(*out);
	return r;
    }

    *outlen = 2+len;

    /* put in len */
    shortlen = len;
    inbyteorder = htons(shortlen);
    memcpy(*out, &inbyteorder, 2);

    return SASL_OK;
}

static char 
frombits(unsigned int i)
{
    assert(i <= 15);

    if (i<=9) return '0'+i;

    return 'a'+ (i-10);
}

static void
DataToBigInt(unsigned char *in, int inlen, mpz_t *outnum)
{
    int i;
    char buf[4096];

    mpz_init(*outnum);    

    memset(buf, '\0', sizeof(buf));

    for (i = 0; i < inlen; i++) 
    {
	buf[i*2]   = frombits(in[i] >> 4);
	buf[i*2+1] = frombits(in[i] & 15);
    }
    
    mpz_set_str (*outnum, buf, 16);
}

static int
GetMPI(unsigned char *data, int datalen, mpz_t *outnum,
       char **left, int *leftlen)
{


    short lenbyteorder;
    int len;

    if ((!data) || (datalen < 2)) {
	VL(("Buffer is not big enough to be SRP MPI: %d\n", datalen));
	return SASL_FAIL;
    }

    /* get the length */
    memcpy(&lenbyteorder, data, 2);
    len = ntohs(lenbyteorder);

    /* make sure it's right */
    if (len + 2 > datalen) {
	VL(("Not enough data for this SRP MPI: we have %d; it say it's %d\n",datalen, len+2));
	return SASL_FAIL;
    }

    DataToBigInt(data+2, len, outnum);

    *left = data+len+2;
    *leftlen = datalen - (len+2);

    return SASL_OK;
}

static void
GetRandBigInt(mpz_t out)
{
    mpz_init(out);

    /* xxx likely should use sasl random funcs */
    mpz_random(out, BITSFORab/(8*sizeof(int)));
}

/* Call the hash function on the data of a BigInt
 *
 */
static void
HashData(context_t *text, char *in, int inlen, unsigned char outhash[])
{
    void *ctx;

    text->HashInit(text->utils, NULL, 0, &ctx);
    text->HashUpdate(text->utils, ctx, in, inlen);
    text->HashFinal(text->utils, outhash, ctx);
}

/* Call the hash function on the data of a BigInt
 *
 */
static int
HashBigInt(context_t *text, mpz_t in, unsigned char outhash[])
{
    int r;
    char buf[4096];
    int buflen;
    void *ctx;
    
    r = BigIntToBytes(in, buf, sizeof(buf)-1, &buflen);
    if (r) return r;

    text->HashInit(text->utils, NULL, 0, &ctx);
    text->HashUpdate(text->utils, ctx, buf, buflen);
    text->HashFinal(text->utils, outhash, ctx);

    return 0;
}

static int
HashInterleaveBigInt(context_t *text, mpz_t num, char **out, int *outlen)
{
    int r;
    char buf[4096];
    int buflen;

    int klen;
    int limit;
    int i;
    int offset;
    int j;
    void *mdEven;
    void *mdOdd;
    unsigned char Evenb[text->HashLen];
    unsigned char Oddb[text->HashLen];

    /* make bigint into bytes */
    r = BigIntToBytes(num, buf, sizeof(buf)-1, &buflen);
    if (r) return r;

    limit = buflen;

    /* skip by leading zero's */
    for (offset = 0; offset < limit && buf[offset] == 0x00; offset++) {
	/* nada */
    }
	
    klen = (limit - offset) / 2;

    text->HashInit(text->utils, NULL, 0, &mdEven);
    text->HashInit(text->utils, NULL, 0, &mdOdd);

    j = limit - 1;
    for (i = 0; i < klen; i++) {
	text->HashUpdate(text->utils, mdEven, buf + j, 1);
	j--;
	text->HashUpdate(text->utils, mdOdd, buf + j, 1);
	j--;
    }

    text->HashFinal(text->utils, Evenb, mdEven);
    text->HashFinal(text->utils, Oddb, mdOdd);

    *out = text->utils->malloc(2 * text->HashLen);
    if (!*out) return SASL_NOMEM;
    *outlen = 2 * text->HashLen;
      
    for (i = 0, j = 0; i < text->HashLen; i++)
    {
	(*out)[j++] = Evenb[i];
	(*out)[j++] = Oddb[i];
    }

    return SASL_OK;
}


/*
 * Calculate 'x' which is needed to calculate 'K'
 *
 */
static int
CalculateX(context_t *text,
	   const char *salt, 
	   int saltlen, 
	   const char *user, 
	   const char *pass, 
	   int passlen, 
	   mpz_t *x)
{
    void *ctx;
    char hash[text->HashLen];

    /* x = H(salt | H(user | ':' | pass))
     *
     */      

    text->HashInit(text->utils, NULL, 0, &ctx);

    text->HashUpdate(text->utils, ctx, (char*) user, strlen(user));
    text->HashUpdate(text->utils, ctx, ":", 1);
    text->HashUpdate(text->utils, ctx, (char*) pass, passlen);

    text->HashFinal(text->utils, hash, ctx);


    text->HashInit(text->utils, NULL, 0, &ctx);

    text->HashUpdate(text->utils, ctx, (char*) salt, saltlen);
    text->HashUpdate(text->utils, ctx, hash, text->HashLen);

    text->HashFinal(text->utils, hash, ctx);

    DataToBigInt(hash, text->HashLen, x);

    return SASL_OK;
}

/* Calculate shared context key K
 *
 * User:  x = H(s, password)
 * User:  S = (B - g^x) ^ (a + ux) % N
 *                  
 * User:  K = Hi(S)
 *
 */
static int
CalculateK_client(context_t *text,
		  char *salt,
		  int saltlen,
		  char *user,
		  char *pass,
		  int passlen,
		  char **key,
		  int *keylen)
{
    int r;
    unsigned char hash[text->HashLen];
    mpz_t x;
    mpz_t u;
    mpz_t aux;
    mpz_t gx;
    mpz_t base;
    mpz_t S;

    r = CalculateX(text, salt, saltlen, user, pass, passlen, &x);
    if (r) return r;

    /* gx = g^x */
    mpz_init(gx);
    mpz_powm (gx, text->g, x, text->N);

    /* base = B - gx */
    mpz_init(base);
    mpz_sub(base, text->B, gx);

    /* u is first 32 bits of B hashed; MSB first */
    r = HashBigInt(text, text->B, hash);
    if (r) return r;
    mpz_init(u);
    DataToBigInt(hash, 4, &u);

    /* a + ux */
    mpz_init(aux);
    mpz_mul(aux, u, x);
    mpz_add(aux, aux, text->a);

    /* S = base^aux % N */
    mpz_init(S);
    mpz_powm (S, base, aux, text->N);

    /* K = Hi(S) */
    r = HashInterleaveBigInt(text, S, key, keylen);
    if (r) return r;

    return SASL_OK;
}



/*
 *  H(
 *            bytes(H( bytes(N) )) ^ bytes( H( bytes(g) )))
 *          | bytes(H( bytes(U) ))
 *          | bytes(s)
 *          | bytes(H( bytes(L) ))
 *          | bytes(A)
 *          | bytes(B)
 *          | bytes(K)
 *      )
 *
 * H() is the result of digesting the designated input/data with the
 * underlying Message Digest Algorithm function (see Section 1).
 *
 * ^ is the bitwise XOR operator.
 */
static int
CalculateM1(context_t *text,
	    mpz_t N,
	    mpz_t g,
	    char *U,     /* username */
	    char *salt, int saltlen,  /* salt */
	    char *L,     /* server's options */
	    mpz_t A,     /* client's public key */
	    mpz_t B,     /* server's public key */
	    char *K, int Klen,
	    char **out, int *outlen)
{
    int i;
    int r;
    unsigned char p1a[text->HashLen];
    unsigned char p1b[text->HashLen];
    unsigned char p1[text->HashLen];
    int p1len;
    char p2[text->HashLen];
    int p2len;
    char *p3;
    int p3len;
    char p4[1024];
    int p4len;
    char p5[1024];
    int p5len;
    char *p6;
    int p6len;
    char p7[text->HashLen];
    int p7len;
    char *tot;
    int totlen = 0;
    char *totp;

    /* p1) bytes(H( bytes(N) )) ^ bytes( H( bytes(g) )) */
    r = HashBigInt(text, N, p1a);
    if (r) return r;
    r = HashBigInt(text, g, p1b);
    if (r) return r;

    for (i = 0; i < text->HashLen; i++) {
	p1[i] = (p1a[i] ^ p1b[i]);
    }
    p1len = text->HashLen;

    /* p2) bytes(H( bytes(U) )) */
    HashData(text, U, strlen(U), p2);
    p2len = text->HashLen;

    /* p3) bytes(s) */
    p3 = salt;
    p3len = saltlen;

    /* p4) bytes(A) */
    r = BigIntToBytes(A, p4, sizeof(p4), &p4len);
    if (r) return r;
    
    /* p5) bytes(B) */
    r = BigIntToBytes(B, p5, sizeof(p5), &p5len);
    if (r) return r;

    /* p6) bytes(K) */
    p6 = K;
    p6len = Klen;

    /* p7) bytes(H( bytes(L) )) */
    HashData(text, L, strlen(L), p7);
    p7len = text->HashLen;

    /* merge p1-p7 together */
    totlen = p1len + p2len + p3len + p4len + p5len + p6len + p7len;
    tot = text->utils->malloc(totlen);
    if (!tot) return SASL_NOMEM;

    totp = tot;

    memcpy(totp, p1, p1len); totp+=p1len;
    memcpy(totp, p2, p2len); totp+=p2len;
    memcpy(totp, p3, p3len); totp+=p3len;
    memcpy(totp, p4, p4len); totp+=p4len;
    memcpy(totp, p5, p5len); totp+=p5len;
    memcpy(totp, p6, p6len); totp+=p6len;
    memcpy(totp, p7, p7len); totp+=p7len;

    /* do the hash over the whole thing */
    *out = text->utils->malloc(text->HashLen);
    if (!*out) {
	text->utils->free(tot);
	return SASL_NOMEM;
    }
    *outlen = text->HashLen;

    HashData(text, tot, totlen, *out);
    text->utils->free(tot);

    return SASL_OK;
}

/*
 *          H(
 *                  bytes(A)
 *                | bytes(H( bytes(U) ))
 *                | bytes(H( bytes(I) ))
 *                | bytes(H( bytes(o) ))
 *                | bytes(M1)
 *                | bytes(K)
 *            )
 *
 *
 *where: 
 *
 * H() is the result of digesting the designated input/data with the
 * underlying Message Digest Algorithm function (see Section 1)
 *
 */
static int
CalculateM2(context_t *text,
	    mpz_t A,
	    char *U,
	    char *I,
	    char *o,
	    char *M1, int M1len,
	    char *K, int Klen,
	    char **out, int *outlen)
{
    int r;
    unsigned char p1[1024];
    int p1len;
    char *p2;
    int p2len;
    char *p3;
    int p3len;
    char p4[text->HashLen];
    int p4len;
    char p5[text->HashLen];
    int p5len;
    char p6[text->HashLen];
    int p6len;
    char *tot;
    int totlen = 0;
    char *totp;

    /* p1) bytes(A) */
    r = BigIntToBytes(A, p1, sizeof(p1), &p1len);
    if (r) return r;    

    /* p2) bytes(M1) */
    p2 = M1;
    p2len = M1len;
    
    /* p3) bytes(K) */
    p3 = K;
    p3len = Klen;
	
    /* p4) bytes(H( bytes(U) )) */
    HashData(text, U, strlen(U), p4);
    p4len = text->HashLen;

    /* p5) bytes(H( bytes(I) )) */
    HashData(text, I, strlen(I), p5);
    p5len = text->HashLen;

    /* p6) bytes(H( bytes(o) )) */
    HashData(text, o, strlen(o), p6);
    p6len = text->HashLen;

    /* merge p1-p6 together */
    totlen = p1len + p2len + p3len + p4len + p5len + p6len;
    tot = text->utils->malloc(totlen);
    if (!tot) return SASL_NOMEM;

    totp = tot;

    memcpy(totp, p1, p1len); totp+=p1len;
    memcpy(totp, p2, p2len); totp+=p2len;
    memcpy(totp, p3, p3len); totp+=p3len;
    memcpy(totp, p4, p4len); totp+=p4len;
    memcpy(totp, p5, p5len); totp+=p5len;
    memcpy(totp, p6, p6len); totp+=p6len;

    /* do the hash over the whole thing */
    *out = text->utils->malloc(text->HashLen);
    if (!*out) {
	return SASL_NOMEM;
	text->utils->free(tot);
    }
    *outlen = text->HashLen;

    HashData(text, tot, totlen, *out);
    text->utils->free(tot);

    return SASL_OK;
}

/* Parse an option out of an option string
 * Place found option in 'option'
 * 'nextptr' points to rest of string or NULL if at end
 */
static int
ParseOption(const sasl_utils_t *utils, char *in, char **option, char **nextptr)
{
    char *comma;
    int len;
    int i;

    if (strlen(in) == 0) {
	*option = NULL;
	return SASL_OK;
    }

    comma = strchr(in,',');    
    if (comma == NULL) comma = in + strlen(in);

    len = comma - in;

    *option = utils->malloc(len + 1);
    if (!*option) return SASL_NOMEM;

    /* lowercase string */
    for (i = 0; i < len; i++) {
	(*option)[i] = tolower((int)in[i]);
    }
    (*option)[len] = '\0';

    if (*comma) {
	*nextptr = comma+1;
    } else {
	*nextptr = NULL;
    }

    return SASL_OK;
}

static int
FindBit(char *name, layer_option_t *opts)
{
    while (opts->name) {
	VL(("Looking for [%s] this is [%s]\n",name,opts->name));
	if (strcmp(name, opts->name)==0) {
	    return opts->bit;
	}

	opts++;
    }

    return 0;
}

static layer_option_t *
FindOptionFromBit(int bit, layer_option_t *opts)
{
    while (opts->name) {
	if (opts->bit == bit) {
	    return opts;
	}

	opts++;
    }

    return NULL;
}

static int
ParseOptionString(char *str, srp_options_t *opts)
{
    if (strcmp(str,OPTION_REPLAY_DETECTION)==0) {
	if (opts->replay_detection) {
	    VL(("Replay Detection option appears twice\n"));
	    return SASL_FAIL;
	}
	opts->replay_detection = 1;
    } else if (strncmp(str,OPTION_INTEGRITY,strlen(OPTION_INTEGRITY))==0) {

	int bit = FindBit(str+strlen(OPTION_INTEGRITY), integrity_options);

	if (bit == 0) return SASL_OK;

	if (bit & opts->integrity) {
	    VL(("Option %s exists multiple times\n",str));
	    return SASL_FAIL;
	}

	opts->integrity = opts->integrity | bit;

    } else if (strncmp(str,OPTION_CONFIDENTIALITY,
		       strlen(OPTION_CONFIDENTIALITY))==0) {

	int bit = FindBit(str+strlen(OPTION_CONFIDENTIALITY),
			  confidentiality_options);
	if (bit == 0) return SASL_OK;

	if (bit & opts->confidentiality) {
	    VL(("Option %s exists multiple times\n",str));
	    return SASL_FAIL;
	}

	opts->confidentiality = opts->confidentiality | bit;

    } else {
	VL(("Option not undersood: %s\n",str));
	return SASL_FAIL;
    }

    return SASL_OK;
}

static int
ParseOptions(const sasl_utils_t *utils, char *in, srp_options_t *out)
{
    int r;

    memset(out, 0, sizeof(srp_options_t));

    while (in) {
	char *opt;

	r = ParseOption(utils, in, &opt, &in);
	if (r) return r;

	if (opt == NULL) return SASL_OK;

	VL(("Got option: [%s]\n",opt));

	r = ParseOptionString(opt, out);
	if (r) return r;
    }

    return SASL_OK;
}

static layer_option_t *
FindBest(int available, layer_option_t *opts)
{
    while (opts->name) {
	VL(("FindBest %d %d\n",available, opts->bit));

	if (available & opts->bit) {
	    return opts;
	}

	opts++;
    }

    return NULL;
}

static int
OptionsToString(const sasl_utils_t *utils, srp_options_t *opts, char **out)
{
    char *ret = NULL;
    int alloced = 0;
    int first = 1;
    layer_option_t *optlist;

    ret = utils->malloc(1);
    if (!ret) return SASL_NOMEM;
    alloced = 1;
    ret[0] = '\0';

    if (opts->replay_detection) {
	alloced += strlen(OPTION_REPLAY_DETECTION)+1;
	ret = utils->realloc(ret, alloced);
	if (!ret) return SASL_NOMEM;

	if (!first) strcat(ret, ",");
	strcat(ret, OPTION_REPLAY_DETECTION);
	first = 0;
    }

    optlist = integrity_options;
    while(optlist->name) {
	if (opts->integrity & optlist->bit) {
	    alloced += strlen(OPTION_INTEGRITY)+strlen(optlist->name)+1;
	    ret = utils->realloc(ret, alloced);
	    if (!ret) return SASL_NOMEM;

	    if (!first) strcat(ret, ",");
	    strcat(ret, OPTION_INTEGRITY);
	    strcat(ret, optlist->name);
	    first = 0;
	}

	optlist++;
    }

    optlist = confidentiality_options;
    while(optlist->name) {
	if (opts->confidentiality & optlist->bit) {
	    alloced += strlen(OPTION_CONFIDENTIALITY)+strlen(optlist->name)+1;
	    ret = utils->realloc(ret, alloced);
	    if (!ret) return SASL_NOMEM;

	    if (!first) strcat(ret, ",");
	    strcat(ret, OPTION_CONFIDENTIALITY);
	    strcat(ret, optlist->name);
	    first = 0;
	}

	optlist++;
    }
    
    *out = ret;
    return SASL_OK;
}

static int
CreateServerOptions(const sasl_utils_t *utils,
		    sasl_security_properties_t *props,
		    char **out)
{
    srp_options_t opts;
    layer_option_t *optlist;

    /* zero out options */
    memset(&opts,0,sizeof(srp_options_t));

    /* Add integrity options */
    optlist = integrity_options;
    while(optlist->name) {
	if ((props->min_ssf <= 1) && (props->max_ssf >= 1)) {
	    opts.integrity |= optlist->bit;
	}
	optlist++;
    }

    /* if we set any integrity options we can advertise replay detection */
    if (opts.integrity) {
	opts.replay_detection = 1;
    }

    /* Add integrity options */
    optlist = confidentiality_options;
    while(optlist->name) {
	if (((int)props->min_ssf <= optlist->ssf) &&
	    ((int)props->max_ssf >= optlist->ssf)) {
	    opts.confidentiality |= optlist->bit;
	}
	optlist++;
    }

    return OptionsToString(utils, &opts, out);
}
		    

static int
CreateClientOpts(sasl_client_params_t *params, 
		 srp_options_t *available, 
		 srp_options_t *out)
{
    int external;
    int limit;
    int musthave;

    /* zero out output */
    memset(out, 0, sizeof(srp_options_t));

    /* get requested ssf */
    external = params->external_ssf;

    /* what do we _need_?  how much is too much? */
    if ((int)params->props.max_ssf > external) {
	limit = params->props.max_ssf - external;
    } else {
	limit = 0;
    }
    if ((int)params->props.min_ssf > external) {
	musthave = params->props.min_ssf - external;
    } else {
	musthave = 0;
    }

    /* we now go searching for an option that gives us at least "musthave"
       and at most "limit" bits of ssf. */
    if ((limit > 1) && (available->confidentiality)) {
	VL(("xxx No good privacy layers\n"));
	return SASL_FAIL;
    }

    VL(("Available integrity = %d\n",available->integrity));

    if ((limit >= 1) && (musthave <= 1) && (available->integrity)) {
	/* integrity */
	layer_option_t *iopt;
	
	iopt = FindBest(available->integrity, integrity_options);
	
	if (iopt) {
	    out->integrity = iopt->bit;
	    return SASL_OK;
	}
    }

    if (musthave <= 0) { /* xxx how do we know if server doesn't support no layer??? */
	/* no layer */
	return SASL_OK;

    }

    
    VL(("Can't find an acceptable layer\n"));
    return SASL_TOOWEAK;
}

/* Set the options (called my client and server)
 *
 * Set up variables/hashes/that sorta thing so layers
 * will operate properly
 */
static int
SetOptions(srp_options_t *opts,
	   context_t *text,
	   const sasl_utils_t *utils,
	   sasl_out_params_t *oparams)
{
    text->size=-1;
    text->needsize=4;

    if ((opts->integrity == 0) && (opts->confidentiality == 0)) {
	oparams->encode = NULL;
	oparams->decode = NULL;
	oparams->mech_ssf = 0;
	VL(("Using no layer\n"));	
	return SASL_OK;
    }
    
    oparams->encode = &layer_encode;
    oparams->decode = &layer_decode;

    text->enabled_replay_detection = opts->replay_detection;

    if (opts->integrity) {
	layer_option_t *iopt;

	text->enabled_integrity_layer = 1;
	oparams->mech_ssf = 1;

	iopt = FindOptionFromBit(opts->integrity, integrity_options);
	if (!iopt) {
	    VL(("Unable to find integrity layer option now\n"));
	    return SASL_FAIL;
	}

	text->IntegHashLen    = iopt->HashLen(utils);
	text->IntegHashInit   = iopt->HashInit;
	text->IntegHashUpdate = iopt->HashUpdate;
	text->IntegHashFinal  = iopt->HashFinal;
    }

    /* conf foo */

    return SASL_OK;
}


#ifdef WITH_SHA1
static int
srp_sha1_server_mech_new(void *glob_context __attribute__((unused)),
			 sasl_server_params_t *params,
			 const char *challenge __attribute__((unused)),
			 unsigned challen __attribute__((unused)),
			 void **conn)
{
  context_t *text;

  /* holds state are in */
  if (!conn)
      return SASL_BADPARAM;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) {
      MEMERROR(params->utils);
      return SASL_NOMEM;
  }

  memset(text, 0, sizeof(context_t));

  text->state = 1;
  text->utils = params->utils;
  text->propName = "SRP-SHA-160";
  text->HashLen    = srp_sha1Len(text->utils);
  text->HashInit   = srp_sha1Init;
  text->HashUpdate = srp_sha1Update;
  text->HashFinal  = srp_sha1Final;

  *conn=text;

  return SASL_OK;
}
#endif /* WITH_SHA1 */

static int
srp_md5_server_mech_new(void *glob_context __attribute__((unused)),
			sasl_server_params_t *params,
			const char *challenge __attribute__((unused)),
			unsigned challen __attribute__((unused)),
			void **conn)
{
  context_t *text;

  /* holds state are in */
  if (!conn)
      return SASL_BADPARAM;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) {
      MEMERROR(params->utils);
      return SASL_NOMEM;
  }

  memset(text, 0, sizeof(context_t));

  text->state = 1;
  text->utils = params->utils;
  text->propName = "SRP-MD5-120";
  text->HashLen    = srp_md5Len(text->utils);
  text->HashInit   = srp_md5Init;
  text->HashUpdate = srp_md5Update;
  text->HashFinal  = srp_md5Final;

  *conn=text;

  return SASL_OK;
}


/* N in base16 */
#define BIGN_STRING "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

/* A large safe prime (N = 2q+1, where q is prime)
 * All arithmetic is done modulo N
 */
static int generate_N_and_g(mpz_t N, mpz_t g)
{
    int result;
    
    mpz_init(N);
    result = mpz_set_str (N, BIGN_STRING, 16);
    if (result) return SASL_FAIL;

    mpz_init(g);
    mpz_set_ui (g, 2);

    return SASL_OK;
}

static int
ServerCalculateK(context_t *text, mpz_t v,
		 mpz_t N, mpz_t g, mpz_t b, mpz_t B, mpz_t A,
		 char **key, int *keylen)
{
    unsigned char hash[text->HashLen];
    mpz_t u;
    mpz_t S;
    int r;

    /* B = (v + g^b) % N */
    mpz_init(B);

    mpz_powm(B, g, b, N);
    mpz_add(B, B, v);
    mpz_mod(B, B, N);

    /* calculate K
     *
     * Host:  S = (Av^u) ^ b % N             (computes session key)
     * Host:  K = Hi(S)
     */

    /* u is first 32 bits of B hashed; MSB first */
    r = HashBigInt(text, B, hash);
    if (r) return r;

    mpz_init(u);
    DataToBigInt(hash, 4, &u);

    mpz_init(S);
    mpz_powm(S, v, u, N);
    mpz_mul(S, S, A);
    mpz_mod(S, S, N);

    mpz_powm(S, S, b, N);

    /* K = Hi(S) */
    r = HashInterleaveBigInt(text, S, key, keylen);
    if (r) return r;

    return SASL_OK;
}

static int
server_step1(context_t *text,
	     sasl_server_params_t *params,
	     const char *clientin,
	     unsigned clientinlen,
	     const char **serverout,
	     unsigned *serveroutlen,
	     sasl_out_params_t *oparams __attribute__((unused)))
{
    char *data;
    int datalen;
    int r;    
    char *mpiN = NULL;
    int mpiNlen;
    char *mpig = NULL;
    int mpiglen;
    char *osS = NULL;
    int osSlen;
    char *utf8L = NULL;
    int utf8Llen;
    char *realm = NULL;
    char *user = NULL;

    /* if nothing we send nothing and except data next time */
    if ((clientinlen == 0) && (text->state == 1)) {
	text->state++;
	*serverout = NULL;
	*serveroutlen = 0;
	return SASL_CONTINUE;
    }

    /* Expect:
     *
     * { utf8(U) }
     *
     */
    r = UnBuffer((char *) clientin, clientinlen, &data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
			      "Error 'unbuffer'ing input for step 1");
      return r;
    }

    r = GetUTF8(params->utils, data, datalen, &text->authid, &data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
			      "Error getting UTF8 string from input");
      return r;
    }

    if (datalen != 0) {
      params->utils->seterror(params->utils->conn, 0, 
	"Extra data to SRP step 1");
      return SASL_FAIL;
    }

    /* Get the realm */
    r = parseuser(params->utils, &user, &realm, params->user_realm,
    		  params->serverFQDN, text->authid);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error getting realm");
      goto fail;
    }

    /* Get user data */
    r = ReadUserInfo(params->utils, user, realm, text->propName,
		     &text->N, &text->g, &text->salt, &text->saltlen,
		     &text->v);
    if (r) {
	/* readuserinfo sets error, if any */
	goto fail;
    }

    r = CreateServerOptions(params->utils, &params->props,
			    &text->server_options);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error creating server options");
      goto fail;
    }

    /* Send out:
     *
     * N - safe prime modulus
     * g - generator
     * s - salt
     * L - server options (available layers etc)
     *
     * { mpi(N) mpi(g) os(s) utf8(L) }
     *
     */
    
    r = MakeMPI(params->utils, text->N, &mpiN, &mpiNlen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error creating 'mpi' string for N");
      goto fail;
    }
    
    r = MakeMPI(params->utils, text->g, &mpig, &mpiglen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error creating 'mpi' string for g");
      goto fail;
    }
    
    r = MakeOS(params->utils, text->salt, text->saltlen, &osS, &osSlen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error turning salt into 'os' string");
      goto fail;
    }
    
    r = MakeUTF8(params->utils, text->server_options, &utf8L, &utf8Llen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error creating 'UTF8' string for L (server options)");
      goto fail;
    }
    
    r = MakeBuffer(params->utils, mpiN, mpiNlen, mpig, mpiglen, osS, osSlen,
		   utf8L, utf8Llen, serverout, serveroutlen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error creating SRP buffer from data in step 1");
      goto fail;
    }

    r = SASL_CONTINUE;
    text->state++;

 fail:

    if (user)   params->utils->free(user);
    if (realm)  params->utils->free(realm);
    if (mpiN)   params->utils->free(mpiN);
    if (mpig)   params->utils->free(mpig);
    if (osS)    params->utils->free(osS);
    if (utf8L)  params->utils->free(utf8L);

    return r;
}

static int
server_step2(context_t *text,
	     sasl_server_params_t *params,
	     const char *clientin,
	     unsigned clientinlen,
	     const char **serverout,
	     unsigned *serveroutlen,
	     sasl_out_params_t *oparams __attribute__((unused)))
{
    char *data;
    int datalen;
    int r;    
    char *mpiB = NULL;
    int mpiBlen;
    srp_options_t client_opts;

    /* Expect:
     *
     * A - client's public key
     * I - authorization
     * o - client option list
     *
     * { mpi(A) utf8(I) utf8(o) }
     *
     */
    r = UnBuffer((char *) clientin, clientinlen, &data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error UnBuffering input in step 2");
      return r;
    }

    r = GetMPI(data, datalen, &text->A, &data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error parsing out 'A'");
      return r;
    }

    r = GetUTF8(params->utils, data, datalen, &text->userid, &data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error parsing out userid");
      return r;
    }

    r = GetUTF8(params->utils, data, datalen, &text->client_options,
		&data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error parsing out client options 'o'");
      return r;
    }

    if (datalen != 0) {
      params->utils->seterror(params->utils->conn, 0, 
	"Extra data in request step 2");
      return SASL_FAIL;
    }

    /* Generate b */
    GetRandBigInt(text->b);

    /* Calculate K (and B) */
    r = ServerCalculateK(text, text->v,
			 text->N, text->g, text->b, text->B, text->A,
			 &text->K, &text->Klen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error calculating K");
      return r;
    }

    /* parse client options */
    r = ParseOptions(params->utils, text->client_options, &client_opts);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error parsing user's options");
      return r;
    }

    r = SetOptions(&client_opts, text, params->utils, oparams);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error setting options");
      return r;   
    }

    /* Send out:
     *
     * B - server's public key
     *
     * { mpi(B) }
     */

    
    r = MakeMPI(params->utils, text->B, &mpiB, &mpiBlen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error turning 'B' into 'mpi' string");
      goto end;
    }
    
    r = MakeBuffer(params->utils, mpiB, mpiBlen, NULL, 0, NULL, 0, NULL, 0,
		   serverout, serveroutlen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error putting all the data together in step 2");
      goto end;
    }
    
    text->state ++;
    r = SASL_CONTINUE;

 end:
    if (mpiB)    params->utils->free(mpiB);

    return r;
}


static int
server_step3(context_t *text,
	     sasl_server_params_t *params,
	     const char *clientin,
	     unsigned clientinlen,
	     const char **serverout,
	     unsigned *serveroutlen,
	     sasl_out_params_t *oparams __attribute__((unused)))
{
    char *data;
    int datalen;
    int r;    
    char *M1 = NULL;
    int M1len;
    char *myM1 = NULL;
    int myM1len;
    char *M2 = NULL;
    int M2len;
    int i;
    char *osM2 = NULL;
    int osM2len;
    
    /* Expect:
     *
     * M1 = client evidence
     *
     * { os(M1) }
     *
     */
    r = UnBuffer((char *) clientin, clientinlen, &data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error parsing input buffer in step 3");
      goto end;
    }

    r = GetOS(params->utils, data, datalen, &M1,&M1len, &data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error getting 'os' M1 (client evidenice)");
      goto end;
    }

    if (datalen != 0) {
      r = SASL_FAIL;
      params->utils->seterror(params->utils->conn, 0, 
	"Extra data in input SRP step 3");
      goto end;
    }

    /* See if M1 is correct */
    r = CalculateM1(text, text->N, text->g, text->authid,
		    text->salt, text->saltlen,
		    text->server_options, text->A, text->B,
		    text->K, text->Klen, &myM1, &myM1len);
    if (r) {	
      params->utils->seterror(params->utils->conn, 0, 
	"Error calculating M1");
      goto end;
    }

    if (myM1len != M1len) {
      params->utils->seterror(params->utils->conn, 0, 
	"M1 lengths do not match");
      VL(("M1 lengths do not match: %d vs %d",M1len, myM1len));
      goto end;
    }

    for (i = 0; i < myM1len; i++) {
	if (myM1[i] != M1[i]) {
	    params->utils->seterror(params->utils->conn, 0, 
				    "client evidence does not match what we "
				    "calculated. Probably a password error");
	    r = SASL_BADAUTH;
	    goto end;
	}
    }

    /* calculate M2 to send */
    r = CalculateM2(text, text->A, text->authid, text->userid,
		    text->client_options, myM1, myM1len, text->K, text->Klen,
		    &M2, &M2len);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error calculating M2 (server evidence)");
      goto end;
    }
    
    /* Send out:
     *
     * M2 = server evidence
     *
     * { os(M2) }
     */
    
    r = MakeOS(params->utils, M2, M2len, &osM2, &osM2len);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error making 'os' string from M2 (server evidence)");
      goto end;
    }
    
    r = MakeBuffer(params->utils, osM2, osM2len, NULL, 0, NULL, 0, NULL, 0,
		   serverout, serveroutlen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error making output buffer in SRP step 3");
      goto end;
    }
    
    text->state ++;
    r = SASL_CONTINUE;
 end:

    if (osM2)   params->utils->free(osM2);
    if (M2)     params->utils->free(M2);
    if (myM1)   params->utils->free(myM1);
    if (M1)     params->utils->free(M1);

    return r;    
}

static int
server_step4(context_t *text,
	     sasl_server_params_t *params,
	     const char *clientin __attribute__((unused)),
	     unsigned clientinlen,
	     const char **serverout,
	     unsigned *serveroutlen,
	     sasl_out_params_t *oparams)
{
    if (clientinlen > 0) {
      params->utils->seterror(params->utils->conn, 0, 
	"Data is not valid in SRP step 4");
      return SASL_FAIL;
    }

    /* Set oparams */
    oparams->doneflag=1;

    oparams->authid = text->authid;
    text->authid = NULL; /* set to null so we don't free */
    oparams->user = text->userid; /* set username */
    text->userid = NULL; /* set to null so we don't free */

    // xxx ghomsy:
    // Realm is no longer a member of sasl_out_params_t
    // why??

    //    oparams->realm = NULL;
    
    oparams->param_version = 0;

    *serverout = NULL;
    *serveroutlen = 0;

    text->state++;
    return SASL_OK;
}


static int
srp_server_mech_step(void *conn_context,
		     sasl_server_params_t *sparams,
		     const char *clientin,
		     unsigned clientinlen,
		     const char **serverout,
		     unsigned *serveroutlen,
		     sasl_out_params_t *oparams)
{
  context_t *text = (context_t *) conn_context;

  if (!sparams
      || !serverout
      || !serveroutlen
      || !oparams)
    return SASL_BADPARAM;

  sparams->utils->log(NULL, SASL_LOG_ERR, "SRP server step %d\n",text->state);

  switch(text->state)
      {
      case 1:
	  return server_step1(text, sparams, clientin, clientinlen,
			      serverout, serveroutlen, oparams);
      case 2:
	  return server_step2(text, sparams, clientin, clientinlen,
			      serverout, serveroutlen, oparams);
      case 3:
	  return server_step3(text, sparams, clientin, clientinlen,
			      serverout, serveroutlen, oparams);
      case 4:
	  return server_step4(text, sparams, clientin, clientinlen,
			      serverout, serveroutlen, oparams);
      default:
	  sparams->utils->seterror(sparams->utils->conn, 0,
				   "Invalid SRP server step");
	  return SASL_FAIL;
      }
}


static int
ReadUserInfo(const sasl_utils_t *utils, char *authid, char *realm,
	     const char *propName,
	     mpz_t *N, mpz_t *g, char **salt, int *saltlen, mpz_t *v)
{
    char secret[8192];
    size_t seclen;
    int r;
    char *data;
    int datalen;

    /* fetch the secret using the sasldb interface */
    r = (*_sasldb_getdata)(utils, utils->conn,
			   authid, realm, propName,
			   secret, sizeof(secret), &seclen);

    if (r) {
      utils->seterror(utils->conn, 0, 
		      "unable to get user's secret");
      return r;
    }

    /* The secret data is encoded just like data we send over the wire. It has
     *
     *  salt - os 
     *  N    - mpi
     *  g    - mpi
     *  v    - mpi
     */
    r = UnBuffer(secret, seclen, &data, &datalen);
    if (r) {
      utils->seterror(utils->conn, 0, 
		      "Error UnBuffering secret data");
      return r;
    }

    r = GetOS(utils, data, datalen, salt, saltlen, &data, &datalen);
    if (r) {
      utils->seterror(utils->conn, 0, 
		      "Error parsing out salt");
      return r;
    }

    r = GetMPI(data, datalen, N, &data, &datalen);
    if (r) {
      utils->seterror(utils->conn, 0, 
		      "Error parsing out 'N'");
      return r;
    }

    r = GetMPI(data, datalen, g, &data, &datalen);
    if (r) {
      utils->seterror(utils->conn, 0, 
		      "Error parsing out 'g'");
      return r;
    }

    r = GetMPI(data, datalen, v, &data, &datalen);
    if (r) {
      utils->seterror(utils->conn, 0, 
		      "Error parsing out 'v'");
      return r;
    }

    if (datalen != 0) {
      utils->seterror(utils->conn, 0, 
		      "Extra data in request step 2");
      r = SASL_FAIL;
    }

    return r;
}

static int
GetSaveInfo(context_t *text,
	    const char *user,
	    const char *pass, unsigned passlen,
	    sasl_secret_t **sec)
{
    mpz_t N;
    mpz_t g;
    mpz_t v;
    mpz_t x;
    char salt[SRP_SALT_SIZE];
    int saltlen;
    int r;    
    char *osSalt = NULL;
    int osSaltlen;
    char *mpiN = NULL;
    int mpiNlen;
    char *mpig = NULL;
    int mpiglen;
    char *mpiv = NULL;
    int mpivlen;    
    const char *buffer = NULL;
    int bufferlen;

    /* generate <salt> */    
    saltlen = sizeof(salt);
    text->utils->rand(text->utils->rpool, salt, saltlen);

    r = generate_N_and_g(N, g);
    if (r) {
	text->utils->seterror(text->utils->conn, 0, 
		      "Error calculating N and g");
	return r;
    }

    r = CalculateX(text, salt, saltlen, user, pass, passlen, &x);
    if (r) {
	text->utils->seterror(text->utils->conn, 0, 
			      "Error calculating 'x'");
      return r;
    }

    /* v = g^x % N */
    mpz_init(v);
    mpz_powm (v, g, x, N);

    /*
     * We need to save:
     *  salt
     *  N
     *  g
     *  v
     */

    r = MakeOS(text->utils, salt, saltlen, &osSalt, &osSaltlen);
    if (r) {
	text->utils->seterror(text->utils->conn, 0, 
			      "Error turning salt into 'os' string");
	goto end;
    }
    
    r = MakeMPI(text->utils, N, &mpiN, &mpiNlen);
    if (r) {
	text->utils->seterror(text->utils->conn, 0, 
			      "Error turning 'N' into 'mpi' string");
	goto end;
    }

    r = MakeMPI(text->utils, g, &mpig, &mpiglen);
    if (r) {
	text->utils->seterror(text->utils->conn, 0, 
			      "Error turning 'g' into 'mpi' string");
	goto end;
    }
    
    r = MakeMPI(text->utils, v, &mpiv, &mpivlen);
    if (r) {
	text->utils->seterror(text->utils->conn, 0, 
			      "Error turning 'N' into 'mpi' string");
	goto end;
    }

    r = MakeBuffer(text->utils, osSalt, osSaltlen, mpiN, mpiNlen,
		   mpig, mpiglen, mpiv, mpivlen, &buffer, &bufferlen);
    if (r) {
	text->utils->seterror(text->utils->conn, 0, 
			      "Error putting all the data together in step 2");
	goto end;
    }    
    
    /* Put 'buffer' into sasl_secret_t */
    *sec = text->utils->malloc(sizeof(sasl_secret_t)+bufferlen+1);
    if (!*sec) {
	r = SASL_NOMEM;
	goto end;
    }
    memcpy((*sec)->data, buffer, bufferlen);
    (*sec)->len = bufferlen;    

    /* Clean everything up */
 end:
    if (osSalt) text->utils->free(osSalt);
    if (mpiN)   text->utils->free(mpiN);
    if (mpig)   text->utils->free(mpig);
    if (mpiv)   text->utils->free(mpiv);
    if (buffer) text->utils->free((void *) buffer);
    mpz_clear(N);
    mpz_clear(g);
    mpz_clear(v);
    mpz_clear(x);

    return r;   
}

static int
srp_setpass(context_t *text,
	    sasl_server_params_t *sparams,
	    const char *userstr,
	    const char *pass,
	    unsigned passlen,
	    unsigned flags)
{
    int r;
    char *user = NULL;
    char *realm = NULL;
    sasl_secret_t *sec;

    r = parseuser(sparams->utils, &user, &realm, sparams->user_realm,
		       sparams->serverFQDN, userstr);
    if (r) {
      sparams->utils->seterror(sparams->utils->conn, 0, 
	"Error parsing user");
      return r;
    }

    if ((flags & SASL_SET_DISABLE) || pass == NULL) {
	sec = NULL;
    } else {
      r = GetSaveInfo(text, user, pass, passlen, &sec);
	if (r) {
	  sparams->utils->seterror(sparams->utils->conn, 0, 
				   "Error creating data for SRP to save");
	  return r;
	}
    }

    /* do the store */
    r = (*_sasldb_putdata)(sparams->utils, sparams->utils->conn,
			   user, realm, text->propName, sec->data, sec->len);

    if (r) {
      sparams->utils->seterror(sparams->utils->conn, 0, 
	"Error putting secret");
      goto cleanup;
    }

    VL(("Setpass for SRP successful\n"));

 cleanup:

    if (user) 	sparams->utils->free(user);
    if (realm) 	sparams->utils->free(realm);
    if (sec)    sparams->utils->free(sec);

    return r;
}

#ifdef WITH_SHA1
static int
srp_sha1_setpass(void *glob_context __attribute__((unused)),
		 sasl_server_params_t *sparams,
		 const char *userstr,
		 const char *pass,
		 unsigned passlen,
		 const char *oldpass __attribute__((unused)),
		 unsigned oldpasslen __attribute__((unused)),
		 unsigned flags)
{
    context_t text;

    text.utils = sparams->utils;
    text.propName = "SRP-MD5-120";
    text.HashLen    = srp_sha1Len(text.utils);
    text.HashInit   = srp_sha1Init;
    text.HashUpdate = srp_sha1Update;
    text.HashFinal  = srp_sha1Final;

    return srp_setpass(&text, sparams, userstr,
		       pass, passlen, flags);
}
#endif /* WITH_SHA1 */

static int
srp_md5_setpass(void *glob_context __attribute__((unused)),
		sasl_server_params_t *sparams,
		const char *userstr,
		const char *pass,
		unsigned passlen,
		const char *oldpass __attribute__((unused)),
		unsigned oldpasslen __attribute__((unused)),
		unsigned flags)
{
    context_t text;

    text.utils = sparams->utils;
    text.propName = "SRP-MD5-120";
    text.HashLen    = srp_md5Len(text.utils);
    text.HashInit   = srp_md5Init;
    text.HashUpdate = srp_md5Update;
    text.HashFinal  = srp_md5Final;

    return srp_setpass(&text, sparams, userstr,
		       pass, passlen, flags);
}


static const sasl_server_plug_t srp_server_plugins[] = 
{
#ifdef WITH_SHA1
  {
    "SRP-SHA-160",	        /* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* glob_context */
    &srp_sha1_server_mech_new,	/* mech_new */
    &srp_server_mech_step,	/* mech_step */
    &srp_both_mech_dispose,	/* mech_dispose */
    &srp_both_mech_free,	/* mech_free */
    &srp_sha1_setpass,		/* setpass */
    NULL,			/* user_query */
    NULL,			/* idle */
    NULL,			/* mech avail */
    NULL			/* spare */
  },
#endif /* WITH_SHA1 */
  {
    "SRP-MD5-120",	        /* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* glob_context */
    &srp_md5_server_mech_new,	/* mech_new */
    &srp_server_mech_step,	/* mech_step */
    &srp_both_mech_dispose,	/* mech_dispose */
    &srp_both_mech_free,	/* mech_free */
    &srp_md5_setpass,		/* setpass */
    NULL,			/* user_query */
    NULL,			/* idle */
    NULL,			/* mech avail */
    NULL			/* spare */
  }
};

int srp_server_plug_init(const sasl_utils_t *utils __attribute__((unused)),
			 int maxversion,
			 int *out_version,
			 const sasl_server_plug_t **pluglist,
			 int *plugcount,
			 const char *plugname __attribute__((unused)))
{
    if (maxversion<SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "SRP version mismatch");
	return SASL_BADVERS;
    }

    /* Do we have database support? */
    /* Note that we can use a NULL sasl_conn_t because our
     * sasl_utils_t is "blessed" with the global callbacks */
    if(_sasl_check_db(utils, NULL) != SASL_OK)
	return SASL_NOMECH;

    *pluglist=srp_server_plugins;

    *plugcount=sizeof(srp_server_plugins)/sizeof(sasl_server_plug_t);
    *out_version=SASL_SERVER_PLUG_VERSION;

    return SASL_OK;
}

/* put in sasl_wrongmech */
#ifdef WITH_SHA1
static int srp_sha1_client_mech_new(void *glob_context __attribute__((unused)),
			       sasl_client_params_t *params,
			       void **conn)
{
    context_t *text;

    /* holds state are in */
    text = params->utils->malloc(sizeof(context_t));
    if (text==NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(context_t));

    text->state=1;
    text->utils = params->utils;
    text->HashLen    = srp_sha1Len(text->utils);
    text->HashInit   = srp_sha1Init;
    text->HashUpdate = srp_sha1Update;
    text->HashFinal  = srp_sha1Final;

    *conn=text;

    return SASL_OK;
}
#endif /* WITH_SHA1 */

static int srp_md5_client_mech_new(void *glob_context __attribute__((unused)),
			       sasl_client_params_t *params,
			       void **conn)
{
    context_t *text;

    /* holds state are in */
    text = params->utils->malloc(sizeof(context_t));
    if (text==NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(context_t));

    text->state=1;
    text->utils = params->utils;
    text->HashLen    = srp_md5Len(text->utils);
    text->HashInit   = srp_md5Init;
    text->HashUpdate = srp_md5Update;
    text->HashFinal  = srp_md5Final;

    *conn=text;

    return SASL_OK;
}

/* 
 * Trys to find the prompt with the lookingfor id in the prompt list
 * Returns it if found. NULL otherwise
 */
static sasl_interact_t *find_prompt(sasl_interact_t **promptlist,
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

/*
 * Somehow retrieve the userid
 * This is the same as in digest-md5 so change both
 */
static int get_userid(sasl_client_params_t *params,
		      const char **userid,
		      sasl_interact_t **prompt_need)
{
  int result;
  sasl_getsimple_t *getuser_cb;
  void *getuser_context;
  sasl_interact_t *prompt;
  const char *id;

  /* see if we were given the userid in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_USER);
  if (prompt!=NULL)
    {
	*userid = prompt->result;
	return SASL_OK;
    }

  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_USER,
				      &getuser_cb,
				      &getuser_context);
  if (result == SASL_OK && getuser_cb) {
    id = NULL;
    result = getuser_cb(getuser_context,
			SASL_CB_USER,
			&id,
			NULL);
    if (result != SASL_OK)
      return result;
    if (! id) {
	PARAMERROR(params->utils);
	return SASL_BADPARAM;
    }
    
    *userid = id;
  }

  return result;
}

static int get_authid(sasl_client_params_t *params,
		      const char **authid,
		      sasl_interact_t **prompt_need)
{

  int result;
  sasl_getsimple_t *getauth_cb;
  void *getauth_context;
  sasl_interact_t *prompt;
  const char *id;

  /* see if we were given the authname in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_AUTHNAME);
  if (prompt!=NULL)
  {
      *authid = prompt->result;
      
      return SASL_OK;
  }

  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_AUTHNAME,
				      &getauth_cb,
				      &getauth_context);
  if (result == SASL_OK && getauth_cb) {
    id = NULL;
    result = getauth_cb(getauth_context,
			SASL_CB_AUTHNAME,
			&id,
			NULL);
    if (result != SASL_OK)
      return result;
    if (! id) {
	PARAMERROR( params->utils );
	return SASL_BADPARAM;
    }
    
    *authid = id;
  }

  return result;
}

static int get_password(sasl_client_params_t *params,
		      sasl_secret_t **password,
		      sasl_interact_t **prompt_need)
{

  int result;
  sasl_getsecret_t *getpass_cb;
  void *getpass_context;
  sasl_interact_t *prompt;

  /* see if we were given the password in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_PASS);
  if (prompt!=NULL)
  {
      /* We prompted, and got.*/
	
      if (! prompt->result) {
	  SETERROR(params->utils, "Unexpectedly missing a prompt result");
	  return SASL_FAIL;
      }
      
      /* copy what we got into a secret_t */
      *password = (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t)+
							  prompt->len+1);
      if (! *password) {
	  MEMERROR( params->utils );
	  return SASL_NOMEM;
      }
      
      (*password)->len=prompt->len;
      memcpy((*password)->data, prompt->result, prompt->len);
      (*password)->data[(*password)->len]=0;

      return SASL_OK;
  }


  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_PASS,
				      &getpass_cb,
				      &getpass_context);

  if (result == SASL_OK && getpass_cb)
    result = getpass_cb(params->utils->conn,
			getpass_context,
			SASL_CB_PASS,
			password);

  return result;
}

/*
 * Make the necessary prompts
 */
static int make_prompts(sasl_client_params_t *params,
			sasl_interact_t **prompts_res,
			int user_res,
			int auth_res,
			int pass_res)
{
  int num=1;
  sasl_interact_t *prompts;

  if (user_res==SASL_INTERACT) num++;
  if (auth_res==SASL_INTERACT) num++;
  if (pass_res==SASL_INTERACT) num++;

  if (num==1) {
      SETERROR( params->utils, "make_prompts called with no actual prompts" );
      return SASL_FAIL;
  }

  prompts=params->utils->malloc(sizeof(sasl_interact_t)*(num+1));
  if ((prompts) ==NULL) {
      MEMERROR( params->utils );
      return SASL_NOMEM;
  }
  
  *prompts_res=prompts;

  if (user_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_USER;
    (prompts)->challenge="Authorization Name";
    (prompts)->prompt="Please enter your authorization name";
    (prompts)->defresult=NULL;

    prompts++;
  }

  if (auth_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_AUTHNAME;
    (prompts)->challenge="Authentication Name";
    (prompts)->prompt="Please enter your authentication name";
    (prompts)->defresult=NULL;

    prompts++;
  }


  if (pass_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_PASS;
    (prompts)->challenge="Password";
    (prompts)->prompt="Please enter your password";
    (prompts)->defresult=NULL;

    prompts++;
  }

  /* add the ending one */
  (prompts)->id=SASL_CB_LIST_END;
  (prompts)->challenge=NULL;
  (prompts)->prompt   =NULL;
  (prompts)->defresult=NULL;

  return SASL_OK;
}

static int
client_step1(context_t *text,
	     sasl_client_params_t *params,
	     const char *serverin  __attribute__((unused)),
	     unsigned serverinlen,
	     sasl_interact_t **prompt_need,
	     const char **clientout,
	     unsigned *clientoutlen,
	     sasl_out_params_t *oparams  __attribute__((unused)))
{
    int auth_result=SASL_OK;
    int pass_result=SASL_OK;
    int user_result=SASL_OK;
    int r;
    char *utf8U = NULL;
    int utf8Ulen;

    /* Expect: 
     *   absolutly nothing
     * 
     */
    if (serverinlen > 0) {
	VL(("Invalid input to first step of SRP\n"));
	return SASL_FAIL;
    }


    /* try to get the authid */
    if (text->authid==NULL)
    {
	auth_result=get_authid(params,
			       (const char **) &text->authid,
			       prompt_need);
	  
	if ((auth_result!=SASL_OK) && (auth_result!=SASL_INTERACT))
	    return auth_result;	  
    }

    /* try to get the userid */
    if (text->userid == NULL) {
      user_result = get_userid(params,
			       (const char **) &text->userid,
			       prompt_need);

      if ((user_result != SASL_OK) && (user_result != SASL_INTERACT))
      {
	  return user_result;
      }
    }
      
    /* try to get the password */
    if (text->password==NULL)
    {
	pass_result=get_password(params,
				 &text->password,
				 prompt_need);
	
	if ((pass_result!=SASL_OK) && (pass_result!=SASL_INTERACT))
	    return pass_result;
    }
    
    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }

    /* if there are prompts not filled in */
    if ((auth_result==SASL_INTERACT) ||
	(user_result==SASL_INTERACT) ||
	(pass_result==SASL_INTERACT))
    {
	/* make the prompt list */
	int result=make_prompts(params,prompt_need,
				auth_result, user_result, pass_result);
	if (result!=SASL_OK) return result;
	
	return SASL_INTERACT;
    }

    /* send authentication identity 
     * { utf8(U) }
     */

    r = MakeUTF8(params->utils, text->authid, &utf8U, &utf8Ulen);
    if (r) goto done;

    r = MakeBuffer(params->utils, utf8U, utf8Ulen, NULL, 0, NULL, 0, NULL, 0,
		   clientout, clientoutlen);
    if (r) goto done;

    text->state++;
    r = SASL_CONTINUE;

 done:

    if (utf8U)    params->utils->free(utf8U);

    return r;
}

static int
client_step2(context_t *text,
	     sasl_client_params_t *params,
	     const char *serverin,
	     unsigned serverinlen,
	     sasl_interact_t **prompt_need __attribute__((unused)),
	     const char **clientout,
	     unsigned *clientoutlen,
	     sasl_out_params_t *oparams __attribute__((unused)))
{
    char *data;
    int datalen;
    int r;    
    char *utf8I = NULL, *mpiA = NULL, *utf8o = NULL;
    int utf8Ilen, mpiAlen, utf8olen;
    srp_options_t server_opts;

    /* expect:
     *  { mpi(N) mpi(g) os(s) utf8(L) }
     *
     */
    r = UnBuffer((char *) serverin, serverinlen, &data, &datalen);
    if (r) return r;

    r = GetMPI((unsigned char *)data, datalen, &text->N, &data, &datalen);
    if (r) {
	VL(("Error getting MPI string for 'N'\n"));
	goto done;
    }

    r = GetMPI((unsigned char *) data, datalen, &text->g, &data, &datalen);
    if (r) {
	VL(("Error getting MPI string for 'g'\n"));
	goto done;
    }

    r = GetOS(params->utils, (unsigned char *)data, datalen,
	      &text->salt, &text->saltlen, &data, &datalen);
    if (r) {
	VL(("Error getting OS string for 's'\n"));
	goto done;
    }

    r = GetUTF8(params->utils, data, datalen, &text->server_options,
		&data, &datalen);
    if (r) {
	VL(("Error getting UTF8 string for 'L'"));
	goto done;
    }

    if (datalen != 0) {
	VL(("Extra data parsing buffer\n"));
	goto done;
    }

    /* parse server options */
    memset(&server_opts, 0, sizeof(srp_options_t));
    r = ParseOptions(params->utils, text->server_options, &server_opts);
    if (r) {
	VL(("Error parsing options\n"));
	goto done;
    }

    /* create an 'a' */
    GetRandBigInt(text->a);

    /* calculate 'A' 
     *
     * A = g^a % N 
     */
    mpz_init(text->A);
    mpz_powm (text->A, text->g, text->a, text->N);

    /* make o */
    r = CreateClientOpts(params, &server_opts, &text->client_opts);
    if (r) {
	VL(("Error creating client options\n"));
	goto done;
    }

    r = OptionsToString(params->utils, &text->client_opts,
			&text->client_options);
    if (r) {
	VL(("Error converting client options to an option string\n"));
	goto done;
    }
      
    /* Send out:
     *
     * A - client's public key
     * I - authorization
     * o - client option list
     *
     * { mpi(A) uf8(I) utf8(o) }
     */
    
    r = MakeMPI(params->utils, text->A, &mpiA, &mpiAlen);
    if (r) {
	VL(("Error making MPI string from A\n"));
	goto done;
    }

    r = MakeUTF8(params->utils, text->userid, &utf8I, &utf8Ilen);
    if (r) {
	VL(("Error making UTF8 string from userid ('I')\n"));
	goto done;
    }

    r = MakeUTF8(params->utils, text->client_options, &utf8o, &utf8olen);
    if (r) {
	VL(("Error making UTF8 string from client options ('o')\n"));
	goto done;
    }

    r = MakeBuffer(params->utils, mpiA, mpiAlen, utf8I, utf8Ilen,
		   utf8o, utf8olen, NULL, 0, clientout, clientoutlen);
    if (r) {
	VL(("Error making output buffer\n"));
	goto done;
    }

    text->state ++;
    r = SASL_CONTINUE;

 done:
    
    if (utf8I)    params->utils->free(utf8I);
    if (mpiA)     params->utils->free(mpiA);
    if (utf8o)    params->utils->free(utf8o);

    return r;
}

static int
client_step3(context_t *text,
	     sasl_client_params_t *params,
	     const char *serverin,
	     unsigned serverinlen,
	     sasl_interact_t **prompt_need __attribute__((unused)),
	     const char **clientout,
	     unsigned *clientoutlen,
	     sasl_out_params_t *oparams)
{
    char *data;
    int datalen;
    int r;    
    char *osM1 = NULL;
    int osM1len;

    /* Expect:
     *  { mpi(B) }
     *
     */
    r = UnBuffer((char *) serverin, serverinlen, &data, &datalen);
    if (r) return r;

    r = GetMPI((unsigned char *) data, datalen, &text->B, &data, &datalen);
    if (r) return r;

    if (datalen != 0) {
	VL(("Extra data parsing buffer\n"));
	return SASL_FAIL;
    }
    
    /* Calculate shared context key K
     *
     */
    r = CalculateK_client(text, text->salt, text->saltlen, text->authid, 
			  text->password->data, text->password->len,
			  &text->K, &text->Klen);
    if (r) return r;

    r = SetOptions(&text->client_opts, text, params->utils, oparams);
    if (r) return r;

    /* Now calculate M1 (client evidence)
     *
     */
    r = CalculateM1(text, text->N, text->g, text->authid,
		    text->salt, text->saltlen,
		    text->server_options, text->A, text->B,
		    text->K, text->Klen,
		    &text->M1, &text->M1len);
    if (r) return r;

    /* Send:
     *
     * { os(M1) }
     */
    
    r = MakeOS(params->utils, text->M1, text->M1len, &osM1, &osM1len);
    if (r) {
	VL(("Error creating OS string for M1\n"));
	goto done;
    }

    r = MakeBuffer(params->utils, osM1, osM1len, NULL, 0, NULL, 0, NULL, 0,
		   clientout, clientoutlen);
    if (r) {
	VL(("Error creating buffer in step 3\n"));
	goto done;
    }

    text->state++;
    r = SASL_CONTINUE;
 done:

    if (osM1)    params->utils->free(osM1);

    return r;
}

static int
client_step4(context_t *text,
	     sasl_client_params_t *params,
	     const char *serverin,
	     unsigned serverinlen,
	     sasl_interact_t **prompt_need __attribute__((unused)),
	     const char **clientout,
	     unsigned *clientoutlen,
	     sasl_out_params_t *oparams __attribute__((unused)))
{
    char *data;
    int datalen;
    int r;    
    char *serverM2 = NULL;
    int serverM2len;
    int i;
    char *myM2 = NULL;
    int myM2len;

    /* Input:
     *
     * M2 - server evidence
     *
     *   { os(M2) }
     */
    r = UnBuffer((char *) serverin, serverinlen, &data, &datalen);
    if (r) return r;

    r = GetOS(params->utils, (unsigned char *)data, datalen,
	      &serverM2, &serverM2len, &data, &datalen);
    if (r) return r;

    if (datalen != 0) {
	VL(("Extra data parsing buffer\n"));
	r = SASL_FAIL;
	goto done;
    }

    /* calculate our own M2 */
    r = CalculateM2(text, text->A, text->authid, text->userid,
		    text->client_options, text->M1, text->M1len,
		    text->K, text->Klen, &myM2, &myM2len);
    if (r) {
	VL(("Error calculating our own M2 (server evidence)\n"));
	goto done;
    }

    /* compare to see if is server spoof */
    if (myM2len != serverM2len) {
	VL(("Server M2 length wrong\n"));
	r = SASL_FAIL;
	goto done;
    }

    
    for (i = 0; i < myM2len; i++) {
	if (serverM2[i] != myM2[i]) {
	    VL(("Server spoof detected. M2 incorrect\n"));
	    r = SASL_FAIL;
	    goto done;
	}
    }

    /* Send out: nothing
     *
     */
    *clientout = NULL;
    *clientoutlen = 0;

    text->state++;
    r = SASL_OK;

 done:

    if (serverM2)    params->utils->free(serverM2);
    if (myM2)        params->utils->free(myM2);

    return r;
}

static int
srp_client_mech_step(void *conn_context,
		     sasl_client_params_t *params,
		     const char *serverin,
		     unsigned serverinlen,
		     sasl_interact_t **prompt_need,
		     const char **clientout,
		     unsigned *clientoutlen,
		     sasl_out_params_t *oparams)
{
  context_t *text = conn_context;

  VL(("SRP client step %d\n",text->state));
  params->utils->log(NULL, SASL_LOG_ERR, "SRP client step %d\n",text->state);

  switch (text->state)
      {
      case 1:
	  return client_step1(text, params, serverin, serverinlen, 
			      prompt_need, clientout, clientoutlen, oparams);
      case 2:
	  return client_step2(text, params, serverin, serverinlen, 
			      prompt_need, clientout, clientoutlen, oparams);
      case 3:
	  return client_step3(text, params, serverin, serverinlen, 
			      prompt_need, clientout, clientoutlen, oparams);
      case 4:
	  return client_step4(text, params, serverin, serverinlen, 
			      prompt_need, clientout, clientoutlen, oparams);
      default:
	  VL(("Invalid SRP step\n"));
	  return SASL_FAIL;
      }

  return SASL_FAIL;
}


static const sasl_client_plug_t srp_client_plugins[] = 
{
#ifdef WITH_SHA1
  {
    "SRP-SHA-160",   	        /* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* required_prompts */
    NULL,			/* glob_context */
    &srp_sha1_client_mech_new,	/* mech_new */
    &srp_client_mech_step,	/* mech_step */
    &srp_both_mech_dispose,	/* mech_dispose */
    &srp_both_mech_free,	/* mech_free */
    NULL,			/* idle */
    NULL,			/* spare1 */
    NULL			/* spare2 */
  },
#endif /* WITH_SHA1 */
  {
    "SRP-MD5-120",   	        /* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* required_prompts */
    NULL,			/* glob_context */
    &srp_md5_client_mech_new,	/* mech_new */
    &srp_client_mech_step,	/* mech_step */
    &srp_both_mech_dispose,	/* mech_dispose */
    &srp_both_mech_free,	/* mech_free */
    NULL,			/* idle */
    NULL,			/* spare1 */
    NULL			/* spare2 */
  }
};

int srp_client_plug_init(const sasl_utils_t *utils __attribute__((unused)),
			 int maxversion,
			 int *out_version,
			 const sasl_client_plug_t **pluglist,
			 int *plugcount,
			 const char *plugname __attribute__((unused)))
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "SRP version mismatch");
	return SASL_BADVERS;
    }

    *pluglist=srp_client_plugins;

    *plugcount=sizeof(srp_client_plugins)/sizeof(sasl_client_plug_t);
    *out_version=SASL_CLIENT_PLUG_VERSION;

    return SASL_OK;
}
