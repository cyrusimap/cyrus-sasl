/* SRP SASL plugin
 * Ken Murchison
 * Tim Martin  3/17/00
 * $Id: srp.c,v 1.11 2001/12/16 04:46:12 ken3 Exp $
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
#include <stdio.h>

/* for big number support */
#include <gmp.h>

/* for digest and encryption support */
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <sasl.h>
#define MD5_H  /* suppress internal MD5 */
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
/* Size limit of SRP buffer */
#define MAXBUFFERSIZE 2147483643

#define OPTION_REPLAY_DETECTION	"replay detection"
#define OPTION_INTEGRITY	"integrity="
#define OPTION_CONFIDENTIALITY	"confidentiality="
#define OPTION_MANDATORY	"mandatory="
#define OPTION_MAXBUFFERSIZE	"maxbuffersize="

/* Table of recommended Modulus (base 16) and Generator pairs */
struct Ng {
    char *N;
    unsigned long g;
} Ng_tab[] = {
    /* [264 bits] */
    { "115B8B692E0E045692CF280B436735C77A5A9E8A9E7ED56C965F87DB5B2A2ECE3",
      2
    },
    /* [384 bits] */
    { "8025363296FB943FCE54BE717E0E2958A02A9672EF561953B2BAA3BAACC3ED5754EB764C7AB7184578C57D5949CCB41B",
    2
    },
    /* [512 bits] */
    { "D4C7F8A2B32C11B8FBA9581EC4BA4F1B04215642EF7355E37C0FC0443EF756EA2C6B8EEB755A1C723027663CAA265EF785B8FF6A9B35227A52D86633DBDFCA43",
      2
    },
    /* [640 bits] */
    { "C94D67EB5B1A2346E8AB422FC6A0EDAEDA8C7F894C9EEEC42F9ED250FD7F0046E5AF2CF73D6B2FA26BB08033DA4DE322E144E7A8E9B12A0E4637F6371F34A2071C4B3836CBEEAB15034460FAA7ADF483",
      2
    },
    /* [768 bits] */
    { "B344C7C4F8C495031BB4E04FF8F84EE95008163940B9558276744D91F7CC9F402653BE7147F00F576B93754BCDDF71B636F2099E6FFF90E79575F3D0DE694AFF737D9BE9713CEF8D837ADA6380B1093E94B6A529A8C6C2BE33E0867C60C3262B",
      2
    },
    /* [1024 bits] */
    { "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
      2
    },
    /* [1280 bits] */
    { "D77946826E811914B39401D56A0A7843A8E7575D738C672A090AB1187D690DC43872FC06A7B6A43F3B95BEAEC7DF04B9D242EBDC481111283216CE816E004B786C5FCE856780D41837D95AD787A50BBE90BD3A9C98AC0F5FC0DE744B1CDE1891690894BC1F65E00DE15B4B2AA6D87100C9ECC2527E45EB849DEB14BB2049B163EA04187FD27C1BD9C7958CD40CE7067A9C024F9B7C5A0B4F5003686161F0605B",
      2
    },
    /* [1536 bits] */
    { "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
      2
    },
    /* [2048 bits] */
    { "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
      2
    }
};

#define NUM_Ng (sizeof(Ng_tab) / sizeof(struct Ng))


/******************** Options *************************/

typedef struct layer_option_s {
    const char *name;		/* name used in option strings */
    unsigned enabled;		/* enabled?  determined at run-time */
    unsigned bit;		/* unique bit in bitmask */
    sasl_ssf_t ssf;		/* ssf of layer */
    const char *evp_name;	/* name used for lookup in EVP table */
} layer_option_t;

static layer_option_t integrity_options[] = {
    {"HMAC-SHA-1",	0, (1<<0), 1,	"sha1"},
    {"HMAC-RIPEMD-160",	0, (1<<1), 1,	"rmd160"},
    {"HMAC-MD5",	0, (1<<2), 1,	"md5"},
    {NULL,		0, (0<<0), 1,	NULL}
};

static layer_option_t confidentiality_options[] = {
    {"DES",		0, (1<<0), 56,	"des-ofb"},
    {"3DES",		0, (1<<1), 112,	"des-ede-ofb"},
    {"AES",		0, (1<<2), 128,	"aes-128-ofb"},
    {"Blowfish",	0, (1<<3), 128,	"bf-ofb"},
    {"CAST-128",	0, (1<<4), 128,	"cast5-ofb"},
    {"IDEA",		0, (1<<5), 128,	"idea-ofb"},
    {NULL,		0, (0<<0), 0,	NULL}
};


enum {
    BIT_REPLAY_DETECTION=	(1<<0),
    BIT_INTEGRITY=		(1<<1),
    BIT_CONFIDENTIALITY=	(1<<2)
};

typedef struct srp_options_s {
    unsigned replay_detection;	/* replay detection on/off flag */
    unsigned integrity;		/* bitmask of integrity layers */
    unsigned confidentiality;	/* bitmask of confidentiality layers */
    unsigned mandatory;		/* bitmask of mandatory layers */
    unsigned long maxbufsize;	/* max # bytes processed by security layer */
} srp_options_t;

/* The main SRP context */
typedef struct context_s {
    int state;

    mpz_t N;
    mpz_t g;

    mpz_t v;			/* verifier */

    mpz_t b;
    mpz_t B;

    mpz_t a;
    mpz_t A;

    char *K;
    int Klen;

    char *M1;
    int M1len;

    char *authid;		/* authentication id */
    char *userid;		/* authorization id */
    char *realm;
    sasl_secret_t *password;

    char *client_options;
    char *server_options;

    srp_options_t client_opts;

    char *salt;
    int saltlen;

    const char *mech_name;	/* used for propName in sasldb */

    /* Layer foo */
    unsigned enabled;		/* bitmask of enabled layers */
    const EVP_MD *md;
    const EVP_MD *hmac_md;
    const EVP_CIPHER *cipher;
    const sasl_utils_t *utils;

    int seqnum_out;
    int seqnum_in;

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


#ifndef EVP_MAX_BLOCK_LENGTH
#define EVP_MAX_BLOCK_LENGTH 32
#endif

static int
layer_encode(void *context,
	     const struct iovec *invec,
	     unsigned numiov,
	     const char **output,
	     unsigned *outputlen)
{
  context_t *text = (context_t *) context;
  int hashlen = 0;
  char hashdata[EVP_MAX_MD_SIZE];
  int tmpnum;
  int ret;
  char *input;
  unsigned inputlen;
  char *encdata = NULL;

  assert(numiov > 0);

  ret = _plug_iovec_to_buf(text->utils, invec, numiov, &text->enc_in_buf);
  if(ret != SASL_OK) return ret;
  
  input = text->enc_in_buf->data;
  inputlen = text->enc_in_buf->curlen;

  if (text->enabled & BIT_CONFIDENTIALITY) {
      EVP_CIPHER_CTX ctx;
      unsigned char IV[EVP_MAX_IV_LENGTH];
      unsigned char block1[EVP_MAX_BLOCK_LENGTH];
      unsigned k = 8 * EVP_CIPHER_block_size(text->cipher); /* XXX bug? */
      unsigned enclen = 0;
      unsigned tmplen;

      encdata = text->utils->malloc(inputlen + 2 * k);
      if (!encdata) return SASL_NOMEM;

      EVP_CIPHER_CTX_init(&ctx);

      memset(IV, 0, sizeof(IV));
      EVP_EncryptInit(&ctx, text->cipher, text->K, IV);

      /* construct the first block so that octets #k-1 and #k
       * are exact copies of octets #1 and #2
       */
      text->utils->rand(text->utils->rpool, block1, k - 2);
      memcpy(block1 + k-2, block1, 2);

      if (!EVP_EncryptUpdate(&ctx, encdata, &tmplen, block1, k)) {
	  text->utils->free(encdata);
	  return SASL_FAIL;
      }
      enclen += tmplen;
	  
      if (!EVP_EncryptUpdate(&ctx, encdata + enclen, &tmplen,
			     input, inputlen)) {
	  text->utils->free(encdata);
	  return SASL_FAIL;
      }
      enclen += tmplen;
	  
      if (!EVP_EncryptFinal(&ctx, encdata + enclen, &tmplen)) {
	  text->utils->free(encdata);
	  return SASL_FAIL;
      }
      enclen += tmplen;

      EVP_CIPHER_CTX_cleanup(&ctx);

      input = encdata;
      inputlen = enclen;
  }

  if (text->enabled & BIT_INTEGRITY) {
      HMAC_CTX hmac_ctx;

      HMAC_Init(&hmac_ctx, text->K, text->Klen, text->hmac_md);

      HMAC_Update(&hmac_ctx, input, inputlen);

      if (text->enabled & BIT_REPLAY_DETECTION) {
	  tmpnum = htonl(text->seqnum_out);
	  HMAC_Update(&hmac_ctx, (char *) &tmpnum, 4);
      
	  text->seqnum_out++;
      }
    
      HMAC_Final(&hmac_ctx, hashdata, &hashlen);
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
  
  if (encdata) text->utils->free(encdata);

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
    char *decdata = NULL;

    if (text->enabled & BIT_INTEGRITY) {
	int tmpnum;
	char hashdata[EVP_MAX_MD_SIZE];
	int i;
	HMAC_CTX hmac_ctx;

	HMAC_Init(&hmac_ctx, text->K, text->Klen, text->hmac_md);

	hashlen = EVP_MD_size(text->hmac_md);

	if ((int)inputlen < hashlen) {
	    text->utils->log(NULL, SASL_LOG_ERR,
			     "Input is smaller than hash length: %d vs %d\n",
			     inputlen, hashlen);
	    return SASL_FAIL;
	}

	/* create my version of the hash */
	HMAC_Update(&hmac_ctx, (char *)input, inputlen - hashlen);

	if (text->enabled & BIT_REPLAY_DETECTION) {
	    tmpnum = htonl(text->seqnum_in);
	    HMAC_Update(&hmac_ctx, (char *) &tmpnum, 4);
	    
	    text->seqnum_in ++;
	}
	
	HMAC_Final(&hmac_ctx, hashdata, NULL);

	/* compare to hash given */
	for (i = 0; i < hashlen; i++) {
	    if (hashdata[i] != input[inputlen - hashlen + i]) {
		text->utils->log(NULL, SASL_LOG_ERR, "Hash is incorrect\n");
		return SASL_FAIL;
	    }
	}
    }

    if (text->enabled & BIT_CONFIDENTIALITY) {
	EVP_CIPHER_CTX ctx;
	unsigned char IV[EVP_MAX_IV_LENGTH];
	unsigned char block1[EVP_MAX_BLOCK_LENGTH];
	unsigned k = 8 * EVP_CIPHER_block_size(text->cipher); /* XXX bug? */
	unsigned declen = 0;
	unsigned tmplen;

	decdata = text->utils->malloc(inputlen - hashlen);
	if (!decdata) return SASL_NOMEM;

	EVP_CIPHER_CTX_init(&ctx);

	memset(IV, 0, sizeof(IV));
	EVP_DecryptInit(&ctx, text->cipher, text->K, IV);

	/* check the first block and see if octets #k-1 and #k
	 * are exact copies of octects #1 and #2
	 */
	if (!EVP_DecryptUpdate(&ctx, block1, &tmplen, (char*) input, k)) {
	    text->utils->free(decdata);
	    return SASL_FAIL;
	}

	if ((block1[0] != block1[k-2]) || (block1[1] != block1[k-1])) {
	    text->utils->free(decdata);
	    return SASL_BADAUTH;
	}
	  
	if (!EVP_DecryptUpdate(&ctx, decdata, &tmplen, (char*) input + k,
			       inputlen - k - hashlen)) {
	    text->utils->free(decdata);
	    return SASL_FAIL;
	}
	declen += tmplen;
	  
	if (!EVP_DecryptFinal(&ctx, decdata + declen, &tmplen)) {
	    text->utils->free(decdata);
	    return SASL_FAIL;
	}
	declen += tmplen;

	EVP_CIPHER_CTX_cleanup(&ctx);

	input = decdata;
	*outputlen = declen;
    } else {
	*outputlen = inputlen - hashlen;
    }

    *output = text->utils->malloc(*outputlen);
    if (!*output) return SASL_NOMEM;

    memcpy( (char *) *output, input, *outputlen);

    if (decdata) text->utils->free(decdata);

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
		text->utils->log(NULL, SASL_LOG_ERR,
				 "Size out of range: %d\n",text->size);
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
	utils->log(NULL, SASL_LOG_ERR, "At least one buffer must be active\n");
	return SASL_FAIL;
    }

    len = in1len + in2len + in3len + in4len;

    if (len > MAX_BUFFER_LEN) {
	utils->log(NULL, SASL_LOG_ERR,
		   "String too long to create SRP buffer string\n");
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
	return SASL_FAIL;
    }

    /* get the length */
    memcpy(&lenbyteorder, in, 4);
    len = ntohl(lenbyteorder);

    /* make sure it's right */
    if (len + 4 != inlen) {
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
	utils->log(NULL, SASL_LOG_ERR, "Can't create utf8 string from null");
	return SASL_FAIL;
    }

    /* xxx actual utf8 conversion */

    llen = strlen(in);

    if (llen > MAX_UTF8_LEN) {
	utils->log(NULL, SASL_LOG_ERR,
		   "String too long to create utf8 string\n");
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
	utils->log(NULL, SASL_LOG_ERR,
		   "Buffer is not big enough to be SRP UTF8\n");
	return SASL_FAIL;
    }

    /* get the length */
    memcpy(&lenbyteorder, data, 2);
    len = ntohs(lenbyteorder);

    /* make sure it's right */
    if (len + 2 > datalen) {
	utils->log(NULL, SASL_LOG_ERR, "Not enough data for this SRP UTF8\n");
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
	utils->log(NULL, SASL_LOG_ERR, "Can't create SRP os string from null");
	return SASL_FAIL;
    }

    if (inlen > MAX_OS_LEN) {
	utils->log(NULL, SASL_LOG_ERR,
		   "String too long to create SRP os string\n");
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
	utils->log(NULL, SASL_LOG_ERR,
		   "Buffer is not big enough to be SRP os\n");
	return SASL_FAIL;
    }

    /* get the length */
    len = (unsigned char)data[0];

    /* make sure it's right */
    if (len + 1 > datalen) {
	utils->log(NULL, SASL_LOG_ERR, "Not enough data for this SRP os\n");
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
	return SASL_FAIL;
    }

    /* get the length */
    memcpy(&lenbyteorder, data, 2);
    len = ntohs(lenbyteorder);

    /* make sure it's right */
    if (len + 2 > datalen) {
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
HashData(context_t *text, char *in, int inlen,
	 unsigned char outhash[], int *outlen)
{
    EVP_MD_CTX mdctx;

    EVP_DigestInit(&mdctx, text->md);
    EVP_DigestUpdate(&mdctx, in, inlen);
    EVP_DigestFinal(&mdctx, outhash, outlen);
}

/* Call the hash function on the data of a BigInt
 *
 */
static int
HashBigInt(context_t *text, mpz_t in, unsigned char outhash[], int *outlen)
{
    int r;
    char buf[4096];
    int buflen;
    EVP_MD_CTX mdctx;
    
    r = BigIntToBytes(in, buf, sizeof(buf)-1, &buflen);
    if (r) return r;

    EVP_DigestInit(&mdctx, text->md);
    EVP_DigestUpdate(&mdctx, buf, buflen);
    EVP_DigestFinal(&mdctx, outhash, outlen);

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
    EVP_MD_CTX mdEven;
    EVP_MD_CTX mdOdd;
    unsigned char Evenb[EVP_MAX_MD_SIZE];
    unsigned char Oddb[EVP_MAX_MD_SIZE];
    int hashlen;

    /* make bigint into bytes */
    r = BigIntToBytes(num, buf, sizeof(buf)-1, &buflen);
    if (r) return r;

    limit = buflen;

    /* skip by leading zero's */
    for (offset = 0; offset < limit && buf[offset] == 0x00; offset++) {
	/* nada */
    }
	
    klen = (limit - offset) / 2;

    EVP_DigestInit(&mdEven, text->md);
    EVP_DigestInit(&mdOdd, text->md);

    j = limit - 1;
    for (i = 0; i < klen; i++) {
	EVP_DigestUpdate(&mdEven, buf + j, 1);
	j--;
	EVP_DigestUpdate(&mdOdd, buf + j, 1);
	j--;
    }

    EVP_DigestFinal(&mdEven, Evenb, NULL);
    EVP_DigestFinal(&mdEven, Oddb, &hashlen);

    *outlen = 2 * hashlen;
    *out = text->utils->malloc(*outlen);
    if (!*out) return SASL_NOMEM;
      
    for (i = 0, j = 0; i < hashlen; i++)
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
    EVP_MD_CTX mdctx;
    char hash[EVP_MAX_MD_SIZE];
    int hashlen;

    /* x = H(salt | H(user | ':' | pass))
     *
     */      

    EVP_DigestInit(&mdctx, text->md);

    EVP_DigestUpdate(&mdctx, (char*) user, strlen(user));
    EVP_DigestUpdate(&mdctx, ":", 1);
    EVP_DigestUpdate(&mdctx, (char*) pass, passlen);

    EVP_DigestFinal(&mdctx, hash, &hashlen);


    EVP_DigestInit(&mdctx, text->md);

    EVP_DigestUpdate(&mdctx, (char*) salt, saltlen);
    EVP_DigestUpdate(&mdctx, hash, hashlen);

    EVP_DigestFinal(&mdctx, hash, &hashlen);

    DataToBigInt(hash, hashlen, x);

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
    unsigned char hash[EVP_MAX_MD_SIZE];
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
    r = HashBigInt(text, text->B, hash, NULL);
    if (r) return r;
    mpz_init(u);
    DataToBigInt(hash, 4, &u);
    if (!mpz_cmp_ui(u, 0)) return SASL_FAIL;

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
    unsigned char p1a[EVP_MAX_MD_SIZE];
    unsigned char p1b[EVP_MAX_MD_SIZE];
    unsigned char p1[EVP_MAX_MD_SIZE];
    int p1len;
    char p2[EVP_MAX_MD_SIZE];
    int p2len;
    char *p3;
    int p3len;
    char p4[1024];
    int p4len;
    char p5[1024];
    int p5len;
    char *p6;
    int p6len;
    char p7[EVP_MAX_MD_SIZE];
    int p7len;
    char *tot;
    int totlen = 0;
    char *totp;

    /* p1) bytes(H( bytes(N) )) ^ bytes( H( bytes(g) )) */
    r = HashBigInt(text, N, p1a, NULL);
    if (r) return r;
    r = HashBigInt(text, g, p1b, &p1len);
    if (r) return r;

    for (i = 0; i < p1len; i++) {
	p1[i] = (p1a[i] ^ p1b[i]);
    }

    /* p2) bytes(H( bytes(U) )) */
    HashData(text, U, strlen(U), p2, &p2len);

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
    HashData(text, L, strlen(L), p7, &p7len);

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
    *out = text->utils->malloc(EVP_MAX_MD_SIZE);
    if (!*out) {
	text->utils->free(tot);
	return SASL_NOMEM;
    }

    HashData(text, tot, totlen, *out, outlen);
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
    char p4[EVP_MAX_MD_SIZE];
    int p4len;
    char p5[EVP_MAX_MD_SIZE];
    int p5len;
    char p6[EVP_MAX_MD_SIZE];
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
    HashData(text, U, strlen(U), p4, &p4len);

    /* p5) bytes(H( bytes(I) )) */
    HashData(text, I, strlen(I), p5, &p5len);

    /* p6) bytes(H( bytes(o) )) */
    HashData(text, o, strlen(o), p6, &p6len);

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
    *out = text->utils->malloc(EVP_MAX_MD_SIZE);
    if (!*out) {
	return SASL_NOMEM;
	text->utils->free(tot);
    }

    HashData(text, tot, totlen, *out, outlen);
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
	if (!strcasecmp(name, opts->name)) {
	    return opts->bit;
	}

	opts++;
    }

    return 0;
}

static layer_option_t *
FindOptionFromBit(unsigned bit, layer_option_t *opts)
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
ParseOptionString(char *str, srp_options_t *opts, int isserver)
{
    if (!strcasecmp(str, OPTION_REPLAY_DETECTION)) {
	if (opts->replay_detection) {
	    return SASL_FAIL;
	}
	opts->replay_detection = 1;

    } else if (!strncasecmp(str, OPTION_INTEGRITY, strlen(OPTION_INTEGRITY))) {

	int bit = FindBit(str+strlen(OPTION_INTEGRITY), integrity_options);

	if (bit == 0) return SASL_OK;

	if (isserver && (bit & opts->integrity)) {
	    return SASL_FAIL;
	}

	opts->integrity = opts->integrity | bit;

    } else if (!strncasecmp(str, OPTION_CONFIDENTIALITY,
			    strlen(OPTION_CONFIDENTIALITY))) {

	int bit = FindBit(str+strlen(OPTION_CONFIDENTIALITY),
			  confidentiality_options);
	if (bit == 0) return SASL_OK;

	if (isserver && (bit & opts->confidentiality)) {
	    return SASL_FAIL;
	}

	opts->confidentiality = opts->confidentiality | bit;

    } else if (!isserver && !strncasecmp(str, OPTION_MANDATORY,
					 strlen(OPTION_MANDATORY))) {

	char *layer = str+strlen(OPTION_MANDATORY);

	if (!strcasecmp(layer, OPTION_REPLAY_DETECTION))
	    opts->mandatory |= BIT_REPLAY_DETECTION;
	else if (!strncasecmp(layer, OPTION_INTEGRITY,
			      strlen(OPTION_INTEGRITY)-1))
	    opts->mandatory |= BIT_INTEGRITY;
	else if (!strncasecmp(layer, OPTION_CONFIDENTIALITY,
			      strlen(OPTION_CONFIDENTIALITY)-1))
	    opts->mandatory |= BIT_CONFIDENTIALITY;
	else
	    return SASL_FAIL;

    } else if (!strncasecmp(str, OPTION_MAXBUFFERSIZE,
			    strlen(OPTION_MAXBUFFERSIZE))) {

	int n = sscanf(str+strlen(OPTION_MAXBUFFERSIZE),
		       "%lu", &opts->maxbufsize);

	if ((n != 1) || (opts->maxbufsize > MAXBUFFERSIZE))
	    return SASL_FAIL;

    } else {
	return SASL_FAIL;
    }

    return SASL_OK;
}

static int
ParseOptions(const sasl_utils_t *utils, char *in, srp_options_t *out,
	     int isserver)
{
    int r;

    memset(out, 0, sizeof(srp_options_t));

    while (in) {
	char *opt;

	r = ParseOption(utils, in, &opt, &in);
	if (r) return r;

	if (opt == NULL) return SASL_OK;

	utils->log(NULL, SASL_LOG_DEBUG, "Got option: [%s]\n",opt);

	r = ParseOptionString(opt, out, isserver);
	if (r) return r;
    }

    return SASL_OK;
}

static layer_option_t *
FindBest(int available, sasl_ssf_t min_ssf, sasl_ssf_t max_ssf,
	 layer_option_t *opts)
{
    layer_option_t *best = NULL;

    if (!available) return NULL;

    while (opts->name) {
	if (opts->enabled && (available & opts->bit) &&
	    (opts->ssf >= min_ssf) && (opts->ssf <= max_ssf) &&
	    (!best || (opts->ssf > best->ssf))) {
		best = opts;
	}

	opts++;
    }

    return best;
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
	if (optlist->enabled &&
	    (props->min_ssf <= 1) && (props->max_ssf >= 1)) {
	    opts.integrity |= optlist->bit;
	}
	optlist++;
    }

    /* if we set any integrity options we can advertise replay detection */
    if (opts.integrity) {
	opts.replay_detection = 1;
    }

    /* Add confidentiality options */
    optlist = confidentiality_options;
    while(optlist->name) {
	if (optlist->enabled &&
	    (props->min_ssf <= optlist->ssf) &&
	    (props->max_ssf >= optlist->ssf)) {
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
    params->utils->log(NULL, SASL_LOG_DEBUG,
		       "Available confidentiality = %d\n",
		       available->confidentiality);

    if (limit > 1) {
	/* confidentiality */
	layer_option_t *copt = NULL;

	copt = FindBest(available->confidentiality, musthave, limit,
			confidentiality_options);
	
	if (copt) {
	    out->confidentiality = copt->bit;
	    /* we've already satisfied the SSF with the confidentiality
	     * layer, but we'll also use an integrity layer if we can
	     */
	    musthave = 0;
	}
	else if (musthave > 1) {
	    params->utils->log(NULL, SASL_LOG_ERR,
			       "Can't find an acceptable privacy layer\n");
	    return SASL_TOOWEAK;
	}
    }

    params->utils->log(NULL, SASL_LOG_DEBUG,
		       "Available integrity = %d\n",available->integrity);

    if ((limit >= 1) && (musthave <= 1)) {
	/* integrity */
	layer_option_t *iopt;

	iopt = FindBest(available->integrity, musthave, limit,
			integrity_options);
	
	if (iopt) {
	    out->integrity = iopt->bit;

	    /* if we set an integrity option we can set replay detection */
	    out->replay_detection = available->replay_detection;
	}
	else if (musthave > 0) {
	    params->utils->log(NULL, SASL_LOG_ERR,
			       "Can't find an acceptable integrity layer\n");
	    return SASL_TOOWEAK;
	}
    }

    /* Check to see if we've satisfied all of the servers mandatory layers */
    params->utils->log(NULL, SASL_LOG_DEBUG,
		       "Mandatory layers = %d\n",available->mandatory);

    if ((!out->replay_detection &&
	 (available->mandatory & BIT_REPLAY_DETECTION)) ||
	(!out->integrity &&
	 (available->mandatory & BIT_INTEGRITY)) ||
	(!out->confidentiality &&
	 (available->mandatory & BIT_CONFIDENTIALITY))) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Mandatory layer not supported\n");
	return SASL_TOOWEAK;
    }

    return SASL_OK;
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
	utils->log(NULL, SASL_LOG_DEBUG, "Using no layer\n");
	return SASL_OK;
    }
    
    oparams->encode = &layer_encode;
    oparams->decode = &layer_decode;
    oparams->maxoutbuf = opts->maxbufsize ? opts->maxbufsize : MAXBUFFERSIZE;

    if (opts->replay_detection) {
	text->enabled |= BIT_REPLAY_DETECTION;

	/* If no integrity layer specified, default to HMAC-SHA-1 */
	if (!opts->integrity)
	    opts->integrity = FindBit("HMAC-SHA-1", integrity_options);
    }

    if (opts->integrity) {
	layer_option_t *iopt;

	text->enabled |= BIT_INTEGRITY;

	iopt = FindOptionFromBit(opts->integrity, integrity_options);
	if (!iopt) {
	    utils->log(NULL, SASL_LOG_ERR,
		       "Unable to find integrity layer option now\n");
	    return SASL_FAIL;
	}

	oparams->mech_ssf = iopt->ssf;
	text->hmac_md = EVP_get_digestbyname(iopt->evp_name);
    }

    if (opts->confidentiality) {
	layer_option_t *iopt;

	text->enabled |= BIT_CONFIDENTIALITY;

	iopt = FindOptionFromBit(opts->confidentiality, confidentiality_options);
	if (!iopt) {
	    utils->log(NULL, SASL_LOG_ERR,
		       "Unable to find integrity layer option now\n");
	    return SASL_FAIL;
	}

	oparams->mech_ssf = iopt->ssf;
	text->cipher = EVP_get_cipherbyname(iopt->evp_name);
    }

    return SASL_OK;
}


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

    EVP_cleanup();
}


static int
srp_sha1_server_mech_new(void *glob_context __attribute__((unused)),
			 sasl_server_params_t *params,
			 const char *challenge __attribute__((unused)),
			 unsigned challen __attribute__((unused)),
			 void **conn)
{
  context_t *text;

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
  text->mech_name  = "SRP-SHA-1";
  text->md = EVP_get_digestbyname("sha1");

  *conn=text;

  return SASL_OK;
}

static int
srp_rmd160_server_mech_new(void *glob_context __attribute__((unused)),
			   sasl_server_params_t *params,
			   const char *challenge __attribute__((unused)),
			   unsigned challen __attribute__((unused)),
			   void **conn)
{
  context_t *text;

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
  text->mech_name  = "SRP-RIPEMD-160";
  text->md = EVP_get_digestbyname("rmd160");

  *conn=text;

  return SASL_OK;
}

static int
srp_md5_server_mech_new(void *glob_context __attribute__((unused)),
			sasl_server_params_t *params,
			const char *challenge __attribute__((unused)),
			unsigned challen __attribute__((unused)),
			void **conn)
{
  context_t *text;

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
  text->mech_name  = "SRP-MD5";
  text->md = EVP_get_digestbyname("md5");

  *conn=text;

  return SASL_OK;
}


/* A large safe prime (N = 2q+1, where q is prime)
 *
 * Use N with the most bits from our table.
 *
 * All arithmetic is done modulo N
 */
static int generate_N_and_g(mpz_t N, mpz_t g)
{
    int result;
    
    mpz_init(N);
    result = mpz_set_str (N, Ng_tab[NUM_Ng-1].N, 16);
    if (result) return SASL_FAIL;

    mpz_init(g);
    mpz_set_ui (g, Ng_tab[NUM_Ng-1].g);

    return SASL_OK;
}

static int
CalculateV(context_t *text,
	   mpz_t N, mpz_t g,
	   const char *user,
	   const char *pass, unsigned passlen,
	   mpz_t *v, char **salt, int *saltlen)
{
    mpz_t x;
    int r;    

    /* generate <salt> */    
    *salt = (char *)text->utils->malloc(SRP_SALT_SIZE);
    if (!*salt) return SASL_NOMEM;
    *saltlen = sizeof(salt);
    text->utils->rand(text->utils->rpool, *salt, *saltlen);

    r = CalculateX(text, *salt, *saltlen, user, pass, passlen, &x);
    if (r) {
	text->utils->seterror(text->utils->conn, 0, 
			      "Error calculating 'x'");
      return r;
    }

    /* v = g^x % N */
    mpz_init(*v);
    mpz_powm (*v, g, x, N);

    mpz_clear(x);

    return r;   
}

static int
ServerCalculateK(context_t *text, mpz_t v,
		 mpz_t N, mpz_t g, mpz_t b, mpz_t B, mpz_t A,
		 char **key, int *keylen)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
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
    r = HashBigInt(text, B, hash, NULL);
    if (r) return r;
    mpz_init(u);
    DataToBigInt(hash, 4, &u);
    if (!mpz_cmp_ui(u, 0)) return SASL_FAIL;

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
ParseUserSecret(const sasl_utils_t *utils, char *secret, size_t seclen,
		mpz_t *v, char **salt, int *saltlen)
{
    int r;
    char *data;
    int datalen;

    /* The secret data is stored as suggested in RFC 2945:
     *
     *  v    - mpi
     *  salt - os 
     */
    r = UnBuffer(secret, seclen, &data, &datalen);
    if (r) {
      utils->seterror(utils->conn, 0, 
		      "Error UnBuffering secret data");
      return r;
    }

    r = GetMPI(data, datalen, v, &data, &datalen);
    if (r) {
      utils->seterror(utils->conn, 0, 
		      "Error parsing out 'v'");
      return r;
    }

    r = GetOS(utils, data, datalen, salt, saltlen, &data, &datalen);
    if (r) {
      utils->seterror(utils->conn, 0, 
		      "Error parsing out salt");
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
server_step1(context_t *text,
	     sasl_server_params_t *params,
	     const char *clientin,
	     unsigned clientinlen,
	     const char **serverout,
	     unsigned *serveroutlen,
	     sasl_out_params_t *oparams)
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
    char propName[100];
    const char *password_request[] = { SASL_AUX_PASSWORD,
				       propName,
				       NULL };
    struct propval auxprop_values[3];

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

    /* Generate N and g */
    r = generate_N_and_g(text->N, text->g);
    if (r) {
	text->utils->seterror(text->utils->conn, 0, 
		      "Error calculating N and g");
	return r;
    }

    /* Get user secret */
    sprintf(propName, "cmusaslsecret%s", text->mech_name);
    r = params->utils->prop_request(params->propctx, password_request);
    if (r != SASL_OK) goto fail;

    /* this will trigger the getting of the aux properties */
    r = params->canon_user(params->utils->conn,
			   user, 0, SASL_CU_AUTHID, oparams);
    if (r != SASL_OK) goto fail;

    r = params->utils->prop_getnames(params->propctx, password_request,
				     auxprop_values);
    if (r < 0 ||
	((!auxprop_values[0].name || !auxprop_values[0].values) &&
	 (!auxprop_values[1].name || !auxprop_values[1].values))) {
	/* We didn't find this username */
	params->utils->seterror(params->utils->conn,0,
				"no secret in database");
	r = SASL_NOUSER;
	goto fail;
    }

    if (auxprop_values[1].name && auxprop_values[1].values) {
	/* We have a precomputed verifier */
	r = ParseUserSecret(params->utils,
			    (char*) auxprop_values[1].values[0],
			    auxprop_values[1].valsize,
			    &text->v, &text->salt, &text->saltlen);
	
	if (r) {
	    /* ParseUserSecret sets error, if any */
	    goto fail;
	}
    } else if (auxprop_values[0].name && auxprop_values[0].values) {
	/* We only have the password -- calculate the verifier */
	int len = strlen(auxprop_values[0].values[0]);
	if (len == 0) {
	    params->utils->seterror(params->utils->conn,0,
				    "empty secret");
	    r = SASL_FAIL;
	    goto fail;
	}

	r = CalculateV(text, text->N, text->g, user,
		   auxprop_values[0].values[0], len,
		   &text->v, &text->salt, &text->saltlen);
	if (r) {
	    params->utils->seterror(params->utils->conn, 0, 
				    "Error calculating v");
	    goto fail;
	}
    } else {
	params->utils->seterror(params->utils->conn, 0,
				"Have neither type of secret");
	r = SASL_FAIL;
	goto fail;
    }    

    params->utils->prop_clear(params->propctx, 1);


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
	     sasl_out_params_t *oparams)
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

    /* Check the value of A */
    if (!mpz_cmp_ui(text->A, 0) || !mpz_cmp_ui(text->A, 1)) {
	params->utils->log(NULL, SASL_LOG_ERR, "Illegal value for 'A'\n");
	return SASL_FAIL;
    }
    
    r = GetUTF8(params->utils, data, datalen, &text->userid, &data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error parsing out userid");
      return r;
    }

    r = params->canon_user(params->utils->conn,
			   text->userid, 0, SASL_CU_AUTHZID, oparams);
    if (r != SASL_OK) return r;
    
    r = GetUTF8(params->utils, data, datalen, &text->client_options,
		&data, &datalen);
    if (r) {
      params->utils->seterror(params->utils->conn, 0, 
	"Error parsing out client options 'o'");
      return r;
    }
    params->utils->log(NULL, SASL_LOG_DEBUG, "o: '%s'", text->client_options);

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
    r = ParseOptions(params->utils, text->client_options, &client_opts, 1);
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
      params->utils->log(NULL, SASL_LOG_ERR,
			 "M1 lengths do not match: %d vs %d",M1len, myM1len);
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

  sparams->utils->log(NULL, SASL_LOG_DEBUG,
		      "SRP server step %d\n", text->state);

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


#ifdef DO_SRP_SETPASS
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
    sasl_secret_t *sec = NULL;
    char propName[100];

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
	mpz_t N;
	mpz_t g;
	mpz_t v;
	char *salt;
	int saltlen;
	char *mpiv = NULL;
	int mpivlen;    
	char *osSalt = NULL;
	int osSaltlen;
	const char *buffer = NULL;
	int bufferlen;

	r = generate_N_and_g(N, g);
	if (r) {
	    text->utils->seterror(text->utils->conn, 0, 
				  "Error calculating N and g");
	    return r;
	}

	r = CalculateV(text, N, g, user, pass, passlen, &v, &salt, &saltlen);
	if (r) {
	    text->utils->seterror(text->utils->conn, 0, 
				  "Error calculating v");
	    return r;
	}

	/* The secret data is stored as suggested in RFC 2945:
	 *
	 *  v    - mpi
	 *  salt - os 
	 */

	r = MakeMPI(text->utils, v, &mpiv, &mpivlen);
	if (r) {
	    text->utils->seterror(text->utils->conn, 0, 
				  "Error turning 'N' into 'mpi' string");
	    goto end;
	}

	r = MakeOS(text->utils, salt, saltlen, &osSalt, &osSaltlen);
	if (r) {
	    text->utils->seterror(text->utils->conn, 0, 
				  "Error turning salt into 'os' string");
	    goto end;
	}

	r = MakeBuffer(text->utils, mpiv, mpivlen, osSalt, osSaltlen,
		       NULL, 0, NULL, 0, &buffer, &bufferlen);

	if (r) {
	    text->utils->seterror(text->utils->conn, 0, 
				  "Error putting all the data together in step 2");
	    goto end;
	}
    
	/* Put 'buffer' into sasl_secret_t */
	sec = text->utils->malloc(sizeof(sasl_secret_t)+bufferlen+1);
	if (!sec) {
	    r = SASL_NOMEM;
	    goto end;
	}
	memcpy(sec->data, buffer, bufferlen);
	sec->len = bufferlen;    

	/* Clean everything up */
 end:
	if (mpiv)   text->utils->free(mpiv);
	if (osSalt) text->utils->free(osSalt);
	if (buffer) text->utils->free((void *) buffer);
	mpz_clear(N);
	mpz_clear(g);
	mpz_clear(v);

	if (r) return r;
    }

    /* do the store */
    sprintf(propName, "cmusaslsecret%s", text->mech_name);
    r = (*_sasldb_putdata)(sparams->utils, sparams->utils->conn,
			   user, realm, propName,
			   (sec ? sec->data : NULL), (sec ? sec->len : 0));

    if (r) {
      sparams->utils->seterror(sparams->utils->conn, 0, 
	"Error putting secret");
      goto cleanup;
    }

    sparams->utils->log(NULL, SASL_LOG_DEBUG, "Setpass for SRP successful\n");

 cleanup:

    if (user) 	sparams->utils->free(user);
    if (realm) 	sparams->utils->free(realm);
    if (sec)    sparams->utils->free(sec);

    return r;
}

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
    text.mech_name  = "SRP-SHA-1";
    text.md = EVP_get_digestbyname("sha1");

    return srp_setpass(&text, sparams, userstr,
		       pass, passlen, flags);
}

static int
srp_cmd160_setpass(void *glob_context __attribute__((unused)),
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
    text.mech_name  = "SRP-RIPEMD-160";
    text.md = EVP_get_digestbyname("rmd160");

    return srp_setpass(&text, sparams, userstr,
		       pass, passlen, flags);
}

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
    text.mech_name  = "SRP-MD5";
    text.md = EVP_get_digestbyname("sha1");

    return srp_setpass(&text, sparams, userstr,
		       pass, passlen, flags);
}
#endif /* DO_SRP_SETPASS */

static int srp_sha1_mech_avail(void *glob_context __attribute__((unused)),
			       sasl_server_params_t *sparams __attribute__((unused)),
			       void **conn_context __attribute__((unused))) 
{
    return (EVP_get_digestbyname("sha1") ? SASL_OK : SASL_NOMECH);
}

static int srp_rmd160_mech_avail(void *glob_context __attribute__((unused)),
				 sasl_server_params_t *sparams __attribute__((unused)),
				 void **conn_context __attribute__((unused))) 
{
    return (EVP_get_digestbyname("rmd160") ? SASL_OK : SASL_NOMECH);
}

static int srp_md5_mech_avail(void *glob_context __attribute__((unused)),
			      sasl_server_params_t *sparams __attribute__((unused)),
			      void **conn_context __attribute__((unused))) 
{
    return (EVP_get_digestbyname("md5") ? SASL_OK : SASL_NOMECH);
}

static sasl_server_plug_t srp_server_plugins[] = 
{
  {
    "SRP-SHA-1",		/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* glob_context */
    &srp_sha1_server_mech_new,	/* mech_new */
    &srp_server_mech_step,	/* mech_step */
    &srp_both_mech_dispose,	/* mech_dispose */
    &srp_both_mech_free,	/* mech_free */
#if DO_SRP_SETPASS
    &srp_sha1_setpass,		/* setpass */
#else
    NULL,
#endif
    NULL,			/* user_query */
    NULL,			/* idle */
    &srp_sha1_mech_avail,	/* mech avail */
    NULL			/* spare */
  },
  /* XXX  May need aliases for SHA-1 here */
  {
    "SRP-RIPEMD-160",	        /* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* glob_context */
    &srp_rmd160_server_mech_new,/* mech_new */
    &srp_server_mech_step,	/* mech_step */
    &srp_both_mech_dispose,	/* mech_dispose */
    &srp_both_mech_free,	/* mech_free */
#if DO_SRP_SETPASS
    &srp_rmd160_setpass,	/* setpass */
#else
    NULL,
#endif
    NULL,			/* user_query */
    NULL,			/* idle */
    &srp_rmd160_mech_avail,	/* mech avail */
    NULL			/* spare */
  },
  {
    "SRP-MD5",			/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* glob_context */
    &srp_md5_server_mech_new,	/* mech_new */
    &srp_server_mech_step,	/* mech_step */
    &srp_both_mech_dispose,	/* mech_dispose */
    &srp_both_mech_free,	/* mech_free */
#if DO_SRP_SETPASS
    &srp_md5_setpass,		/* setpass */
#else
    NULL,
#endif
    NULL,			/* user_query */
    NULL,			/* idle */
    &srp_md5_mech_avail,	/* mech avail */
    NULL			/* spare */
  }
};

int srp_server_plug_init(const sasl_utils_t *utils,
			 int maxversion,
			 int *out_version,
			 const sasl_server_plug_t **pluglist,
			 int *plugcount,
			 const char *plugname __attribute__((unused)))
{
    int nplug;
    layer_option_t *opts;

    if (maxversion<SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "SRP version mismatch");
	return SASL_BADVERS;
    }

    nplug = sizeof(srp_server_plugins)/sizeof(sasl_server_plug_t);

    /* Add all digests and ciphers */
    OpenSSL_add_all_algorithms();

    /* Can't advertise integrity w/o support for HMAC-SHA-1 */
    if (EVP_get_digestbyname("sha1")) {
	/* See which digests we have available */
	opts = integrity_options;
	while (opts->name) {
	    if (EVP_get_digestbyname(opts->evp_name)) {
		opts->enabled = 1;
	    }
	    
	    opts++;
	}
    }

    /* Can't advertise confidentiality w/o support for AES */
    if (EVP_get_cipherbyname("aes-128-ofb")) {
	/* See which ciphers we have available and set max_ssf accordingly */
	opts = confidentiality_options;
	while (opts->name) {
	    if (EVP_get_cipherbyname(opts->evp_name)) {
		opts->enabled = 1;

		if (opts->ssf > srp_server_plugins[0].max_ssf) {
		    int i;
		    for (i = 0; i < nplug; i++) {
			srp_server_plugins[i].max_ssf = opts->ssf;
		    }
		}
	    }

	    opts++;
	}
    }

#ifdef DO_SRP_SETPASS
    /* Do we have database support? */
    /* Note that we can use a NULL sasl_conn_t because our
     * sasl_utils_t is "blessed" with the global callbacks */
    if(_sasl_check_db(utils, NULL) != SASL_OK)
	return SASL_NOMECH;
#endif

    *pluglist=srp_server_plugins;

    *plugcount=nplug;
    *out_version=SASL_SERVER_PLUG_VERSION;

    return SASL_OK;
}

/* put in sasl_wrongmech */
static int srp_sha1_client_mech_new(void *glob_context __attribute__((unused)),
			       sasl_client_params_t *params,
			       void **conn)
{
    const EVP_MD *md;
    context_t *text;

    if ((md = EVP_get_digestbyname("sha1")) == NULL)
	return SASL_NOMECH;

    /* holds state are in */
    text = params->utils->malloc(sizeof(context_t));
    if (text==NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(context_t));

    text->state=1;
    text->utils = params->utils;
    text->md = md;
    *conn=text;

    return SASL_OK;
}

static int srp_rmd160_client_mech_new(void *glob_context __attribute__((unused)),
				      sasl_client_params_t *params,
				      void **conn)
{
    const EVP_MD *md;
    context_t *text;

    if ((md = EVP_get_digestbyname("rmd160")) == NULL)
	return SASL_NOMECH;

    /* holds state are in */
    text = params->utils->malloc(sizeof(context_t));
    if (text==NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(context_t));

    text->state=1;
    text->utils = params->utils;
    text->md = md;

    *conn=text;

    return SASL_OK;
}

static int srp_md5_client_mech_new(void *glob_context __attribute__((unused)),
			       sasl_client_params_t *params,
			       void **conn)
{
    const EVP_MD *md;
    context_t *text;

    if ((md = EVP_get_digestbyname("md5")) == NULL)
	return SASL_NOMECH;

    /* holds state are in */
    text = params->utils->malloc(sizeof(context_t));
    if (text==NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(context_t));

    text->state=1;
    text->utils = params->utils;
    text->md = md;

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
     *   absolutely nothing
     * 
     */
    if (serverinlen > 0) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid input to first step of SRP\n");
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

    params->canon_user(params->utils->conn, text->authid, 0,
		       SASL_CU_AUTHID, oparams);
    params->canon_user(params->utils->conn, text->userid, 0,
		       SASL_CU_AUTHZID, oparams);

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

/* Check to see if N,g is in the recommended list */
static int check_N_and_g(mpz_t N, mpz_t g)
{
    char *N_prime;
    unsigned long g_prime;
    unsigned i;
    int r = SASL_FAIL;

    N_prime = mpz_get_str(NULL, 16, N);
    g_prime = mpz_get_ui(g);

    for (i = 0; i < NUM_Ng; i++) {
	if (!strcasecmp(N_prime, Ng_tab[i].N) && (g_prime == Ng_tab[i].g)) {
	    r = SASL_OK;
	    break;
	}
    }

    free(N_prime);
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
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error getting MPI string for 'N'\n");
	goto done;
    }

    r = GetMPI((unsigned char *) data, datalen, &text->g, &data, &datalen);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error getting MPI string for 'g'\n");
	goto done;
    }

    /* Check N and g to see if they are one of the recommended pairs */
    r = check_N_and_g(text->N, text->g);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Values of 'N' and 'g' are not recommended\n");
	goto done;
    }

    r = GetOS(params->utils, (unsigned char *)data, datalen,
	      &text->salt, &text->saltlen, &data, &datalen);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error getting OS string for 's'\n");
	goto done;
    }

    r = GetUTF8(params->utils, data, datalen, &text->server_options,
		&data, &datalen);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error getting UTF8 string for 'L'");
	goto done;
    }
    params->utils->log(NULL, SASL_LOG_DEBUG, "L: '%s'", text->server_options);

    if (datalen != 0) {
	params->utils->log(NULL, SASL_LOG_ERR, "Extra data parsing buffer\n");
	goto done;
    }

    /* parse server options */
    memset(&server_opts, 0, sizeof(srp_options_t));
    r = ParseOptions(params->utils, text->server_options, &server_opts, 0);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR, "Error parsing options\n");
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
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error creating client options\n");
	goto done;
    }

    r = OptionsToString(params->utils, &text->client_opts,
			&text->client_options);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error converting client options to an option string\n");
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
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error making MPI string from A\n");
	goto done;
    }

    r = MakeUTF8(params->utils, text->userid, &utf8I, &utf8Ilen);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error making UTF8 string from userid ('I')\n");
	goto done;
    }

    r = MakeUTF8(params->utils, text->client_options, &utf8o, &utf8olen);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error making UTF8 string from client options ('o')\n");
	goto done;
    }

    r = MakeBuffer(params->utils, mpiA, mpiAlen, utf8I, utf8Ilen,
		   utf8o, utf8olen, NULL, 0, clientout, clientoutlen);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR, "Error making output buffer\n");
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

    /* Check the value of B */
    if (!mpz_cmp_ui(text->B, 0) || !mpz_cmp_ui(text->B, 1)) {
	params->utils->log(NULL, SASL_LOG_ERR, "Illegal value for 'B'\n");
	return SASL_FAIL;
    }
    
    if (datalen != 0) {
	params->utils->log(NULL, SASL_LOG_ERR, "Extra data parsing buffer\n");
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
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error creating OS string for M1\n");
	goto done;
    }

    r = MakeBuffer(params->utils, osM1, osM1len, NULL, 0, NULL, 0, NULL, 0,
		   clientout, clientoutlen);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error creating buffer in step 3\n");
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
	params->utils->log(NULL, SASL_LOG_ERR, "Extra data parsing buffer\n");
	r = SASL_FAIL;
	goto done;
    }

    /* calculate our own M2 */
    r = CalculateM2(text, text->A, text->authid, text->userid,
		    text->client_options, text->M1, text->M1len,
		    text->K, text->Klen, &myM2, &myM2len);
    if (r) {
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Error calculating our own M2 (server evidence)\n");
	goto done;
    }

    /* compare to see if is server spoof */
    if (myM2len != serverM2len) {
	params->utils->log(NULL, SASL_LOG_ERR, "Server M2 length wrong\n");
	r = SASL_FAIL;
	goto done;
    }

    
    for (i = 0; i < myM2len; i++) {
	if (serverM2[i] != myM2[i]) {
	    params->utils->log(NULL, SASL_LOG_ERR,
			       "Server spoof detected. M2 incorrect\n");
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

  params->utils->log(NULL, SASL_LOG_DEBUG, "SRP client step %d\n",text->state);

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
	  params->utils->log(NULL, SASL_LOG_ERR, "Invalid SRP step\n");
	  return SASL_FAIL;
      }

  return SASL_FAIL;
}


static sasl_client_plug_t srp_client_plugins[] = 
{
  {
    "SRP-SHA-1",   	        /* mech_name */
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
  /* XXX  May need aliases for SHA-1 here */
  {
    "SRP-RIPEMD-160",   	/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    SASL_FEAT_WANT_CLIENT_FIRST,/* features */
    NULL,			/* required_prompts */
    NULL,			/* glob_context */
    &srp_rmd160_client_mech_new,/* mech_new */
    &srp_client_mech_step,	/* mech_step */
    &srp_both_mech_dispose,	/* mech_dispose */
    &srp_both_mech_free,	/* mech_free */
    NULL,			/* idle */
    NULL,			/* spare1 */
    NULL			/* spare2 */
  },
  {
    "SRP-MD5",   	        /* mech_name */
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
    int nplug;
    layer_option_t *opts;

    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "SRP version mismatch");
	return SASL_BADVERS;
    }

    nplug = sizeof(srp_client_plugins)/sizeof(sasl_client_plug_t);

    /* Add all digests and ciphers */
    OpenSSL_add_all_algorithms();

    /* See which digests we have available */
    opts = integrity_options;
    while (opts->name) {
	if (EVP_get_digestbyname(opts->evp_name))
	    opts->enabled = 1;

	opts++;
    }

    /* See which ciphers we have available and set max_ssf accordingly */
    opts = confidentiality_options;
    while (opts->name) {
	if (EVP_get_cipherbyname(opts->evp_name)) {
	    opts->enabled = 1;

	    if (opts->ssf > srp_client_plugins[0].max_ssf) {
		int i;
		for (i = 0; i < nplug; i++) {
		    srp_client_plugins[i].max_ssf = opts->ssf;
		}
	    }
	}

	opts++;
    }

    *pluglist=srp_client_plugins;

    *plugcount=nplug;
    *out_version=SASL_CLIENT_PLUG_VERSION;

    return SASL_OK;
}
