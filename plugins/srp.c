/* SRP SASL plugin
 * Tim Martin  3/17/00
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
#include <sasl.h>
#include <saslplug.h>

#include <assert.h>
#include <ctype.h>

/* for big number support */
#include <gmp.h>

/* for SHA1 support */
#include <openssl/sha.h>

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
/* xxx  # include "saslANONYMOUS.h" */
#endif

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define SRP_VERSION (3)

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

/* security bits */
#define SRP_SUPPORTS_INTEGRITY 1
#define SRP_SUPPORTS_SEQUENCENUMBERS 2
#define SRP_SUPPORTS_CONFIDENTIALITY 4


#define HASHLEN SHA_DIGEST_LENGTH
#define MAXBIGNUMLEN 1024

/* Size of N in bits */
#define BITSFORN 128
/* Size of diffie-hellman secrets a and b */
#define BITSFORab 64


#define VL(x) printf x

/* global: if we've already set a pass entry */
static int mydb_initialized = 0;

typedef struct netstring_s {

    int size;
    
    char data[1]; /* allocate to size you need */

} netstring_t;

/* doesn't contain netstring formatting */
typedef struct netdata_s {

    int size;
    
    char data[1]; /* allocate to size you need */

} netdata_t;



typedef struct hash_s {

    unsigned char data[SHA_DIGEST_LENGTH];
    int len;

} hash_t;

typedef struct interleaved_s {

    unsigned char data[SHA_DIGEST_LENGTH*2];

} interleaved_t;

typedef struct savedinfo_s {

    char salt[16];

    mpz_t verifier;

} savedinfo_t;

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

    interleaved_t sharedsecretK;

    char *authid;
    char *realm;
    sasl_secret_t *password;

    unsigned char client_options;
    unsigned char server_options;

    hash_t M1; /* client needs to save between steps 3 and 4 */
    savedinfo_t *sinfo;

} context_t;


/* forward declarations */
static int create_public_server(mpz_t g, mpz_t N, mpz_t v,
				mpz_t b, mpz_t B);

static char frombits(unsigned int i)
{
    assert(i <= 15);

    if (i<=9) return '0'+i;

    return 'a'+ (i-10);
}

static int tobits(char c)
{
    if ((int) isdigit(c))
	return c-'0';

    if ((c>='a') && (c<='f'))
	return c-'a'+10;

    if ((c>='A') && (c<='F'))
	return c-'A'+10;

    return 0;
}


/* copy a string */
static int
srp_strdup(sasl_utils_t * utils, const char *in, char **out, int *outlen)
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

static netdata_t *create_netdata_bigint(mpz_t n, sasl_utils_t *utils)
{
    int size;
    netdata_t *ret;
    int prefixlen=0;
    int lup;
    char *str;

    size = mpz_sizeinbase (n, 16);

    str = (char *) utils->malloc(size+10);
    if (!str) return NULL;
    mpz_get_str (str, 16, n);

    ret = (netdata_t *) utils->malloc(sizeof(netdata_t)+20+size);
    if (!ret) return NULL;

    if (size%2!=0) {
	ret->data[0]=tobits(str[0]);
	size--;
	str++;
	prefixlen=1;
    }

    for (lup=0;lup<size/2;lup++)
    {
	ret->data[prefixlen+lup] = (tobits(str[lup*2]) << 4);
	ret->data[prefixlen+lup] |= tobits(str[lup*2+1]);
    }

    ret->size = prefixlen+(size/2);

    return ret;
}

static netstring_t *create_netstring_bigint(mpz_t n, sasl_utils_t *utils)
{
    int size;
    int prefixlen;
    netstring_t *ret;
    int lup;
    char *str;

    size = mpz_sizeinbase (n, 16);

    str = (char *) utils->malloc(size+10);
    if (!str) return NULL;
    mpz_get_str (str, 16, n);

    ret = (netstring_t *) utils->malloc(sizeof(netstring_t)+20+size);
    if (!ret) return NULL;

    sprintf(ret->data,"%d:",(size+1)/2);
    prefixlen = strlen(ret->data);

    if (size%2!=0) {
	ret->data[prefixlen]=tobits(str[0]);
	size--;
	str++;
	prefixlen++;
    }

    for (lup=0;lup<size/2;lup++)
    {
	ret->data[prefixlen+lup] = (tobits(str[lup*2]) << 4);
	ret->data[prefixlen+lup] |= tobits(str[lup*2+1]);
    }

    ret->data[prefixlen+size/2] = ',';
    ret->data[prefixlen+(size/2)+1] = '\0';

    ret->size = prefixlen+(size/2)+1;

    return ret;
}

/*
 * Create a netstring from a character array
 */

static netstring_t *create_netstring_str(char *str, int len, sasl_utils_t *utils)
{
    netstring_t *ret;
    int prefixlen;

    ret = (netstring_t *) utils->malloc(sizeof(netstring_t)+10+len);

    sprintf(ret->data,"%d:",len);
    prefixlen = strlen(ret->data);

    memcpy(ret->data+prefixlen,str,len);

    ret->data[prefixlen+len]=',';
    ret->data[prefixlen+len+1]='\0';

    ret->size = prefixlen+len+1;

    return ret;
}

static void Hash(unsigned char *data, unsigned long len, hash_t *hash)
{
    SHA_CTX c;

    SHA1_Init(&c);

    SHA1_Update(&c,data,len);

    SHA1_Final(&(hash->data[0]),&c);
    
    hash->len = SHA_DIGEST_LENGTH; 

    /*    int lup;

    memset(hash->data, 'z', sizeof(hash->data));

    if (len > SHA_DIGEST_LENGTH) len = SHA_DIGEST_LENGTH;

    for (lup=0;lup<(int)len;lup++)
	hash->data[lup] = data[lup];

	hash->len = SHA_DIGEST_LENGTH;*/
}

static int Hash_bigint(mpz_t num, hash_t *hash, sasl_utils_t *utils)
{ 
    int size;
    int lup;
    char *str;
    char *data;

    size = mpz_sizeinbase (num, 16);
    
    str = (char *) utils->malloc(size+10);
    if (!str) return SASL_NOMEM;
    mpz_get_str (str, 16, num);
    
    data = (char *) utils->malloc(size+10);
    if (!data) return SASL_NOMEM;

    for (lup=0;lup<size/2;lup++)
    {
	data[lup] = (tobits(str[lup*2]) << 4);
	data[lup] = tobits(str[lup*2+1]);
    }

    Hash(data, size/2, hash);

    utils->free(str);
    utils->free(data);

    return SASL_OK;
}

static int SHA_Interleave(mpz_t num, interleaved_t *inter, sasl_utils_t *utils)
{
    netstring_t *tmpns;
    char *T;
    int Tlen;
    char *E, *F;
    int lup;
    hash_t G;
    hash_t H;

    tmpns = create_netstring_bigint(num, utils);
    if (!tmpns) return SASL_NOMEM;
    
    /* removing leading zeros is already done right? */

    /* if odd kill first byte */
    T = tmpns->data;
    Tlen = tmpns->size;
    if (Tlen % 2 !=0) { T++; Tlen--; }

    E = (char *) utils->malloc(Tlen/2+1);
    if (!E) return SASL_NOMEM;
    F = (char *) utils->malloc(Tlen/2+1);
    if (!F) return SASL_NOMEM;

    /* E gets even bytes. F gets odd */
    for (lup=0;lup<Tlen/2;lup++)
    {
	E[lup]=T[lup*2];
	F[lup]=T[lup*2+1];
    }

    utils->free(tmpns);

    /* hash E and F into G and H*/
    Hash(E,Tlen/2, &G);
    Hash(F,Tlen/2, &H);

    utils->free(E);
    utils->free(F);

    /* interleave hashes into 'inter' */
    for (lup=0;lup<HASHLEN*2;lup++)
    {
	if (lup%2 == 0)
	    inter->data[lup]=G.data[lup/2];
	else
	    inter->data[lup]=H.data[(lup-1)/2];		
    }

    return SASL_OK;
}

/* returns the realm we should pretend to be in */
static int parseuser(sasl_utils_t *utils,
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



static int
server_start(void *glob_context __attribute__((unused)),
             sasl_server_params_t *params,
	     const char *challenge __attribute__((unused)),
	     int challen __attribute__((unused)),
	     void **conn,
	     const char **errstr)
{
  context_t *text;

  /* holds state are in */
  if (!conn)
      return SASL_BADPARAM;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;

  memset(text, '\0', sizeof(context_t));
  text->state=1;
  *conn=text;
  
  if (errstr)
      *errstr = NULL;

  return SASL_OK;
}


static int bigint_fromstr(unsigned char *data, int len, sasl_utils_t *utils, mpz_t ret)
{
    char *str;
    int lup;

    mpz_init(ret);

    /* convert to base 16 */
    str = (char *) utils->malloc(len*2+10);
    if (!str) return SASL_NOMEM;

    for (lup=0;lup<len;lup++)
    {
	str[lup*2]   = frombits(data[lup] >> 4);
	str[lup*2+1] = frombits(data[lup] & 15);
    }
    
    str[lup*2]='\0';

    mpz_set_str (ret, str, 16);

    utils->free(str);

    return SASL_OK;
}

static int bigint_fromnetdata(netdata_t *ns, sasl_utils_t *utils, mpz_t ret)
{
    return bigint_fromstr(ns->data, ns->size, utils,ret);
}


/* The probability of a
   false positive is (1/4)**REPS.  A reasonable value of reps is 25. */
#define REPS 25

static int old_generate_N(mpz_t N,mpz_t bigg)
{
    mpz_t try;
    mpz_t exp;
    mpz_t res;
    int g;
    mpz_t z;
    int bad_g;

    mpz_init(try);
    mpz_init(z);
    mpz_init(N);
   

    do {

	do {
	    mpz_random(try, BITSFORN/(8*sizeof(int))); 
	} while (mpz_probab_prime_p(try,REPS)!=1);

	/* N = 2q+1 where q = try */
	mpz_mul_ui( z, try, 2);
	mpz_add_ui( N, z, 1);

    } while (mpz_probab_prime_p(N,REPS)!=1);

    /* Calculate the generator g */
    mpz_init(exp);
    mpz_init(bigg);
    mpz_init(res);
    g=1;

    do {
	bad_g = 0;
	g++; /* starts at 2 */
	mpz_set_ui (bigg, g);

	if (g>100) return SASL_FAIL;
	    
	/* g^((p-1)/q) % p ==>  g^((z/q)) % N for q=2,try */
	/* if equals 1 for either q then g is bad */

	/* 2 */
	mpz_tdiv_q_ui(exp,z,2);	

	mpz_powm (res, bigg, exp, N);      
	if ((mpz_size (res) ==1) && (mpz_get_ui (res)==1)) {
	    bad_g = 1;
	}

	/* try */
	mpz_tdiv_q(exp,z,try);	

	mpz_powm (res, bigg, exp, N);      
	if ((mpz_size (res) ==1) && (mpz_get_ui (res)==1)) {
	    bad_g = 1;
	}
	
	
    } while (bad_g == 1);
    
    mpz_set_ui (N, 100);
    mpz_set_ui (bigg, 2);

    return SASL_FAIL;
}


/* A large safe prime (N = 2q+1, where q is prime) All arithmetic is done modulo N */
static int generate_N_and_g(mpz_t N,mpz_t bigg)
{

#define BIGNUM "3Kn/YYiomHkFkfM1x4kayR125MGkzpLUDy3y14FlTMwYnhZkjrMXnoC2TcFAecNlU5kFzgcpKYUbBOPZFRtyf3"
    {
	char dec[4000];
	int declen;
	int lup;

	lup = sasl_decode64(BIGNUM,strlen(BIGNUM),dec,&declen);

	printf("error = %d\n",lup);

	printf("len = %d\n",strlen(BIGNUM));
	printf("declen = %d\n",declen);

	/*	for (lup=0;lup<declen;lup++) {
	    printf("%d %d\n",lup,dec[lup]);
	    }*/

	for (lup=0;lup<10;lup++) {
	    printf("%c",frombits( (dec[lup] >> 4) & 15));
	    printf("%c",frombits( dec[lup] & 15));
	}
	printf("\n");


    }

    /*
     * 512 bits
     *  N = dca9ff6188a898790591
     *  g = 2
     */

    {
	int result;

	mpz_init(N);
	result = mpz_set_str (N, "dca9ff6188a898790591", 16);
	if (result) return SASL_FAIL;
	mpz_init(bigg);
	mpz_set_ui (bigg, 2);
    }

    return SASL_OK;
}

static void merge_netstrings(sasl_utils_t *utils,
			     netstring_t *ns1,netstring_t *ns2,netstring_t *ns3,
			     char **out, int *outlen)
{
    int totallen;
    char lenstr[30];
    char *tmp;

    /* calculate total length of strings */
    totallen = 0;
    if (ns1)
	totallen+=ns1->size;
    if (ns2)
	totallen+=ns2->size;
    if (ns3)
	totallen+=ns3->size;

    snprintf(lenstr,sizeof(lenstr),"%d:",totallen);
    
    *outlen = strlen(lenstr) + totallen + 1;
    *out = utils->malloc(*outlen);
    
    tmp = *out;
    memcpy(tmp,lenstr, strlen(lenstr));
    tmp+=strlen(lenstr);

    if (ns1) {
	memcpy( tmp, ns1->data, ns1->size);
	tmp+=ns1->size;
    }
    if (ns2) {
	memcpy( tmp, ns2->data, ns2->size);
	tmp+=ns2->size;
    }
    if (ns3) {
	memcpy( tmp, ns3->data, ns3->size);
	tmp+=ns3->size;
    }
    tmp[0]=',';
}

static int checkvalid_netstring(char *in, int inlen, char **datastart, int *datalen)
{
    char lenstr[20];
    int pos = 0;
    
    /* see how big it says it is */
    while ((pos<inlen) && (pos < (int) sizeof(lenstr)) && (isdigit((int) in[pos]))) {
	lenstr[pos] = in[pos];
	pos++;
    }
    
    if (pos == 0) {
	VL (("netstring doesn't contain length indicator\n"));
	return SASL_FAIL;
    }

    lenstr[pos]='\0';

    (*datalen) = strtol(lenstr, NULL, 10);

    if (errno == ERANGE) {
	VL(("Underflow or overflow occured\n"));
	return SASL_FAIL;
    }

    if ((*datalen) < 0) {
	VL(("Negative netstring length\n"));
	return SASL_FAIL;
    }

    if (inlen < pos+1+(*datalen)+1) {
	VL(("Netsrring wrong size (%d vs %d)\n", inlen, pos+1+(*datalen)+1));
	return SASL_FAIL;
    }
    
    if (in[pos]!=':') {
	VL(("Netstring missing required colon\n"));
	return SASL_FAIL;
    }

    if (in[pos+(*datalen)+1]!=',') {
	VL(("Netstring missing required comma\n"));
	return SASL_FAIL;
    }

    *datastart = in+pos+1;

    return SASL_OK;
}

static int split_netstrings(sasl_utils_t *utils,
			    netdata_t **nd1, netdata_t **nd2, netdata_t **nd3,
			    char *in, int inlen)
{
    char *datastart, *ns_str;
    int datalen, ns_len;
    int result;

    /*    int lup;
    
        for (lup=0;lup<inlen;lup++)
    {
	if (isalnum(in[lup]))
	    printf("%d %c %d\n",lup,in[lup],in[lup]);
	else
	    printf("%d ? %d\n",lup,in[lup]);
	    } */

    result = checkvalid_netstring(in, inlen, &datastart, &datalen);
    if (result!=SASL_OK) return result;

    if (nd1) {
	result = checkvalid_netstring(datastart, datalen, &ns_str, &ns_len);
	if (result!=SASL_OK) return result;

	*nd1 = utils->malloc(sizeof(netstring_t)+ns_len+1);
	if (!*nd1) return SASL_NOMEM;

	(*nd1)->size = ns_len;
	memcpy((*nd1)->data, ns_str, ns_len);
	(*nd1)->data[ns_len] = '\0';

	datastart = ns_str+ns_len+1;
    }

    if (nd2) {

	result = checkvalid_netstring(datastart, datalen, &ns_str, &ns_len);
	if (result!=SASL_OK) return result;

	*nd2 = utils->malloc(sizeof(netstring_t)+ns_len+1);
	if (!*nd2) return SASL_NOMEM;

	(*nd2)->size = ns_len;
	memcpy((*nd2)->data, ns_str, ns_len);
	(*nd2)->data[ns_len] = '\0';

	datastart = ns_str+ns_len+1;
    }

    if (nd3) {
	result = checkvalid_netstring(datastart, datalen, &ns_str, &ns_len);
	if (result!=SASL_OK) return result;

	*nd3 = utils->malloc(sizeof(netstring_t)+ns_len+1);
	if (!*nd3) return SASL_NOMEM;

	(*nd3)->size = ns_len;
	memcpy((*nd3)->data, ns_str, ns_len);
	(*nd3)->data[ns_len] = '\0';

	datastart = ns_str+ns_len+1;
    }

    VL(("netstring split worked\n"));
    
    return SASL_OK;
}

static int calculate_server_evidence(char *authname,
				     mpz_t A,
				     unsigned char client_options,
				     hash_t *M1,
				     interleaved_t *K,
				     hash_t *out,
				     sasl_utils_t *utils)
{
    char *concatstr;
    int len;
    char *M2;
    netdata_t *tmpnd;

    tmpnd = create_netdata_bigint(A, utils);
    if (tmpnd==NULL) return SASL_NOMEM;

    len = strlen(authname) + tmpnd->size + 1 + HASHLEN + sizeof(K->data);

    concatstr = (char *) utils->malloc(len+1);
    if (!concatstr) return SASL_NOMEM;

    /* Server calculate evidence M2
     * M2 = H(U | A | o | M1 | K)
    */

    M2 = (char *) concatstr;
    
    /* add U (authname) */
    memcpy(M2, authname, strlen(authname));
    M2+=strlen(authname);

    /* append A */
    memcpy(M2,tmpnd->data, tmpnd->size);
    M2+=tmpnd->size;
    utils->free(tmpnd);    

    /* append o (options) */
    M2[0] = client_options;
    M2+=1;

    /* append M1 */
    memcpy(M2, M1->data, sizeof(M1->data));
    M2+=sizeof(M1->data);

    /* append K */
    memcpy(M2, K->data, sizeof(K->data));
    
    Hash(concatstr, len, out);

    return SASL_OK;
}

static int calculate_client_evidence(mpz_t N, mpz_t g,
				     char *salt, int saltlen,
				     unsigned char server_options,
				     mpz_t A, mpz_t B,
				     interleaved_t *K,
				     hash_t *out,
				     sasl_utils_t *utils)
{
    hash_t Hn;
    hash_t Hg;
    char concatstr[HASHLEN+MAXBIGNUMLEN+1+MAXBIGNUMLEN+MAXBIGNUMLEN+HASHLEN*2];
    char *M1;
    int lup;
    netdata_t *tmpnd;

    /* Client calculate evidence M1
       M1 = H(H(N) XOR H(g) | s | Z | A | B | K)
    */

    Hash_bigint(N, &Hn, utils);
    Hash_bigint(g, &Hg, utils);
    
    /* Hn XOR Hg into Hn*/
    for (lup=0;lup<HASHLEN;lup++)
	Hn.data[lup]=Hn.data[lup]^Hg.data[lup];

    M1 = (char *) concatstr;
    memcpy(M1,Hn.data, HASHLEN);
    M1+=HASHLEN;
    

    /* append salt */
    memcpy(M1,salt, saltlen);
    M1+=saltlen;

    /* append Z (options) */
    M1[0] = server_options;
    M1+=1;

    /* append A */
    tmpnd = create_netdata_bigint(A, utils);
    if (tmpnd==NULL) return SASL_NOMEM;
    memcpy(M1,tmpnd->data, tmpnd->size);
    M1+=tmpnd->size;
    utils->free(tmpnd);

    /* append B */
    tmpnd = create_netdata_bigint(B, utils);
    if (tmpnd==NULL) return SASL_NOMEM;
    memcpy(M1,tmpnd->data, tmpnd->size);
    M1+=tmpnd->size;
    utils->free(tmpnd);

    /* append K */
    memcpy(M1, K->data, sizeof(K->data));
    M1+=sizeof(K->data);

    Hash(concatstr, M1-concatstr, out);

    return SASL_OK;
}




static int get_salt_and_verifier(const char *userid, const char *realm,
				 sasl_utils_t *utils, savedinfo_t **sinfo,
				 const char **errstr)
{
    sasl_server_getsecret_t *getsecret;
    void *getsecret_context;
    sasl_secret_t *sec=NULL;
    int result;
    int saltlen=16;
    char *vstr;
    int vlen;

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
    result = getsecret(getsecret_context, "SRP", userid, realm, &sec);
    if (result == SASL_NOUSER || !sec) {
      if (errstr) *errstr = "no secret in database";
      return SASL_NOUSER;
    }
    if (result != SASL_OK) {
	return result;
    }

    if (sec->len < saltlen) {
	VL(("Secret database corruption (size %d)\n",sec->len));
	if (errstr) *errstr = "secret database corruption";
	return SASL_FAIL;
    }

    /* data is in format
     *
     * salt - series of bytes
     * verifier - netstring
     */    
    *sinfo = (savedinfo_t *) utils->malloc(sizeof(savedinfo_t));
    if (!*sinfo) return SASL_NOMEM;

    saltlen = sizeof( (*sinfo)->salt);

    memcpy( (*sinfo)->salt, sec->data, saltlen);

    result = checkvalid_netstring((char *) sec->data+saltlen,sec->len-saltlen, &vstr, &vlen);
    if (result!=SASL_OK) {
	VL(("Invalid netstring saved. Database corrupted\n"));
	return result;          
    }

    result = bigint_fromstr(vstr, vlen, utils, (*sinfo)->verifier);
    if (result!=SASL_OK) {
	VL(("Unable to make bigint from string\n"));
	return result;
    }
    
    return SASL_OK;
}


static int
server_continue_step (void *conn_context,
	       sasl_server_params_t *sparams,
	       const char *clientin,
	       int clientinlen,
	       char **serverout,
	       int *serveroutlen,
	       sasl_out_params_t *oparams,
	       const char **errstr)
{
  int result;
  context_t *text = (context_t *) conn_context;

  if (!sparams
      || !serverout
      || !serveroutlen
      || !oparams)
    return SASL_BADPARAM;

  if (clientinlen < 0)
      return SASL_BADPARAM;

  if (errstr)
      *errstr = NULL;

  VL(("SRP server step %d\n",text->state));

  if (text->state == 1) {
      netstring_t *ns1;
      netstring_t *ns2;
      netstring_t *ns3;

      /* Server sends N, g, and Z */

      /*
       * N  - A large safe prime (N = 2q+1, where q is prime) All arithmetic is done modulo N 
       * g  - generator
       */

       /* generate N and g */
       result = generate_N_and_g(text->N,text->g);
       if (result!=SASL_OK) return result;

       /* set Z */
       /* xxx everything off right now */
       text->server_options = 0;
       
       ns1 = create_netstring_bigint(text->N,sparams->utils);
       ns2 = create_netstring_bigint(text->g,sparams->utils);
       ns3 = create_netstring_str(&(text->server_options),1,sparams->utils);

       /* put them all together */
       merge_netstrings(sparams->utils,ns1,ns2,ns3, serverout, serveroutlen);

       text->state = 2;

       return SASL_CONTINUE;
  }
  if (text->state == 2) {
      netdata_t *nd1=NULL;
      netdata_t *nd2=NULL;
      netdata_t *nd3=NULL;

      netstring_t *ns1=NULL;
      netstring_t *ns2=NULL;
      int result;
      hash_t hashedB;
      unsigned int u;
      mpz_t x;

      /* We received:
       *
       * U - authname 
       * A - client's public key
       * o - options
       */

      result = split_netstrings(sparams->utils, &nd1,&nd2,&nd3,
				(char *) clientin, clientinlen);
      if (result!=SASL_OK) return result;

      result = bigint_fromnetdata(nd2,sparams->utils ,text->A);
      if (result!=SASL_OK) return result;

      printf("server A: ");
      mpz_out_str (stdout, 10, text->A);
      printf("\n");

      if (nd3->size!=1) {
	  VL(("Options is wrong size\n"));
	  return SASL_FAIL;
      }
      text->client_options = nd3->data[0];

      /* xxx do something with options */
      
      /* We send:
       *
       * s - salt
       * B - server public key
       */

      result = parseuser(sparams->utils, &text->authid, &text->realm, sparams->user_realm,
			 sparams->serverFQDN, nd1->data);
      if (result != SASL_OK) {
	  return result;
      }

      printf("authid = %s realm = %s\n",text->authid,text->realm);

      result = get_salt_and_verifier(text->authid,text->realm,
				     sparams->utils, &(text->sinfo), errstr);
      if (result!=SASL_OK) return result;

      VL(("Retrieved salt from db\n"));

      ns1 = create_netstring_str(text->sinfo->salt, sizeof(text->sinfo->salt), sparams->utils);

      VL(("Calculating B\n"));

      /* B = (v + g^b) %N */
      result = create_public_server(text->g, text->N, text->sinfo->verifier, text->b, text->B);
      if (result!=SASL_OK) return result;

      ns2 = create_netstring_bigint(text->B, sparams->utils);

      printf("server B: ");
      mpz_out_str (stdout, 10, text->B);
      printf("\n");

      /* u is first 32 bits of B; MSB first */      
      Hash_bigint(text->B, &hashedB, sparams->utils);
      memcpy(&u, hashedB.data, 4);
      u = ntohl(u);

      printf("U = %d\n",u);

      /* calculate server shared secret */
      /* S = (A*v^u)^b %N */

      mpz_init(text->S);

      mpz_powm_ui (text->S, text->sinfo->verifier, u, text->N);      
      mpz_mul (text->S, text->S, text->A);
      mpz_powm (text->S, text->S, text->b, text->N);

      result = SHA_Interleave(text->S, &text->sharedsecretK, sparams->utils);
      if (result!=SASL_OK) return result;

      printf("server calculated S: ");
      mpz_out_str (stdout, 10, text->S);
      printf("\n");

      merge_netstrings(sparams->utils,ns1,ns2,NULL,serverout,serveroutlen);

      text->state = 3;

      return SASL_CONTINUE;
  }

  if (text->state == 3) {

      netstring_t *ns1=NULL;      
      unsigned char *M1in;
      int M1inlen;
      hash_t M1;
      hash_t M2;
      int lup;

      /*
       * Recieve M1 evidence
       *
       */
      result = checkvalid_netstring((char *) clientin, clientinlen, (char **) &M1in, &M1inlen);
      if (result!=SASL_OK) return result;      

      /* Let's calculate M1 ourselves and see if it matches */
      result = calculate_client_evidence(text->N, text->g,
					 text->sinfo->salt, sizeof(text->sinfo->salt),
					 text->server_options,
					 text->A, text->B,
					 &text->sharedsecretK,
					 &M1,
					 sparams->utils);
      if (result!=SASL_OK) return result;      
      
      for (lup=0;lup<HASHLEN;lup++)
      {
	  if (M1in[lup]!=M1.data[lup]) {
	      if (errstr) *errstr = "Client evidence is wrong";
	      return SASL_BADAUTH;
	  }
      }

      /*
       * Calculate and send:
       *  M2
       */

      result = calculate_server_evidence(text->authid,
					 text->A,
					 text->client_options,
					 &M1,
					 &text->sharedsecretK,
					 &M2,
					 sparams->utils);
      if (result!=SASL_OK) return result;      
      
      ns1 = create_netstring_str(M2.data, sizeof(M2.data), sparams->utils);
      if (ns1==NULL) return SASL_NOMEM;
      
      *serverout = sparams->utils->malloc(ns1->size+1);
      if (!*serverout) return SASL_NOMEM;
      memcpy(*serverout, ns1->data, ns1->size);
      *serveroutlen = ns1->size;

      /* Set the oparams */
      oparams->doneflag=1;
      result = srp_strdup(sparams->utils, text->authid, &oparams->user, NULL); 
      result = srp_strdup(sparams->utils, text->realm, &oparams->realm, NULL); 
      result = srp_strdup(sparams->utils, text->authid, &oparams->authid, NULL);
      oparams->mech_ssf = 0;
      oparams->maxoutbuf = 0;
      oparams->encode = NULL;
      oparams->decode = NULL;
      oparams->param_version = 0;

      text->state = 4;
      return SASL_OK;
  }

  return SASL_FAIL;
}

/*
 * Put a DUMMY entry in the db to show that there is at least one SRP entry in the db
 *
 * Note: this function is duplicated in multiple plugins. If you fix
 * something here please update the other files
 */
static int mechanism_fill_db(char *mech_name, sasl_server_params_t *sparams)
{
  int result;
  sasl_server_putsecret_t *putsecret;
  void *putsecret_context;
  sasl_secret_t *sec = NULL;
  long version;

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
  version = htonl(SRP_VERSION);
  memcpy(sec->data, &version, 4);

  /* do the store */
  result = putsecret(putsecret_context,
		     mech_name, 
		     "",
		     "",
		     sec);

  if (result == SASL_OK)
  {
      mydb_initialized = 1;
  }

  return result;
}

static int calculate_x(sasl_utils_t *utils,
		       const char *user, int userlen,
		       const char *pass, int passlen,
		       char *salt, int saltlen,
		       mpz_t x)
{
    char *userpassstr = NULL;
    char *saltfoo =NULL;
    hash_t userpasshash;
    hash_t hashx;
    int result;

    /* create <username> | ':' | <pass> */
    userpassstr = utils->malloc(userlen+1+passlen+1);
    if (!userpassstr) {
	result = SASL_NOMEM;
	goto done;
    }
	
    strcpy(userpassstr, user);
    userpassstr[userlen]=':';
    memcpy(userpassstr+userlen+1, pass, passlen);
    userpassstr[userlen+1+passlen]='\0';

    /* SHA( <username> | ':' | <pass> ) */
    Hash(userpassstr, userlen+1+passlen, &userpasshash);
    
    /* create <salt> | SHA ( ... ) */
    saltfoo = utils->malloc(saltlen+HASHLEN+1);
    if (!saltfoo) {
	result = SASL_NOMEM;
	goto done;
    }
    
    memcpy(saltfoo, salt, saltlen);
    memcpy(saltfoo+saltlen, userpasshash.data, HASHLEN);

    /* x = SHA( <salt> | SHA (... )) */
    Hash(saltfoo, saltlen+HASHLEN, &hashx);

    result = bigint_fromstr(hashx.data, sizeof(hashx.data), utils, x);
    if (result!=SASL_OK) goto done;

 done:
    
    if (userpassstr) utils->free(userpassstr);
    if (saltfoo) utils->free(saltfoo);

    return result;
}
/*
 * Flatten an saved_info_t into bytes
 *
 * we need to save:
 * salt      
 * mpz_t verifier;
 *
 * store salt as series of bytes
 * verifier as netstring 
 *
 */

static sasl_secret_t *flatten_sinfo(savedinfo_t *sinfo, sasl_utils_t *utils)
{

    int result;
    int toalsize;
    netstring_t *ns1;
    sasl_secret_t *sec;
    int totalsize;

    ns1 = create_netstring_bigint(sinfo->verifier, utils);
    if (!ns1) return NULL;

    totalsize = sizeof(sinfo->salt) + ns1->size;

    sec=(sasl_secret_t *) utils->malloc(sizeof(sasl_secret_t)+
					totalsize+1);
    if (!sec) return NULL;

    memcpy(sec->data, sinfo->salt, sizeof(sinfo->salt));
    memcpy(sec->data+sizeof(sinfo->salt), ns1->data, ns1->size);

    sec->len = totalsize;

    return sec;
}

static int
setpass(void *glob_context __attribute__((unused)),
	sasl_server_params_t *sparams,
	const char *userstr,
	const char *pass,
	unsigned passlen,
	int flags __attribute__((unused)),
	const char **errstr)
{
    int userlen = strlen(userstr);
    
    int result;
    sasl_server_putsecret_t *putsecret;
    void *putsecret_context;
    char *user = NULL;
    char *realm = NULL;

    savedinfo_t sinfo;
    sasl_secret_t *sec = NULL;

    if (errstr) {
	*errstr = NULL;
    }

    result = parseuser(sparams->utils, &user, &realm, sparams->user_realm,
		       sparams->serverFQDN, userstr);
    if (result != SASL_OK) {
	return result;
    }

    if ((flags & SASL_SET_DISABLE) || pass == NULL) {
	sec = NULL;
    } else {
	mpz_t N, g, x;

	/* generate <salt> */    
	sparams->utils->rand(sparams->utils->rpool, sinfo.salt, sizeof(sinfo.salt));
    
	/* x = SHA( <salt> | SHA (... )) */
	result = calculate_x(sparams->utils,
			     user, userlen,
			     pass, passlen,
			     sinfo.salt, sizeof(sinfo.salt),
			     x);
	if (result!=SASL_OK) return result;

	result = generate_N_and_g(N, g);
	if (result!=SASL_OK) return result;

	/* calculate v = g^x % N */
	mpz_init(sinfo.verifier);
	mpz_powm(sinfo.verifier,g,x,N);


	/* flatten sinfo */
	sec = flatten_sinfo(&sinfo, sparams->utils);

	if (sec == NULL) {
	    result = SASL_NOMEM;
	    goto cleanup;
	}
    }

    /* get the callback for saving to the password db */
    result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_PUTSECRET,
					 &putsecret,
					 &putsecret_context);
    if (result != SASL_OK) {
	goto cleanup;
    }

    /* do the store */
    result = putsecret(putsecret_context,
		       "SRP", 
		       user,
		       realm,
		       sec);

    if (result != SASL_OK) {
	goto cleanup;
    }

    /* put entry in db to say we have at least one user */
    result = mechanism_fill_db("SRP", sparams);

    VL(("Setpass for SRP successful\n"));

 cleanup:
    if (sec) {
	memset(sec, 0, sizeof(sasl_secret_t) + sizeof(savedinfo_t));
	sparams->utils->free(sec);
    }

    if (user) 	sparams->utils->free(user);
    if (realm) 	sparams->utils->free(realm);
    return result;
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "SRP",		        /* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    NULL,			/* glob_context */
    &server_start,		/* mech_new */
    &server_continue_step,	/* mech_step */
    NULL,			/* mech_dispose */
    NULL,			/* mech_free */
    &setpass,			/* setpass */
    NULL,			/* user_query */
    NULL,			/* idle */
    NULL,			/* install_credentials */
    NULL,			/* uninstall_credentials */
    NULL			/* free_credentials */
  }
};

int sasl_server_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<SRP_VERSION)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=SRP_VERSION;

  return SASL_OK;
}

static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  if (!text)
    return;

  utils->free(text);
}

/* put in sasl_wrongmech */
static int
client_start(void *glob_context __attribute__((unused)),
	     sasl_client_params_t *params,
	     void **conn)
{
  context_t *text;

  if (! conn)
    return SASL_BADPARAM;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;

  memset(text, '\0', sizeof(context_t));
  text->state=0;  
  *conn=text;

  return SASL_OK;
}

/*
 * Create large random a
 * A = g^a % N
 *
 */

static netstring_t *create_public_client(mpz_t g, mpz_t N, mpz_t a, mpz_t A, 
					 sasl_utils_t *utils)
{
    mpz_init(a);
    mpz_init(A);

    /* xxx likely should use sasl random funcs */
    mpz_random(a,BITSFORab/(8*sizeof(int))); 

    /* A = g^a % N */
    mpz_powm (A, g, a, N);

    return create_netstring_bigint(A, utils);
}

/*
 * Create large random b
 * B = (v + g^b) % N
 *
 */

static int create_public_server(mpz_t g, mpz_t N, mpz_t v,
				mpz_t b, mpz_t B)
{
    mpz_init(b);
    mpz_init(B);

    /* xxx likely should use sasl random funcs */
    mpz_random(b,BITSFORab/(8*sizeof(int))); 

    /*  g^b % N */
    mpz_powm (B, g, b, N);

    /* v + (g^b%N)  */
    mpz_add (B, B, v);

    /* B = (v + g^b) % N */
    mpz_mod (B, B, N);

    return SASL_OK;
}

/* 
 * Trys to find the prompt with the lookingfor id in the prompt list
 * Returns it if found. NULL otherwise
 */

static sasl_interact_t *find_prompt(sasl_interact_t *promptlist,
				    unsigned int lookingfor)
{
  if (promptlist==NULL) return NULL;

  while (promptlist->id!=SASL_CB_LIST_END)
  {
    if (promptlist->id==lookingfor)
      return promptlist;

    promptlist++;
  }

  return NULL;
}

static int get_authid(sasl_client_params_t *params,
		      char **authid,
		      sasl_interact_t **prompt_need)
{

  int result;
  sasl_getsimple_t *getauth_cb;
  void *getauth_context;
  sasl_interact_t *prompt = NULL;
  const char *ptr;

  /* see if we were given the authname in the prompt */
  if (prompt_need) prompt = find_prompt(*prompt_need,SASL_CB_AUTHNAME);
  if (prompt!=NULL)
  {
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
  switch (result)
    {
    case SASL_INTERACT:
      return SASL_INTERACT;

    case SASL_OK:
      if (! getauth_cb)
	  return SASL_FAIL;
      result = getauth_cb(getauth_context,
			  SASL_CB_AUTHNAME,
			  (const char **)&ptr,
			  NULL);
      if (result != SASL_OK)
	  return result;

      *authid=params->utils->malloc(strlen(ptr)+1);
      if ((*authid)==NULL) return SASL_NOMEM;
      strcpy(*authid, ptr);
      break;

    default:
      break;
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
  sasl_interact_t *prompt = NULL;

  /* see if we were given the password in the prompt */
  if (prompt_need) prompt=find_prompt(*prompt_need,SASL_CB_PASS);
  if (prompt!=NULL)
  {
    /* We prompted, and got.*/
	
    if (! prompt->result)
      return SASL_FAIL;

    /* copy what we got into a secret_t */
    *password = (sasl_secret_t *) params->utils->malloc(sizeof(sasl_secret_t)+
						       prompt->len+1);
    if (! *password) return SASL_NOMEM;

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

  switch (result)
    {
    case SASL_INTERACT:      
      return SASL_INTERACT;
    case SASL_OK:
      if (! getpass_cb)
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

static void free_prompts(sasl_client_params_t *params,
			sasl_interact_t *prompts)
{
  sasl_interact_t *ptr=prompts;
  if (ptr==NULL) return;

  do
  {
    /* xxx might be freeing static memory. is this ok? */
    if (ptr->result!=NULL)
      params->utils->free(ptr->result);

    ptr++;
  } while(ptr->id!=SASL_CB_LIST_END);

  params->utils->free(prompts);
  prompts=NULL;
}

/*
 * Make the necessary prompts
 */

static int make_prompts(sasl_client_params_t *params,
			sasl_interact_t **prompts_res,
			int auth_res,
			int pass_res)
{
  int num=1;
  sasl_interact_t *prompts;

  if (auth_res==SASL_INTERACT) num++;
  if (pass_res==SASL_INTERACT) num++;

  if (num==1) return SASL_FAIL;

  prompts=params->utils->malloc(sizeof(sasl_interact_t)*num);
  if ((prompts) ==NULL) return SASL_NOMEM;
  *prompts_res=prompts;

  if (auth_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_AUTHNAME;
    (prompts)->challenge="Authorization Name";
    (prompts)->prompt="Please enter your authorization name";
    (prompts)->defresult=NULL;

    VL(("authid callback added\n"));
    prompts++;
  }

  if (pass_res==SASL_INTERACT)
  {
    /* We weren't able to get the callback; let's try a SASL_INTERACT */
    (prompts)->id=SASL_CB_PASS;
    (prompts)->challenge="Password";
    (prompts)->prompt="Please enter your password";
    (prompts)->defresult=NULL;

    VL(("password callback added\n"));
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
client_continue_step(void *conn_context,
		sasl_client_params_t *params,
		const char *serverin,
		int serverinlen,
		sasl_interact_t **prompt_need,
		char **clientout,
		int *clientoutlen,
		sasl_out_params_t *oparams)
{
  int result;
  context_t *text;
  text=conn_context;

  VL(("SRP client step %d\n",text->state));

  if (text->state == 0) {

      /* nothing. server makes first challenge */

      *clientout=params->utils->malloc(1);
      if (! (*clientout)) return SASL_NOMEM;
      (*clientout)[0]='\0';
      *clientoutlen = 0;

      VL(("Step one succeeded!\n"));
      text->state = 1;
      return SASL_CONTINUE;
  }

  if (text->state == 1) {

      netdata_t *nd1;
      netdata_t *nd2;
      netdata_t *nd3;

      netstring_t *ns1;
      netstring_t *ns2;
      netstring_t *ns3;

      int result;
      int auth_result=SASL_OK;
      int pass_result=SASL_OK;

      /* try to get the userid */
      if (text->authid==NULL)
      {
	  VL (("Trying to get authid\n"));
	  auth_result=get_authid(params,
				 &text->authid,
				 prompt_need);
	  
	  if ((auth_result!=SASL_OK) && (auth_result!=SASL_INTERACT))
	      return auth_result;	  
      }
      
      /* try to get the password */
      if (text->password==NULL)
      {
	  VL (("Trying to get password\n"));
	  pass_result=get_password(params,
				   &text->password,
				   prompt_need);
	  
	  if ((pass_result!=SASL_OK) && (pass_result!=SASL_INTERACT))
	      return pass_result;
      }

    
      /* free prompts we got */
      if (prompt_need) free_prompts(params,*prompt_need);

      /* if there are prompts not filled in */
      if ((auth_result==SASL_INTERACT) ||
	  (pass_result==SASL_INTERACT))
      {
	  /* make the prompt list */
	  int result=make_prompts(params,prompt_need,
				  auth_result, pass_result);
	  if (result!=SASL_OK) return result;
	  
	  VL(("returning prompt(s)\n"));
	  return SASL_INTERACT;
      }

      printf("authid = %s\n",text->authid);

      /* We received:
       *
       * N
       * g
       * Z - server options
       */
      result = split_netstrings(params->utils, &nd1,&nd2,&nd3, (char *) serverin, serverinlen);
      if (result!=SASL_OK) return result;

      printf("split worked\n");

      result = bigint_fromnetdata(nd1, params->utils, text->N);
      if (result!=SASL_OK) return result;

      result = bigint_fromnetdata(nd2, params->utils, text->g);
      if (result!=SASL_OK) return result;

      if (nd3->size!=1) {
	  VL(("Options is wrong size\n"));
	  return SASL_FAIL;
      }
      text->server_options = nd3->data[0];

      printf("got N and g\n");

      printf("client g: ");
      mpz_out_str (stdout, 10, text->g);
      printf("\n");

      printf("client N: ");
      mpz_out_str (stdout, 10, text->N);
      printf("\n");

      /* U  - authname
       * A  - public key
       * o  - options byte
       */
      ns1 = create_netstring_str(text->authid,strlen(text->authid), params->utils);

      ns2 = create_public_client(text->g,text->N, text->a, text->A, params->utils);

      printf("created public netstring\n");

      /* xxx client options */
      text->client_options = 0;

      /* create options */
      ns3 = create_netstring_str(&text->client_options,1, params->utils);

      merge_netstrings(params->utils, ns1,ns2,ns3,clientout,clientoutlen);

      text->state = 2;
      return SASL_CONTINUE;
  }
  if (text->state == 2) { /* client step 2 */
      netdata_t *nd1;
      netdata_t *nd2;
      netstring_t *ns1;
      netstring_t *tmpns;
      mpz_t exp;
      int lup;
      hash_t hashedB;
      unsigned int u;
      hash_t hashx;
      mpz_t x;

      /* We received 
       *
       * s - salt
       * B - server public key
       */

      result = split_netstrings(params->utils, &nd1,&nd2,NULL, (char *) serverin, serverinlen);
      if (result!=SASL_OK) return result;

      result = bigint_fromnetdata(nd2, params->utils, text->B);
      if (result!=SASL_OK) return result;

      printf("client B: ");
      mpz_out_str (stdout, 10, text->B);
      printf("\n");

      printf("foo\n");
      /* Calculate shared secret S */
      /* S = (B - g^x) ^ (a+u*x) %N */


      /* u is first 32 bits of B; MSB first */      
      Hash_bigint(text->B, &hashedB, params->utils);
      memcpy(&u, hashedB.data, 4);
      u = ntohl(u);      

      printf("client U = %d\n",u);

      /* generate x */
      result = calculate_x(params->utils,
			   text->authid, strlen(text->authid), 
			   text->password->data,text->password->len, 
			   nd1->data, nd1->size,
			   x);
      if (result!=SASL_OK) return result;

      /* exp = a+u*x */
      mpz_init(exp);
      mpz_mul_ui (exp, x, u);
      mpz_add(exp,exp,text->a);

      /* (tmp)S = B - g^x */
      mpz_init(text->S);
      mpz_powm (text->S, text->g, x, text->N);     
      printf("calculated g: ");
      mpz_out_str (stdout, 10, text->g);
      printf("\n");
      printf("calculated x: ");
      mpz_out_str (stdout, 10, x);
      printf("\n");
      printf("calculated N: ");
      mpz_out_str (stdout, 10, text->N);
      printf("\n");
       printf("calculated tmpS 1: ");
      mpz_out_str (stdout, 10, text->S);
      printf("\n");

      mpz_sub(text->S, text->B,text->S);

      printf("calculated tmpS: ");
      mpz_out_str (stdout, 10, text->S);
      printf("\n");

      /* S = tmpS^exp % N */
      mpz_powm(text->S, text->S, exp, text->N);

      printf("client calculated S: ");
      mpz_out_str (stdout, 10, text->S);
      printf("\n");

      result = SHA_Interleave(text->S, &text->sharedsecretK, params->utils);
      if (result!=SASL_OK) return result;

      /*
       * Give out:
       *  M1
       *
       */

      result = calculate_client_evidence(text->N, text->g,
					 nd1->data, nd1->size,
					 text->server_options,
					 text->A, text->B,
					 &text->sharedsecretK,
					 &(text->M1),
					 params->utils);
      if (result!=SASL_OK) return result;


      ns1 = create_netstring_str(text->M1.data, sizeof(text->M1.data), params->utils);
      if (ns1==NULL) return SASL_NOMEM;
      
      *clientout = params->utils->malloc(ns1->size+1);
      if (!*clientout) return SASL_NOMEM;
      memcpy(*clientout, ns1->data, ns1->size);
      *clientoutlen = ns1->size;
      

      text->state = 3;
      return SASL_CONTINUE;
  }

  if (text->state == 3) {

      unsigned char *M2in;
      int M2inlen;
      hash_t M2;
      int lup;
      
      /*
       * Retrieve M2 and verify it
       *
       */
      result = checkvalid_netstring((char *) serverin, serverinlen, (char *) &M2in, &M2inlen);
      if (result!=SASL_OK) return result;      

      /* Let's calculate M2 ourselves and see if it matches */
      result = calculate_server_evidence(text->authid,
					 text->A,
					 text->client_options,
					 &(text->M1),
					 &text->sharedsecretK,
					 &M2,
					 params->utils);
      if (result!=SASL_OK) return result;      
      
      for (lup=0;lup<HASHLEN;lup++)
      {
	  if (M2in[lup]!=M2.data[lup]) {
	      VL (("Server evidence failure\n"));
	      return SASL_FAIL;
	  }
      }

      *clientout = params->utils->malloc(1);
      if (!*clientout) return SASL_NOMEM;
      (*clientout)[0] = '\0';
      *clientoutlen = 0;

      text->state = 4;     
      return SASL_OK;
  }

  return SASL_FAIL;
}

static const long client_required_prompts[] = {
  SASL_CB_AUTHNAME,
  SASL_CB_LIST_END
};

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "SRP",	   	        /* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    client_required_prompts,	/* required_prompts */
    NULL,			/* glob_context */
    &client_start,		/* mech_new */
    &client_continue_step,	/* mech_step */
    &dispose,			/* mech_dispose */
    NULL,			/* mech_free */
    NULL,			/* auth_create */
    NULL			/* idle */
  }
};

int sasl_client_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion < SRP_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=SRP_VERSION;

  return SASL_OK;
}
