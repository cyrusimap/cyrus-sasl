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

typedef struct context_s {
    int state;

    mpz_t N;
    mpz_t g;

} context_t;



typedef struct hash_s {

    unsigned char data[SHA_DIGEST_LENGTH];
    int len;

} hash_t;

static int
server_start(void *glob_context __attribute__((unused)),
             sasl_server_params_t *sparams __attribute__((unused)),
	     const char *challenge __attribute__((unused)),
	     int challen __attribute__((unused)),
	     void **conn,
	     const char **errstr)
{
  /* holds state are in */
  if (!conn)
      return SASL_BADPARAM;
  
  *conn = NULL;
  if (errstr)
      *errstr = NULL;

  return SASL_OK;
}

typedef struct netstring_s {

    int size;
    
    char data[1]; /* allocate to size you need */

} netstring_t;

static netstring_t *create_netstring_bigint(mpz_t n, sasl_utils_t *utils)
{
    int size;
    int prefixlen;
    netstring_t *ret;

    size = mpz_sizeinbase (n, 16) + 2;

    ret = (netstring_t *) utils->malloc(sizeof(netstring_t)+20+size);

    sprintf(ret->data,"%d:",size);
    prefixlen = strlen(ret->data);
    memcpy(ret->data+prefixlen, n->???, size);    /* xxx */
    ret->data[prefixlen+size] = ',';
    ret->data[prefixlen+size+1] = '\0';

    ret->size = prefixlen+size+1;

    return ret;
}

/*
 * Create a netstring from a single character
 */

static netstring_t *create_netstring_char(char c, sasl_utils_t *utils)
{
    int prefixlen;
    netstring_t *ret;

    ret = (netstring_t *) utils->malloc(sizeof(netstring_t)+10);

    sprintf(ret->data,"1:%c,",c);
    ret->size = 4;

    return ret;
}

/* The probability of a
   false positive is (1/4)**REPS.  A reasonable value of reps is 25. */
#define REPS 25

/* A large safe prime (N = 2q+1, where q is prime) All arithmetic is done modulo N */
static mpz_t generate_N(void)
{
    mpz_t N;
    mpz_t q;

    mpz_init(N);
    mpz_init(q);

    do {

	do {
	    /* xxx */
	} while (mpz_probab_prime_p(try,REPS)!=1);

	/* N = 2q+1 */
	mpz_mul_ui( q, q, 2);
	mpz_add_ui( N, q, 1);

    } while (mpz_probab_prime_p(N,REPS)!=1);

    mpz_clear(q);

    return N;
}

static void merge_netstrings(netstring_t *ns1,netstring_t *ns2,netstring_t *ns3,
			     char **out, int *outlen)
{
    int totallen;

    /* calculate total length of strings */
    totallen = 0;
    if (ns1)
	totallen+=ns1->size;
    if (ns2)
	totallen+=ns2->size;
    if (ns3)
	totallex+=ns3->size;

    snprintf(lenstr,sizeof(lenstr),"%d:",totallen);
    
    *outlen = strlen(lenstr) + totallen + 1;
    *out = sparams->utils->malloc(*outlen);
    
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

static int checkvalid_netstring(char *in, int inlen, char **datastart, int **datalen)
{
    char lenstr[20];
    int pos = 0;
    
    /* see how big it says it is */
    while ((pos<inlen) && (pos < sizeof(lenstr)) && (isdigit((int) in[pos]))) {
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

    if (in[inlen]!=',') {
	VL(("Netstring missing required comma\n"));
	return SASL_FAIL;
    }

    *datastart = in+pos+1;

    return SASL_OK;
}

static int split_netstrings(sasl_utils_t *utils,
			    netstring_t **ns1, netstring_t **ns2, netstring_t **ns3,
			    char *in, int inlen)
{
    char *datastart, *ns_str;
    int datalen, ns_len;
    int result;

    result = checkvalid_netstring(in, inlen, &datastart, &datalen);
    if (result!=SASL_OK) return result;
    
    if (ns1) {
	result = checkvalid_netstring(datastart, datalen, &ns_str, &ns_len);
	if (result!=SASL_OK) return result;

	*ns1 = utils->malloc(sizeof(netstring_t)+ns_len);
	if (!*ns1) return SASL_NOMEM;

	(*ns1)->size = ns_len;
	memcpy((*ns1)->data, ns_str, ns_len);

	datastart = ns_str+ns_len+1;
    }

    if (ns2) {
	result = checkvalid_netstring(datastart, datalen, &ns_str, &ns_len);
	if (result!=SASL_OK) return result;

	*ns2 = utils->malloc(sizeof(netstring_t)+ns_len);
	if (!*ns2) return SASL_NOMEM;

	(*ns2)->size = ns_len;
	memcpy((*ns2)->data, ns_str, ns_len);

	datastart = ns_str+ns_len+1;
    }

    if (ns3) {
	result = checkvalid_netstring(datastart, datalen, &ns_str, &ns_len);
	if (result!=SASL_OK) return result;

	*ns3 = utils->malloc(sizeof(netstring_t)+ns_len);
	if (!*ns3) return SASL_NOMEM;

	(*ns3)->size = ns_len;
	memcpy((*ns3)->data, ns_str, ns_len);

	datastart = ns_str+ns_len+1;
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
  struct sockaddr_in *remote_addr;   
  char *clientdata;
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

  if (conn->state == 1) {
      netstring_t *ns1;
      netstring_t *ns2;
      netstring_t *ns3;

      /* Server sends N, g, and Z */

      /*
       * N   -  A large safe prime (N = 2q+1, where q is prime) All arithmetic is done modulo N 
       * g   -  generator
       */

       mpz_t N;
       mpz_t g;
       unsigned char Z = 0;

       /* generate n */
       N = generate_N();

       /* xxx generate g */
       mpz_init(g);
       mpz_set_ui(g,2);

       /* set Z */
       /* xxx everything off right now */
       Z = 0;
       
       ns1 = create_netstring_bigint(N);
       ns2 = create_netstring_bigint(g);
       ns3 = create_netstring_char(Z);

       /* put them all together */
       merge_netstrings(ns1,ns2,ns3, serverout, serveroutlen);

       conn->state = 2;

       return SASL_CONTINUE;
  }
  if (conn->state == 2) {
      netstring_t *ns1=NULL;
      netstring_t *ns2=NULL;
      netstring_t *ns3=NULL;
      int result;
      hash_t hashedB;

      /* We received:
       *
       * U - authname 
       * A - client's public key
       * o - options
       */

      result = split_netstrings(sparams->utils, &ns1,&ns2,&ns3, clientin, clientinlen);
      if (result!=SASL_OK) return result;

      text->authname = ns1;
      text->A = bigint_fromnetstring(ns2);

      /* xxx do something with options */
      
      /* We send:
       *
       * s - salt
       * B - server public key
       */

      ns1 = get_salt();
      ns2 = create_public(text->g,text->N);

      /* B = (v + g^b) %N
      B = create_public(text->g,text->N);

      /* u is first 32 bits of B; MSB first */
      Hash(B,len of B, &hashedB);
      memcpy(text->u, hashedB.data, 4);
      text->u = ntohl(text->u);


      /* calculate server shared secret */
      /* S = (A*v^u)^b %N */
      
      mpz_init(text->S);
      mpz_powm_ui (text->S, text->verifier, text->u, text->N);
      
      mpz_mul (text->S, text->S, text->A);

      mpz_powm (text->S, text->S, text->b, text->N);



      merge_netstrings(ns1,ns2,NULL,serverout,serveroutlen);

      text->state = 3;

      return SASL_CONTINUE;
  }

  return SASL_FAIL;
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
    NULL,			/* setpass */
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
  if (maxversion<ANONYMOUS_VERSION)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=ANONYMOUS_VERSION;

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
	sasl_client_params_t *params __attribute__((unused)),
	void **conn)
{
  context_t *text;

  if (! conn)
    return SASL_BADPARAM;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;  
  *conn=text;

  return SASL_OK;
}

/*
 * A 'limb' is the amount that fits in a word
 * on the particular architecture
 */
#define MAXLIMBS 100

/*
 * Create large random a
 * A = g^a % N
 *
 */

static netstring_t *create_public(mpz_t g, mpz_t N)
{
    mpz_t a;
    mpz_t A;

    mpz_init(a);
    mpz_init(A);

    /* xxx likely should use sasl random funcs */
    mpz_random(a,MAXLIMBS);

    /* xxx save 'a' somewhere */

    /* A = g^a % N */    
    mpz_powm (A, g, a, N);

    return create_netstring_bigint(A);
}

/*
 * Preform a Sha1 hash
 */

#define SHA_A 0x67452301
#define SHA_B 0xefcdab89
#define SHA_C 0x98badcfe
#define SHA_D 0x10325476
#define SHA_E 0xc3d2e1f0

static void Hash(char *data, int len, hash_t hash)
{
    char block[512/8];
    unsigned int a,b,c,d,e;
    /* pad msg */

    
    /* */
    a = SHA_A;
    b = SHA_B;
    c = SHA_C;
    d = SHA_D;
    e = SHA_E;
    
    for (round = 0;round < 4;lup++)
    {       
	if (round == 0) Kt = 0x5a827999;
	if (round == 1) Kt = 0x6ed9eba1;	
	if (round == 2) Kt = 0x8f1bbcdc;
	if (round == 3) Kt = 0xca62c1d6;

	for (op=0;lup<op<20;lup++)
	{
	    int temp = left_circle_shift(a,5);
	    
	    switch(round) {
	    case 0: temp+=shafunc1(b,c,d);
		break;
	    case 1:
		break;
	    case 2:
		break;
	    case 3:
		break;
	    }

	    temp+=e;
	    
	    if ((round == 0) && (op <=15)) {
		W = 
	    } else {

	    }

	    e = d;
	    d = c;
	    c = b <<< 30;
	    a = temp;
	}
    }
	    
}

static void Hash(unsigned char *data, unsigned long len, hash_t *hash)
{
    SHA_CTX c;

    SHA1_Init(&c);

    SHA1_Update(&c,data,len);

    SHA1_Final(&(hash->data[0]),&c);
    
    hash->len = SHA_DIGEST_LENGTH;
}

static int
client_continue_step(void *conn_context,
		sasl_client_params_t *params,
		const char *serverin __attribute__((unused)),
		int serverinlen,
		sasl_interact_t **prompt_need,
		char **clientout,
		int *clientoutlen,
		sasl_out_params_t *oparams)
{
  int result;
  unsigned userlen;
  char hostname[256];
  sasl_getsimple_t *getuser_cb;
  void *getuser_context;
  const char *user = NULL;
  context_t *text;
  text=conn_context;

  if (text->state == 1) {

      /* We received:
       *
       * N
       * g
       * Z
       */

      


      /* U  - authname
       * A  - public key
       * o  - options byte
       */

      netstring_t *ns1;
      netstring_t *ns2;
      netstring_t *ns3;

      unsigned char o = 0;
      char *authname = "tmartin"; /* xxx */

      ns1 = create_netstring_str(params->utils,authname);
      
      ns2 = create_public(text->g,text->N);

      /* create options */
      ns3 = create_netstring_char(o);

      merger_netstrings(ns1,ns2,ns3,clientout,clientoutlen);

      text->state = 2;
      return SASL_CONTINUE;
  }
  if (text->state == 2) {

      /* Client calculate evidence M1
	 M1 = H(H(N) XOR H(g) | s | Z | A | B | K)
      */
      
      Hn = Hash(text->N);
      Hg = Hash(text->g);

      /* Hn XOR Hg */
      for (lup=0;lup<HASHLEN;lup++)
	  Hn[lup]=Hn[lup]^Hg[lup];

      char concatstr[HASHLEN+MAXBIGNUMLEN+1+MAXBIGNUMLEN+MAXBIGNUMLEN+HASHLEN*2];

      

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
  if (maxversion < ANONYMOUS_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=ANONYMOUS_VERSION;

  return SASL_OK;
}
