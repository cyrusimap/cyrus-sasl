/* Digest MD5 SASL plugin
 * Tim Martin, Alexey Melnikov 
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#ifdef WIN32
#include "winconfig.h"
#endif /* WIN32 */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sasl.h>
#include <saslplug.h>  
#include <saslutil.h>

#define NONCE_SIZE (32)          /* arbitrary */

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslDIGESTMD5.h"
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL "
VERSION " $";

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

#ifdef sun
/* gotta define gethostname ourselves on suns */
extern int gethostname(char *, int);
#endif

#define bool int
#define false 0
#define true  1


/*#define DEBUGON 1*/
#define DEBUGPRINT(x) printf("DEBUG: %s\n", x);
#include <assert.h>

/* xxx */
static char *charset="utf-8";

/*Forward declarations:*/
static char *calculate_response(sasl_utils_t *utils,
							  
							  char *username,
							  char *realm,
							  char *nonce, 
							  char *ncvalue,
							  char *cnonce,
							  char *qop,
							  char *digesturi,
                              char *passwd);

static int htoi(unsigned char *hexin, int *res);
static char *convert16(unsigned char *in,int inlen,sasl_utils_t *utils);

#define DIGESTMD5_VERSION (3)
#define KEYS_FILE NULL

typedef struct context {
  int state;

  /*sasl_malloc_t *malloc;
    //sasl_free_t *free;*/

  char *nonce;
  int   noncelen;

  int   last_ncvalue;

} context_t;

#define HASHLEN 16
typedef char HASH[HASHLEN];
#define HASHHEXLEN 32
typedef char HASHHEX[HASHHEXLEN+1];

#define IN
#define OUT
							  
void CvtHex(
    IN HASH Bin,
    OUT HASHHEX Hex
    )
{
    unsigned short i;
    unsigned char j;

    for (i = 0; i < HASHLEN; i++) {
        j = (Bin[i] >> 4) & 0xf;
        if (j <= 9)
            Hex[i*2] = (j + '0');
         else
            Hex[i*2] = (j + 'a' - 10);
        j = Bin[i] & 0xf;
        if (j <= 9)
            Hex[i*2+1] = (j + '0');
         else
            Hex[i*2+1] = (j + 'a' - 10);
    }
    Hex[HASHHEXLEN] = '\0';
}


void DigestCalcSecret(
	IN sasl_utils_t *utils,			    
    IN char * pszUserName,
    IN char * pszRealm,
    IN char * pszPassword,
    OUT HASH HA1)
{
      MD5_CTX Md5Ctx;
      
      utils->MD5Init(&Md5Ctx);
      utils->MD5Update(&Md5Ctx, pszUserName, strlen(pszUserName));
      utils->MD5Update(&Md5Ctx, ":", 1);
      utils->MD5Update(&Md5Ctx, pszRealm, strlen(pszRealm));
      utils->MD5Update(&Md5Ctx, ":", 1);
      utils->MD5Update(&Md5Ctx, pszPassword, strlen(pszPassword));
      utils->MD5Final(HA1, &Md5Ctx);
};


/* calculate H(A1) as per spec */
void DigestCalcHA1(
	IN sasl_utils_t *utils,			    
    IN char * pszUserName,
    IN char * pszRealm,
    IN char * pszPassword,
    IN char * pszNonce,
    IN char * pszCNonce,
    OUT HASHHEX SessionKey
    )
{
      MD5_CTX Md5Ctx;
      HASH HA1;

      DigestCalcSecret(
		  utils,			    
          pszUserName,
          pszRealm,
          pszPassword,
		  HA1);

#ifdef DEBUGON
	   //Debug only:
      CvtHex(HA1, SessionKey);
      printf ("HA1 is \"%s\"\r\n", SessionKey);
#endif
 

      utils->MD5Init(&Md5Ctx);
      utils->MD5Update(&Md5Ctx, HA1, HASHLEN);
      utils->MD5Update(&Md5Ctx, ":", 1);
      utils->MD5Update(&Md5Ctx, pszNonce, strlen(pszNonce));
      utils->MD5Update(&Md5Ctx, ":", 1);
      utils->MD5Update(&Md5Ctx, pszCNonce, strlen(pszCNonce));
      utils->MD5Final(HA1, &Md5Ctx);

      CvtHex(HA1, SessionKey);
};

/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse(
    IN sasl_utils_t *utils,
    IN HASHHEX HA1,           /* H(A1) */
    IN char * pszNonce,       /* nonce from server */
    IN char * pszNonceCount,  /* 8 hex digits */
    IN char * pszCNonce,      /* client nonce */
    IN char * pszQop,         /* qop-value: "", "auth", "auth-int" */
    IN char * pszDigestUri,   /* requested URL */
    IN HASHHEX HEntity,       /* H(entity body) if qop="auth-int" */
    OUT HASHHEX Response      /* request-digest or response-digest */
    )
{
      MD5_CTX Md5Ctx;
      HASH HA2;
      HASH RespHash;
       HASHHEX HA2Hex;

       /* calculate H(A2)*/
      utils->MD5Init(&Md5Ctx);
	  utils->MD5Update(&Md5Ctx, "AUTHENTICATE:", 13);
      utils->MD5Update(&Md5Ctx, pszDigestUri, strlen(pszDigestUri));
      if (strcasecmp(pszQop, "auth-int") == 0) {
            utils->MD5Update(&Md5Ctx, ":", 1);
            utils->MD5Update(&Md5Ctx, HEntity, HASHHEXLEN);
      };
      utils->MD5Final(HA2, &Md5Ctx);
       CvtHex(HA2, HA2Hex);

       /* calculate response*/
      utils->MD5Init(&Md5Ctx);
      utils->MD5Update(&Md5Ctx, HA1, HASHHEXLEN);
      utils->MD5Update(&Md5Ctx, ":", 1);
      utils->MD5Update(&Md5Ctx, pszNonce, strlen(pszNonce));
      utils->MD5Update(&Md5Ctx, ":", 1);
      if (*pszQop) {
          utils->MD5Update(&Md5Ctx, pszNonceCount, strlen(pszNonceCount));
          utils->MD5Update(&Md5Ctx, ":", 1);
          utils->MD5Update(&Md5Ctx, pszCNonce, strlen(pszCNonce));
          utils->MD5Update(&Md5Ctx, ":", 1);
          utils->MD5Update(&Md5Ctx, pszQop, strlen(pszQop));
          utils->MD5Update(&Md5Ctx, ":", 1);
      }
      utils->MD5Update(&Md5Ctx, HA2Hex, HASHHEXLEN);
      utils->MD5Final(RespHash, &Md5Ctx);
      CvtHex(RespHash, Response);
}


static char *calculate_response(sasl_utils_t *utils,
							  
							  char *username,
							  char *realm,

							  char *nonce, 
							  char *ncvalue,
							  char *cnonce,
							  char *qop,
							  char *digesturi,

                              char *passwd)
{
  HASHHEX SessionKey;
  HASHHEX HEntity = "00000000000000000000000000000000";
  HASHHEX Response;
  char    *result;

  /*Verifing that all parameters was defined*/
  assert (username!=NULL);
  assert (realm!=NULL);
  assert (nonce!=NULL);
  assert (cnonce!=NULL);

  assert (ncvalue!=NULL);
  assert (digesturi!=NULL);

  assert (passwd!=NULL);

  if (qop==NULL) 
	  qop = "auth";

   DEBUGPRINT ("calculate_response assert passed\n")

 DigestCalcHA1(
    utils,
    username,
    realm,
    passwd,
    nonce,
    cnonce,
    SessionKey
    );

   /*printf ("Session Key is \"%s\"\r\n", SessionKey);*/

 DigestCalcResponse(
    utils,
    SessionKey,               /* H(A1)*/
    nonce,             /* nonce from server*/
    ncvalue,        /* 8 hex digits */
    cnonce,            /* client nonce */
    qop,               /* qop-value: "", "auth", "auth-int" */

    digesturi,         /* requested URL*/

    HEntity,                  /* H(entity body) if qop="auth-int"*/
    Response                  /* request-digest or response-digest*/
    );

  result = utils->malloc(HASHHEXLEN+1);
  memcpy (result, Response, HASHHEXLEN);
  result[HASHHEXLEN] = 0;

  return result;
}

void DigestCalcHA1FromSecret(
	IN sasl_utils_t *utils,
        IN HASH HA1,
        IN char * pszNonce,
        IN char * pszCNonce,
        OUT HASHHEX SessionKey)
{
      MD5_CTX Md5Ctx;
      
#ifdef DEBUGON
      /*Debug only:*/
      CvtHex(HA1, SessionKey);
      printf ("HA1 is \"%s\"\r\n", SessionKey);
#endif

      utils->MD5Init(&Md5Ctx);
      utils->MD5Update(&Md5Ctx, HA1, HASHLEN);
      utils->MD5Update(&Md5Ctx, ":", 1);
      utils->MD5Update(&Md5Ctx, pszNonce, strlen(pszNonce));
      utils->MD5Update(&Md5Ctx, ":", 1);
      utils->MD5Update(&Md5Ctx, pszCNonce, strlen(pszCNonce));
      utils->MD5Final(HA1, &Md5Ctx);

      CvtHex(HA1, SessionKey);
};

static char *create_response(sasl_utils_t *utils,
							  char *username,
							  char *realm,
							  char *nonce, 
							  char *ncvalue,
							  char *cnonce,
							  char *qop,
							  char *digesturi,
                              HASH  Secret)
{
  HASHHEX SessionKey;
  HASHHEX HEntity = "00000000000000000000000000000000";
  HASHHEX Response;
  char    *result;

  if (qop==NULL) 
    qop = "auth";

  DigestCalcHA1FromSecret(
    utils,
    Secret,
    nonce,
    cnonce,
    SessionKey);


  /*printf ("Session Key is \"%s\"\r\n", SessionKey);*/


  DigestCalcResponse(
    utils,
    SessionKey,               /* H(A1)*/
    nonce,             /* nonce from server*/
    ncvalue,        /* 8 hex digits*/
    cnonce,            /* client nonce*/
    qop,               /* qop-value: "", "auth", "auth-int"*/
    digesturi,         /* requested URL*/
    HEntity,                  /* H(entity body) if qop="auth-int"*/
    Response                  /* request-digest or response-digest*/
    );

  result = utils->malloc(HASHHEXLEN+1);
  memcpy (result, Response, HASHHEXLEN);
  result[HASHHEXLEN] = 0;

  return result;
}



static char * create_nonce(sasl_utils_t *utils)
{
  char *base64buf;
  int   base64len;

  char *ret=(char *) utils->malloc(NONCE_SIZE);
  if (ret==NULL)
    return NULL;

  sasl_rand(utils->rpool,(char *) ret, NONCE_SIZE);

  /* base 64 encode it so it has valid chars */
  base64len = (NONCE_SIZE * 4 / 3) + (NONCE_SIZE % 3 ? 4 : 0);

  base64buf = (char *) utils->malloc( base64len + 1);
  if (base64buf == NULL) {
    /*fprintf(stderr, "ERROR: Unable to allocate final buffer\n");*/
    return(NULL);
  }

/* 
 * Returns SASL_OK on success, SASL_BUFOVER if result won't fit
 */
  if (sasl_encode64(ret, NONCE_SIZE,
	                base64buf, base64len, NULL) != SASL_OK)
  {
   utils->free(ret);
   return NULL;
  }

  utils->free(ret);

   DEBUGPRINT ("nonce created")

  return base64buf;
}

static int add_to_challenge(sasl_utils_t *utils, 
							char **str, 
							char *name,
							char *value,
							bool need_quotes)
{
  int namesize=strlen(name);
  int valuesize=strlen(value);

  if (*str==NULL)
  {
    *str=utils->malloc(namesize+2+valuesize+2);
    if (*str==NULL) return SASL_FAIL;
    *str[0]=0;
  } else {
    int curlen=strlen(*str);
    *str=utils->realloc(*str, curlen+1+namesize+2+valuesize+2);
    if (*str==NULL) return SASL_FAIL;
    strcat(*str, ",");
  }

  strcat(*str, name);

  if (need_quotes)
  {
    strcat(*str, "=\"");
    strcat(*str, value); /*XXX. What about quoting???*/
    strcat(*str,"\"");
  }
  else
  {
    strcat(*str, "=");
    strcat(*str, value);
  }

  return SASL_OK;
}


char *strend (char *s)
{
	if (s==NULL) return NULL;

	return (s+strlen(s));
}

void get_pair(char **in, char **name, char **value)
{
  char  *endvalue;
  char  *endpair;
  char  *curp = *in;
  *name = NULL;
  *value = NULL;

  if (curp == NULL) return;
  if (curp[0] == '\0') return;

  /*skipping spaces:*/
  while (curp[0]==' ')
    curp++;
  
  *name = curp;
  
  *value = strchr (*name, '=');
  (*value)[0] = '\0';
  (*value)++;

  if (**value == '"')
  {
    (*value)++;
    endvalue = strchr (*value, '"');
    endvalue[0] = '\0';
	endvalue++;
  }
  else
  {
    endvalue=*value;
  }

  endpair = strchr (endvalue, ',');
  if (endpair == NULL)
  {
	  endpair = strend(endvalue);
  }
  else
  {
      endpair[0] = '\0';
      endpair++; /*skipping <,>*/
  }

  *in = endpair;
}


int _sasl_plugin_strdup(sasl_utils_t *utils, const char *in, char **out, int *outlen)
{
  size_t len = strlen(in);
  if (outlen) *outlen = len;
  *out=utils->malloc(len + 1);
  if (! *out) return SASL_NOMEM;
  strcpy((char *) *out, in);
  return SASL_OK;
};





static int privacy_encode(void *context, const char *input, unsigned inputlen,
			  char **output, unsigned *outputlen)
{

  return SASL_FAIL;
}


static int privacy_decode(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen)
{
  /* not implemented */
    return SASL_FAIL;
}



static int integrity_encode(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen)
{
  return SASL_OK;
}

static int integrity_decode(void *context, 
							const char *input, unsigned inputlen,
							char **output, unsigned *outputlen)
{
    return SASL_OK;
};


static int server_start(void *glob_context __attribute__((unused)),
		 sasl_server_params_t *sparams,
		 const char *challenge __attribute__((unused)),
		 int challen __attribute__((unused)),
		 void **conn,
		 const char **errstr)
{
  context_t *text;

  if (errstr)
    *errstr = NULL;

  /* holds state are in */
  text= sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  /*text->malloc = sparams->utils->malloc;
    //text->free = sparams->utils->free;*/
  text->state=1;
  
  *conn=text;

  return SASL_OK;
}

static void dispose(void *conn_context, sasl_utils_t *utils)
{

  utils->free(conn_context);
}

static void mech_free(void *global_context, sasl_utils_t *utils)
{

  utils->free(global_context);  
}

static int server_continue_step (void *conn_context,
	      sasl_server_params_t *sparams,
	      const char *clientin,
	      int clientinlen,
	      char **serverout,
	      int *serveroutlen,
	      sasl_out_params_t *oparams,
	      const char **errstr)
{

  context_t *text;
  text=conn_context;

  if (errstr)
    *errstr = NULL;

  if (text->state==1)
  {
    char *challenge=NULL;
    char *realm;
    char *nonce;
    char *qop="auth";
    char *charset="utf-8";
	char *algorithm="md5-sess";
    
	/* digest-challenge  = 1#( realm | nonce | qop-options | stale |
                        maxbuf | charset | cipher-opts | auth-param ) */

    /* get realm */
    sparams->utils->getprop(sparams->utils->conn, SASL_REALM /*SASL_USERNAME ???*/,
         (void **)&realm);
    if (!realm)
    {
      /*printf("must get realm some other way\n");*/
      return SASL_FAIL;
    }

    /* add to challenge */
    if (add_to_challenge(sparams->utils, &challenge,"realm", realm, true)!=SASL_OK)
      return SASL_FAIL;
        
    /* get nonce XXX have to clean up after self if fail */
    nonce=create_nonce(sparams->utils);
    if (nonce==NULL)
      return SASL_FAIL;

    /* add to challenge */
    if (add_to_challenge(sparams->utils, &challenge,"nonce", nonce, true)!=SASL_OK)
      return SASL_FAIL;

    /*
    qop-options
     A quoted string of one or more tokens indicating the "quality of
     protection" values supported by the server.  The value "auth"
     indicates authentication; the value "auth-int" indicates
     authentication with integrity protection; the value "auth-conf"
     indicates authentication with integrity protection and encryption.
    */
    /* XXX add integrity? */
    /*qop="auth";*/ 

    /* add qop to challenge */
    if (add_to_challenge(sparams->utils, &challenge,"qop", qop, true)!=SASL_OK)
      return SASL_FAIL;

	/* "stale" not used in initial authentication */

    /*
     maxbuf
      A number indicating the size of the largest buffer the server is able
      to receive when using "auth-int". If this directive is missing, the
      default value is 65536. This directive may appear at most once; if
      multiple instances are present, the client should abort the
      authentication exchange.
	*/
	
     
    /*charset="utf-8";*/
    if (add_to_challenge(sparams->utils, &challenge,"charset", charset, true)!=SASL_OK)
      return SASL_FAIL;

    /*if (add_to_challenge(sparams->utils, &challenge,"algorithm", algorithm, true)!=SASL_OK)
      //  return SASL_FAIL;*/


	/*The size of a digest-challenge MUST be less than 2048 bytes.!!!*/

	*serverout = challenge;
    *serveroutlen=strlen(*serverout);

	text->noncelen = strlen(nonce);
	/*text->nonce=sparams->utils->malloc(text->noncelen+1);
    //if (text->nonce==NULL) return SASL_NOMEM;
    //memcpy(text->nonce, nonce, text->noncelen);*/
	text->nonce = nonce;

	text->last_ncvalue = 0; /*Next must be "nc=00000001"*/

    text->state=2;

    /* sparams->utils->free(realm); //Not malloc'ated!!! No free(...)!!!

       //sparams->utils->free(nonce); Nonce is saved!!! Do not free it!!! */

    return SASL_CONTINUE;
  };


  if (text->state==2)
  {
    /* verify digest*/
    char *userid = NULL;
    sasl_secret_t *sec;
    int len=sizeof(MD5_CTX);
    int result;
    sasl_server_getsecret_t *getsecret;
    void *getsecret_context;

	char *serverresponse = NULL;

	char *username = NULL;
	char *realm = NULL;
    char *nonce = NULL;
    char *cnonce = NULL;

	char *ncvalue = NULL;
	int   noncecount;
							      
	char *qop = NULL;
    char *digesturi = NULL;
	char *response = NULL;

	char *maxbufstr = NULL;

	/*int   maxbuf;*/


    char *charset = NULL;
	char *cipher = NULL;
                                  
    HASH     A1;

	int usernamelen;
	int realm_len;

    char *xxx;
	char *divaddr, *prevaddr;

	/* can we mess with clientin? copy it to be safe
	   //  char *in=clientin; //???*/
	char *in_start;
	char *in=sparams->utils->malloc(clientinlen+1);

	/*printf ("in allocated - %d bytes\r\n",clientinlen+1);*/

    memcpy(in, clientin, clientinlen);
	in[clientinlen] = 0;

    in_start = in;

    /*printf ("Server data is \"%s\"\r\n", in);*/

    /* parse what we got */
    while (in[0]!='\0')
    {
      char *name, *value;
      get_pair(&in, &name, &value);

      VL(("received form client pair: %s - %s\n",name,value));
      
	/* Extracting parameters */

	/*
     digest-response  = 1#( username | realm | nonce | cnonce |
                       nonce-count | qop | digest-uri | response |
                       maxbuf | charset | cipher | auth-param )
	*/
    /*digest-uri-value  = serv-type "/" host [ "/" serv-name ]
    serv-type        = 1*ALPHA
    host             = 1*( ALPHA | DIGIT | "-" | "." )
    service          = host*/

       DEBUGPRINT ("server_start step 2 : received pair: \t");
       DEBUGPRINT (name);
       DEBUGPRINT (":");
       DEBUGPRINT (value);
       DEBUGPRINT ("\n");

      if (strcmp(name,"username")==0) {

		  _sasl_plugin_strdup(sparams->utils, value, &username, NULL);

	  } else if (strcmp(name,"cnonce")==0) {

		  _sasl_plugin_strdup(sparams->utils, value, &cnonce, NULL);

	  } else if (strcmp(name,"nc")==0) {

	      if (htoi(value, &noncecount)!=SASL_OK)
		  {
           result = SASL_BADAUTH;
           goto FreeAllMem;
		  }

		  _sasl_plugin_strdup(sparams->utils, value, &ncvalue, NULL);

	  } else if (strcmp(name,"realm")==0) {

		  _sasl_plugin_strdup(sparams->utils, value, &realm, NULL);

      } else if (strcmp(name,"nonce")==0) {


	if (strcmp(value, text->nonce)!=0) /*Nonce changed: Abort authentication!!!*/
		  {
           result = SASL_BADAUTH;
           goto FreeAllMem;
		  }


      } else if (strcmp(name,"qop")==0) {

          
		  /* slen = strlen(value);
		  qop = sparams->utils->malloc(slen+1+1);
		  strcpy (qop, value);

		  qop[slen] = ',';
		  qop[slen+1] = '\0'; */

		  xxx = strend(value);
		  divaddr = value - 1;

		  do
		  {
   		    prevaddr = divaddr + 1;
		    divaddr = strchr (prevaddr, ',');
		    if (divaddr == NULL) 
		     divaddr = strend(value);

		    if (strnicmp( value,"auth", MIN(4, divaddr-prevaddr) )!=0) /*Other types are not yet supported!!!*/
			{
             result = SASL_BADAUTH;
             goto FreeAllMem;
			}

		  }
		  while (divaddr < xxx);

		  _sasl_plugin_strdup(sparams->utils, value, &qop, NULL);


      } else if (strcmp(name,"digest-uri")==0) {

	/*XXX: verify digest-uri format*/
	/*digest-uri-value  = serv-type "/" host [ "/" serv-name ]*/
		  _sasl_plugin_strdup(sparams->utils, value, &digesturi, NULL);

      } else if (strcmp(name,"response")==0) {

		  _sasl_plugin_strdup(sparams->utils, value, &response, NULL);

      } else if (strcmp(name,"cipher")==0) {

		  _sasl_plugin_strdup(sparams->utils, value, &cipher, NULL);

      } else if (strcmp(name,"maxbuf")==0) {

		  _sasl_plugin_strdup(sparams->utils, value, &maxbufstr, NULL);
		  /*maxbuf = XXX;*/

      } else if (strcmp(name,"charset")==0) {

		  _sasl_plugin_strdup(sparams->utils, value, &charset, NULL);

      } else {
        VL (("unrecognized pair: ignoring\n"));
      }
      
    }

	/*
    username         = "username" "=" <"> username-value <">
    username-value   = qdstr-val
    cnonce           = "cnonce" "=" <"> cnonce-value <">
    cnonce-value     = qdstr-val
    nonce-count      = "nc" "=" nc-value
    nc-value         = 8LHEX
    qop              = "qop" "=" qop-value
    digest-uri       = "digest-uri" "=" digest-uri-value
    digest-uri-value  = serv-type "/" host [ "/" serv-name ]
    serv-type        = 1*ALPHA
    host             = 1*( ALPHA | DIGIT | "-" | "." )
    service          = host
    response         = "response" "=" <"> response-value <">
    response-value   = 32LHEX
    LHEX       = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" |
                 "8" | "9" | "a" | "b" | "c" | "d" | "e" | "f"
    cipher = "cipher" "=" cipher-value
	*/


    /*Verifing that all parameters was defined*/
	if ( (username==NULL) || 
		 (realm==NULL) || 
	     /*(nonce==NULL) ||  */
	     (ncvalue==NULL) || 
	     (cnonce==NULL) || 
	     (digesturi==NULL) || 
	     (response==NULL) )
	{
	  result = SASL_BADAUTH; /*Not enough parameters!!!*/
        goto FreeAllMem;
	}

    if (qop==NULL) 
	  qop = "auth";

	usernamelen = strlen(username);
	realm_len = strlen(realm);

	userid=sparams->utils->malloc(usernamelen+1+realm_len+1);
    if (userid==NULL) 
	{
        result = SASL_NOMEM;
        goto FreeAllMem;
	}


    memcpy(userid, username, usernamelen);
    userid[usernamelen] = (char) ':'; /*'\0'; ???*/
 
    memcpy(userid + usernamelen + 1, realm, realm_len);
    userid[usernamelen+realm_len+1] = '\0';

       
	  DEBUGPRINT ("userid constructed");
	  DEBUGPRINT (userid);
    

    result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_GETSECRET,
					 /*&getsecret,*/
					 (int (**)()) &getsecret, /*???*/
					 &getsecret_context);
    if (result != SASL_OK)
      goto FreeAllMem;

	  DEBUGPRINT ("getsecret address obtained");
	  /*printf ("Address : %p\r\n", (void *)getsecret); */

    if (! getsecret)
	{
      result = SASL_FAIL;
      goto FreeAllMem;
	}

    /* We use the user's DIGEST secret*/

    result = getsecret(getsecret_context, "DIGEST-MD5", userid /* not username!!! */, &sec);
    if (result != SASL_OK)
      goto FreeAllMem;

    if (!sec)
	{
      result = SASL_FAIL;
      goto FreeAllMem;
	}

	  DEBUGPRINT ("getsecret called");

	  /*Verifying response obtained from client
	//
    //H_URP = H( { username-value, ":", realm-value, ":", passwd } )
    //sec->data contains H_URP */

	    if (sec->len != HASHLEN) /*Verifying that we really store A1 in our authentication database*/
	{
	  result = SASL_FAIL; 
      goto FreeAllMem;
	}

/*
//
//   A1       = { H( { username-value, ":", realm-value, ":", passwd } ),
//                  ":", nonce-value, ":", cnonce-value }
//
*/
	
	  DEBUGPRINT ("copying data from secret");

    memcpy(A1, sec->data, HASHLEN);
    A1[HASHLEN] = '\0';

	  DEBUGPRINT ("A1 is");
	  DEBUGPRINT (A1);

	  DEBUGPRINT ("Before Create Response");

    serverresponse = create_response(sparams->utils,
	                                 username,
									 realm,
									 text->nonce,
									 ncvalue,
									 cnonce,
									 qop,
									 digesturi,
									 A1);


    /*memcpy(ver_i.state,sec->data+8 , len);
    //memcpy(ver_o.state,sec->data+len+8, len); 
    //sparams->utils->free(sec);*/

       DEBUGPRINT ("server response created");

    if (serverresponse==NULL) 
	{
      result = SASL_NOMEM;
      goto FreeAllMem;
	};

       DEBUGPRINT ("before free secret");

       sasl_free_secret(&sec); /*sparams->utils->free(sec);???*/

       DEBUGPRINT ("after free secret");

       /* if ok verified*/
    if (strcmp(serverresponse,response)!=0)
    {
      result = SASL_BADAUTH;

       DEBUGPRINT ("Client Sent:");
       DEBUGPRINT (response);
       DEBUGPRINT ("Server calculated");
       DEBUGPRINT (serverresponse);

	  /* XXX stuff for reauth */

      goto FreeAllMem;
	};

    /* nothing more to do; authenticated 
    // set oparams information
    //*/
    oparams->doneflag=1;

    oparams->mech_ssf=0; /*1 - only integrity support*/

    oparams->maxoutbuf=1024; /* no clue what this should be*/
  
    oparams->encode=NULL;
    oparams->decode=NULL;


	if (_sasl_plugin_strdup(sparams->utils, realm, &oparams->realm, NULL)==SASL_NOMEM)
	{
      result = SASL_NOMEM;
      goto FreeAllMem;
	}

	if (_sasl_plugin_strdup(sparams->utils, username, &oparams->user, NULL)==SASL_NOMEM)
	{
	  sparams->utils->free (oparams->realm);
	  oparams->realm = NULL;
      result = SASL_NOMEM;
      goto FreeAllMem;
	}

	if (_sasl_plugin_strdup(sparams->utils, username, &oparams->authid, NULL)==SASL_NOMEM)
	{
	  sparams->utils->free (oparams->realm);
	  oparams->realm = NULL;
	  sparams->utils->free (oparams->user);
	  oparams->user = NULL;
      result = SASL_NOMEM;
      goto FreeAllMem;
	}

	sasl_setprop(conn_context, SASL_USERNAME, oparams->user); /*Test-Server.C use this!!!*/

    oparams->param_version=0;

    *serverout = NULL;
    *serveroutlen = 0;

	result = SASL_OK;

FreeAllMem:
    
       DEBUGPRINT ("Before FreeAllMem");


	sparams->utils->free (in_start);

	sparams->utils->free (username); 
	sparams->utils->free (realm);
	/*sparams->utils->free (nonce);*/
    sparams->utils->free (cnonce);
	sparams->utils->free (ncvalue);
	sparams->utils->free (qop);
    sparams->utils->free (digesturi);
	sparams->utils->free (response);
	sparams->utils->free (maxbufstr);
    sparams->utils->free (charset);
	sparams->utils->free (cipher);

	sparams->utils->free(userid);

	sparams->utils->free(serverresponse);

    if (result == SASL_OK)
	 text->state=3;

    return result;
  }

  return SASL_FAIL; /* should never get here */
}

const sasl_server_plug_t plugins[] = 
{
  {
    "DIGEST-MD5",
    0, /* max ssf */
    0,
    NULL,
    &server_start,
    &server_continue_step,
    &dispose,
    &mech_free,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
  }
};

int sasl_server_plug_init(sasl_utils_t *utils, int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  /* fail if we can't open the srvtab file */
  /*if (access(KEYFILE, R_OK)!=0)
    //  return SASL_FAIL;*/

  if (maxversion<DIGESTMD5_VERSION)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=DIGESTMD5_VERSION;

  return SASL_OK;
}

/* put in sasl_wrongmech */
static int c_start(void *glob_context __attribute__((unused)), 
		 sasl_client_params_t *params,
		 void **conn)
{
  context_t *text;

  /* holds state are in */
  text= params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  /*text->malloc= params->utils->malloc;*/
  /*text->free= params->utils->free;*/
  text->state=1;  
  *conn=text;

   DEBUGPRINT ("c_start finished");

  return SASL_OK;
}


/* convert a string of 8bit chars to it's representation in hex
 * using lowercase letters
 */
static char *convert16(unsigned char *in,int inlen,sasl_utils_t *utils)
{
  static char hex[]="0123456789abcdef";
  int lup;
  char *out;
  out=utils->malloc(inlen*2+1);
  if (out==NULL) return NULL;

  for (lup=0;lup<inlen;lup++)
  {
    out[lup*2]=  hex[  in[lup] >> 4 ];
    out[lup*2+1]=hex[  in[lup] & 15 ];
  }
  out[lup*2]=0;
  return out;
}


static int htoi(unsigned char *hexin, int *res)
{
  int lup, inlen;
  inlen = strlen (hexin);

  *res = 0;
  for (lup=0;lup<inlen;lup++)
  {
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

       default:       return SASL_BADPARAM;
	  }

  }

  return SASL_OK;
}


static int c_continue_step (void *conn_context,
	      sasl_client_params_t *params,
	      const char *serverin,
	      int serverinlen,
	      sasl_interact_t **prompt_need,
	      char **clientout,
	      int *clientoutlen,
	      sasl_out_params_t *oparams)
{
  context_t *text;
  text=conn_context;

  if (text->state==1)
  {

     DEBUGPRINT ("c_start step 1 started");

    /* XXX reauth if possible */
    /* XXX if reauth is successfull - goto text->state=3!!! */

     *clientout = params->utils->malloc(1); /*text->malloc(1);*/

    if (! *clientout) return SASL_NOMEM;
    **clientout = '\0';
    *clientoutlen = 0;

    text->state=2;

     DEBUGPRINT ("c_start step 1 finished");

    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    char *digesturi = NULL;
    char *username = NULL;

    char *nonce = NULL;
    char *ncvalue = "00000001"; 
    char *cnonce = NULL;

    char *qop = NULL;
    /*char *servtype = NULL;
    //char *host = NULL;
    //char *servname = NULL;*/
    char *response = NULL;

    char *realm = NULL;
    char *passwd = NULL;

    char *maxbuf_str = NULL;
    /*int   maxbuf;*/

    char *charset = NULL;
    char *cipher = NULL;

    int result = SASL_FAIL;

	char *in = NULL;
	char *in_start;

	/*char secret[65]; 
	  //int lup;*/

    char *client_response=NULL;

    /* can we mess with serverin? copy it to be safe */
    /* char *in=serverin; //char *in=*serverin;???*/

     DEBUGPRINT ("c_start step 2 started");
     /*printf ("; serverin length is %d\n",serverinlen);*/

    /* need to prompt for password */
    if (*prompt_need==NULL)
    {
      *prompt_need=params->utils->malloc(sizeof(sasl_interact_t));
      if ((*prompt_need) ==NULL) return SASL_NOMEM; /*nothing allocated!!!*/
      (*prompt_need)->id=1;
      (*prompt_need)->challenge="password";
      (*prompt_need)->prompt="Please enter your password";
      (*prompt_need)->defresult="";

      return SASL_INTERACT;
    }

    _sasl_plugin_strdup(params->utils, 
		                (*prompt_need)->result, 
						&passwd, NULL);

    /*printf ("c_start step 2 : password is \"%s\"\n", passwd);*/

    /*params->utils->free((void *) (*prompt_need)->result); //This doesn't work!!!*/

	sasl_free_buf ( (*prompt_need)->result );

     DEBUGPRINT ("c_start step 2 : original password freed\n");

    params->utils->free(*prompt_need);
    (*prompt_need)=NULL;


	in = params->utils->malloc(serverinlen+1);
    memcpy(in, serverin, serverinlen);
	in[serverinlen] = 0;

    in_start = in;

    /*printf ("Server data is \"%s\"\r\n", in);*/

    /* parse what we got */
    while (in[0]!='\0') /*???*/
    {
      char *name, *value;
      get_pair(&in, &name, &value);

      /*VL(("received pair: %s - %s\n",name,value));*/

       DEBUGPRINT ("c_start step 2 : received pair: \t");
       DEBUGPRINT (name);
       DEBUGPRINT (":");
       DEBUGPRINT (value);
       DEBUGPRINT ("\n");

      if (strcmp(name,"realm")==0)
      {

		_sasl_plugin_strdup(params->utils, value, &realm, NULL);

      } else if (strcmp(name,"nonce")==0) {

		_sasl_plugin_strdup(params->utils, value, &nonce, NULL);

      } else if (strcmp(name,"qop")==0) {

		_sasl_plugin_strdup(params->utils, value, &qop, NULL);

      } else if (strcmp(name,"stale")==0) {

        /*XXX 
		//_sasl_plugin_strdup(params->utils, value, &stale_str, NULL);
		//XXX*/

      } else if (strcmp(name,"maxbuf")==0) {

	/*		//XXX
		//_sasl_plugin_strdup(params->utils, value, &maxbuf_str, NULL);
		//XXX*/

      } else if (strcmp(name,"charset")==0) {

		_sasl_plugin_strdup(params->utils, value, &charset, NULL);

      } else {
        VL (("unrecognized pair: ignoring\n"));
      }
    }

     DEBUGPRINT ("c_start step 2 : parsing finished");

    /* (username | realm | nonce | cnonce | nonce-count | qop
        digest-uri | response | maxbuf | charset | auth-param ) */

    /* get username */
    params->utils->getprop(params->utils->conn, SASL_USERNAME,
			   (void **)&username);
    if (! username) {
      VL(("no username!\n"));
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
    }

     VL (("c_start step 2 : username got : \"%s\"",username));


    /* realm is got from server */

    /* get nonce XXX have to clean up after self if fail */

    cnonce=create_nonce(params->utils);
    if (cnonce==NULL)
	{
      printf("failed to create cnonce\n");
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
	};

     DEBUGPRINT ("c_start step 2 : cnonce created");

    /* XXX nonce count */

    /* serv-type */
     /*servtype=params->service;*/
    /* host */
     /*host=params->serverFQDN; //params->params->serverFQDN;*/
    /* XXX serv-name */
     /*servname=params->serverFQDN; //params->params->serverFQDN;*/
    /* XXX digest uri */

    digesturi = params->utils->malloc( strlen(params->service)+1+
		                               strlen(params->serverFQDN)+1+
				       /*strlen(params->serverFQDN)+1*/
		                               1 
		                              );
    if (digesturi==NULL)
	{
      result = SASL_NOMEM;
	  goto FreeAllocatedMem;
    };

	strcpy(digesturi, params->service);
	strcat (digesturi, "/");
	strcat (digesturi, params->serverFQDN);
	/*strcat (digesturi, "/");
	  //strcat (digesturi, params->serverFQDN);*/

     DEBUGPRINT ("c_start step 2 : digest-uri constructed:");
     DEBUGPRINT (digesturi);

    /* response */
    response=calculate_response(params->utils,
						     username,
							 realm,
							 nonce, 
							 ncvalue,
							 cnonce,
							 qop,
							 digesturi,
                             passwd);

     DEBUGPRINT ("After calculate_response");

    if (add_to_challenge(params->utils, &client_response,"username", username, true)!=SASL_OK)
	{
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
    }

     DEBUGPRINT ("username");
						     
    if (add_to_challenge(params->utils, &client_response,"realm", realm, true)!=SASL_OK)
	{
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
	}
        
     DEBUGPRINT ("realm");

    if (add_to_challenge(params->utils, &client_response,"nonce", nonce, true)!=SASL_OK)
	{
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
    }

     DEBUGPRINT ("nonce");

    if (add_to_challenge(params->utils, &client_response,"cnonce", cnonce, true)!=SASL_OK)
	{
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
	}

     DEBUGPRINT ("cnonce");

    if (add_to_challenge(params->utils, &client_response,"nc", ncvalue, false)!=SASL_OK)
	{
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
    }

     DEBUGPRINT ("nc");

    if (add_to_challenge(params->utils, &client_response,"qop", qop, true)!=SASL_OK)
	{
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
    }

    /*charset="utf-8";
      // ???*/
    if (add_to_challenge(params->utils, &client_response,"charset", charset, true)!=SASL_OK)
	{
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
    }

    if (add_to_challenge(params->utils, &client_response,"digest-uri", digesturi, true)!=SASL_OK)
	{
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
    }

    if (add_to_challenge(params->utils, &client_response,"response", response, true)!=SASL_OK)
	{
	  params->utils->free(response); /*!!!*/
      result = SASL_FAIL;
	  goto FreeAllocatedMem;
    }


	*clientout = client_response;
    *clientoutlen = strlen(client_response);

     DEBUGPRINT ("Step result is");
     DEBUGPRINT (*clientout);


	result = SASL_OK;

	text->state=3;

    oparams->doneflag=1;

    /* set oparams */
	oparams->encode=NULL;
    oparams->decode=NULL;


    oparams->mech_ssf=0; /*1 - only integrity support*/
    oparams->maxoutbuf=1024; /* no clue what this should be*/

	if (_sasl_plugin_strdup(params->utils, realm, &oparams->realm, NULL)==SASL_NOMEM)
	{
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
	}

	if (_sasl_plugin_strdup(params->utils, username, &oparams->user, NULL)==SASL_NOMEM)
	{
	  params->utils->free (oparams->realm);
	  oparams->realm = NULL;
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
	}

	if (_sasl_plugin_strdup(params->utils, username, &oparams->authid, NULL)==SASL_NOMEM)
	{
	  params->utils->free (oparams->realm);
	  oparams->realm = NULL;
	  params->utils->free (oparams->user);
	  oparams->user = NULL;
      result = SASL_NOMEM;
      goto FreeAllocatedMem;
	}

	/*sasl_setprop(conn_context, SASL_USERNAME, oparams->user); //Test-Server.C use this!!!*/

    oparams->param_version=0;



    


FreeAllocatedMem:
	params->utils->free(passwd);
	params->utils->free (in_start);

	/*They wasn't malloc-ated
	  //params->utils->free(username);*/
    
      /*Realm is got from server!!!*/
	params->utils->free(realm);
	params->utils->free(nonce);
	params->utils->free(qop);

	/*params->utils->free(stale_str);
	  //params->utils->free(maxbuf_str);*/

	params->utils->free(charset);
    params->utils->free(digesturi);

    /*params->utils->free(ncvalue); //Only for multiple authentications*/

	params->utils->free(cnonce);

    return result;
  }

  /* challenge #2 */
  if (text->state==3) /*ReAUTH. NTI!!!*/
  {
    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
};

const sasl_client_plug_t client_plugins[] = 
{
  {
    "DIGEST-MD5",
    1 /*???*/, /* max ssf */
    0,
    NULL,
    NULL,
    &c_start,
    &c_continue_step,
    &dispose,
    &mech_free,
    NULL,
    NULL
  }
};

int sasl_client_plug_init(sasl_utils_t *utils, int maxversion,
			  int *out_version, const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<DIGESTMD5_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=DIGESTMD5_VERSION;

  return SASL_OK;
}
