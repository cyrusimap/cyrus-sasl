/* SCRAM-MD5 SASL plugin
 * Please note this is no longer being maintained
 * Tim Martin 
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
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sasl.h>
#include <saslplug.h>
#include <saslutil.h>

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslSCRAM.h"
#endif /* WIN32 */

#define SCRAM_MD5_VERSION (3)

struct scram_entry
{
  unsigned char salt[8];
  unsigned char verifier[16];
  unsigned char serverkey[16];
};

typedef struct global_context {

  int number;  /* sequence number so no 2 nonce's can be the same 
		* starts as random number
		*/

} global_context_t;

typedef struct context {

  struct scram_entry entry;

  int state;    /* holds state are in */
  char *msgid;  /* timestamp used for md5 transforms */
  int msgidlen;
  int number;    /* got from global context */

  sasl_ssf_t ssf;

  char *clientinitmsg; /* initial message  */
  int clientinitmsglen;
  char *serverinitmsg; /* initial message  */
  int serverinitmsglen;

  sasl_utils_t *utils;

  char digest1[16];

  int sendnum;  /* for use with integrity layer */
  int recvnum;
  unsigned char integrity[16];

} context_t;

/* this is integrity protection */
static int encode(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen)
{
  context_t *text=context;
  unsigned char digest[16];
  char *tmp;

  tmp=text->utils->malloc(20);
  if (tmp==NULL) return SASL_NOMEM;
  memcpy(tmp, &(text->sendnum), 4); /* ntohl(text->sendnum), 4);*/
  text->sendnum++;
  memcpy(tmp+4, text->integrity, 16);

  text->utils->hmac_md5((unsigned char *) input,inputlen,
			  (unsigned char *) tmp,20,digest);

  *outputlen=inputlen+16;
  *output=text->utils->malloc(*outputlen);  
  if ((*output) == NULL) return SASL_NOMEM;
  memcpy(*output, input, inputlen);
  memcpy(*output+inputlen, digest, 16);

  text->utils->free(tmp);

  return SASL_OK;
}

static int decode(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen)
{
  char *tmp;
  int lup;
  unsigned char digest[16];
  context_t *text=context;

  tmp=text->utils->malloc(20);
  if (tmp==NULL) return SASL_NOMEM;
  memcpy(tmp, &(text->recvnum), 4); 
  text->recvnum++;
  memcpy(tmp+4, text->integrity, 16);

  text->utils->hmac_md5((unsigned char *) input,inputlen-16,
			  (unsigned char *) tmp,20,digest);

  for (lup=0;lup<16;lup++)
    if (input[inputlen-16+lup]!=(char)digest[lup])
    {
      return SASL_FAIL;
    }
  
  *outputlen=inputlen-16;
  *output=text->utils->malloc(*outputlen);  
  if ((*output)==NULL) return SASL_NOMEM;
  memcpy(*output, input, *outputlen);

  text->utils->free(tmp);

  return SASL_OK;
}

static int start(void *glob_context, 
		 sasl_server_params_t *sparams,
		 const char *challenge __attribute__((unused)),
		 int challen __attribute__((unused)),
		 void **conn,
		 const char **errstr)
{
  context_t *text;
  global_context_t *glob=glob_context;
  if (errstr)
      *errstr = NULL;
  text= sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;
  text->number = glob->number++;

  *conn=text;

  return SASL_OK;
}



static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;
  utils->free(text->clientinitmsg);
  utils->free(text->serverinitmsg);
  utils->free(text);
}

static void mech_free(void *global_context, sasl_utils_t *utils)
{

  utils->free(global_context);  
}

static char * randomdigits(sasl_utils_t *utils)
{
  unsigned long num;

  char *ret;
 
  /* random 32-bit number */
  unsigned char temp[5];

  sasl_rand(utils->rpool,(char *) temp,4);

  num=(temp[0] *256*256*256) +
      (temp[1] *256*256) +
      (temp[2] * 256) +
      (temp[3] );

  ret= utils->malloc(15);
  if (ret==NULL) return NULL;
  sprintf(ret,"%u",(unsigned int) num);

  return ret;
}

static char *gettime(sasl_utils_t *utils)
{
  char *ret;
  time_t t;

  t=time(NULL);
  ret= utils->malloc(15);
  if (ret==NULL) return NULL;
  sprintf(ret,"%u",(unsigned int) t);
  
  return ret;
}



static int load_things(sasl_utils_t *utils, context_t *text, const char *user)
{
    MD5_CTX ver_i, ver_o, tctx;
    int result;
    sasl_secret_t *sec;
    sasl_server_getsecret_t *getsecret;
    void *getsecret_context;
    unsigned char digest1[16], digest2[16], digest3[16], serverkey[16];
    int len=sizeof(MD5_CTX);

    result = utils->getcallback(utils->conn, SASL_CB_SERVER_GETSECRET,
				&getsecret, &getsecret_context);
    if (result != SASL_OK)
      return result;

    if (! getsecret)
      return SASL_FAIL;

    result = getsecret(getsecret_context, "SCRAM-MD5", user, &sec);
    if (result != SASL_OK)
      return result;

    if (! sec)
      return SASL_FAIL;

    memcpy(text->entry.salt,sec->data , 8);
    memcpy(ver_i.state,sec->data+8 , len);
    memcpy(ver_o.state,sec->data+len+8, len); 

    utils->MD5Update(&ver_i, (unsigned char *) sec->data, 8);
    utils->MD5Final(digest1, &ver_i);
    utils->MD5Update(&ver_o, digest1, 16);
    utils->MD5Final(digest1, &ver_o);

    utils->free(sec);
  /* erase secret from memory */
    
  /* step C */
  utils->MD5Init(&tctx); 
  utils->MD5Update(&tctx, digest1, 16); 
  utils->MD5Final(digest2, &tctx); 


  /* step D */
  utils->MD5Init(&tctx); 
  utils->MD5Update(&tctx, digest2, 16); 
  utils->MD5Final(digest3, &tctx); 

  memcpy(text->entry.verifier, digest3, 16);

  /* create the server ver now */
  utils->hmac_md5((unsigned char *) text->entry.salt,8,
		  (unsigned char *) digest1,16, serverkey);

  memcpy(text->entry.serverkey, serverkey, 16);
  
  return SASL_OK;
}

static int server_continue_step (void *conn_context,
	      sasl_server_params_t *params,
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
    int lup=0;
    int result;
    int pos=0;
    char userid[65];

    char info[4];
    char serviceid[100];
    char nonce[1024];
    char *time=gettime(params->utils);
    char *randdigits=randomdigits(params->utils);

    int *intp;

    if ((time==NULL) || (randdigits==NULL))
	return SASL_NOMEM;

    /* get requested ssf */
    result = sasl_getprop(params->utils->conn,
			  SASL_SSF_EXTERNAL, (void **)&intp);  
    if (result!=SASL_OK) { return result; }
    text->ssf = *intp;

    /* save msg for step #2 */
    text->clientinitmsg=params->utils->malloc(clientinlen);
    if (text->clientinitmsg==NULL) return SASL_NOMEM;

    text->clientinitmsglen=clientinlen;
    memcpy(text->clientinitmsg, clientin, clientinlen);


    lup=0;
    /* get userid */
    while ((lup<clientinlen) && (clientin[lup]!=0))
    {
      lup++;
    }

    lup++;
    while ((lup<clientinlen) && (clientin[lup]!=0))
    {
      userid[pos]=clientin[lup];
      lup++;
      pos++;
    }
    userid[pos]=0;

    /* load stuff from passwd file */
    result=load_things(params->utils, text, userid);
    if (result!=SASL_OK) { return result; }

    /* 8 octet salt
     * 1 octet security layers x01
     * 3 maximum cipher text size can receive x00
     * service @ server domain
     * server nonce
     */

    info[0]=text->ssf;
    info[1]=0x00;
    info[2]=0x00;
    info[3]=0x00;
    
    sprintf(serviceid,"%s@%s",params->service , params->serverFQDN);
    
    sprintf(nonce,"%s%i%s",time, text->number, randdigits);
    params->utils->free(time);
    params->utils->free(randdigits);

    *serveroutlen=8+4+strlen(serviceid)+strlen(nonce);
    *serverout=params->utils->malloc(*serveroutlen);
    if ((*serverout)==NULL) return SASL_NOMEM;

    memcpy((char *) *serverout    ,text->entry.salt,8);
    memcpy((char *) *serverout+8  ,info,4);
    memcpy((char *) *serverout+12 ,serviceid,strlen(serviceid));
    memcpy((char *) *serverout+12+strlen(serviceid) ,nonce,strlen(nonce));

    text->serverinitmsg=params->utils->malloc(*serveroutlen+1);
    if (text->serverinitmsg==NULL) return SASL_NOMEM;
    text->serverinitmsglen=*serveroutlen;
    memcpy(text->serverinitmsg, *serverout, *serveroutlen);    
    memset(text->serverinitmsg+*serveroutlen, 0, 1);

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {

    MD5_CTX tctx;
    int len=sizeof(MD5_CTX);
    unsigned char digest4[16], digest5[16], xor_value[16], digestg[16], digest8[16];
    char bitmask[4];
    char clientbitmask[5];
    /* verify digest */
    char *parti;
    int lup;
    char *parte;

    

    /* */
 

    /* */
    
    /* create buffer */
    bitmask[0]=text->ssf;
    bitmask[1]=0x00;
    bitmask[2]=0x00;
    bitmask[3]=0x00;

    /* step E */
    memcpy(clientbitmask, clientin, 4);
    clientbitmask[4]=0;
    len=text->clientinitmsglen+text->serverinitmsglen+4;

    parte=params->utils->malloc(len);
    if (parte==NULL) return SASL_NOMEM;

    memset(parte, 0, len);
    memcpy(parte, text->serverinitmsg, text->serverinitmsglen+1);
    memcpy(parte+text->serverinitmsglen, text->clientinitmsg, text->clientinitmsglen);
    memcpy(parte+text->serverinitmsglen+text->clientinitmsglen,
	   bitmask, 4);

    /* step b */    /* should be stored thing instead of digest3 */
    params->utils->hmac_md5((unsigned char *) parte,len,
			    (unsigned char *) text->entry.verifier,16,digest4);


    /* step c */
    for (lup=0;lup<16;lup++)
      xor_value[lup]= clientin[4+lup] ^ digest4[lup];


    /* this is needed for integrity protection */
    params->utils->hmac_md5((unsigned char *) parte,len,
			    (unsigned char *) xor_value,16,digest8);
    memcpy( text->integrity, digest8, 16);

    params->utils->free(parte);

    /* step d */
    params->utils->MD5Init(&tctx); 
    params->utils->MD5Update(&tctx, xor_value, 16); 
    params->utils->MD5Final(digest5, &tctx); 


    /* part e should be equal to stored verifier */
    for (lup=0;lup<16;lup++)
      if (text->entry.verifier[lup]!=digest5[lup])
      {
	
	return SASL_BADAUTH;
      }

    /* if got here then verified */
        
    /* create an ``I'' */
    len=text->clientinitmsglen+text->serverinitmsglen+4;

    parti=params->utils->malloc(len);
    if (parti==NULL) return SASL_NOMEM;

    memset(parti, 0, len);
    memcpy(parti, text->clientinitmsg, text->clientinitmsglen);
    memcpy(parti+text->clientinitmsglen, text->serverinitmsg, text->serverinitmsglen);
    memcpy(parti+text->serverinitmsglen+text->clientinitmsglen,
	   bitmask, 4);


    /* part g */
    params->utils->hmac_md5((unsigned char *) parti,len,
			    (unsigned char *) text->entry.serverkey,16,digestg);

    params->utils->free(parti);

    *serverout = params->utils->malloc(16);
    if ((*serverout) == NULL) return SASL_NOMEM;
    *serveroutlen=16;

    memcpy((char *) *serverout, digestg, 16);

    /* nothing more to do; authenticated 
     * set oparams information
     */
    oparams->doneflag=1;
    /*
    oparams->user=userid; 
    oparams->authid=userid;
*/
    oparams->mech_ssf=text->ssf;

    oparams->maxoutbuf=0; /* no clue what this should be */



    if (text->ssf==0)  /* no encryption */
    {
      oparams->encode=NULL;
      oparams->decode=NULL;
    } else if (text->ssf==1) {
      text->utils=params->utils;
      text->sendnum=1;
      text->recvnum=1;
      oparams->encode=&encode;
      oparams->decode=&decode;
    } else {
      return SASL_FAIL;
    }

    oparams->realm=NULL;
    oparams->param_version=0;

    return SASL_OK;
  }


  return SASL_FAIL; /* should never get here */
}

static int
setpass(void *glob_context __attribute__((unused)),
	sasl_server_params_t *sparams,
	const char *user,
	const char *pass,
	unsigned passlen,
	int flags __attribute__((unused)),
	const char **errstr)
{
  int result;
  sasl_server_putsecret_t *putsecret;
  void *putsecret_context;
  char buf[sizeof(sasl_secret_t) + sizeof(struct scram_entry)];
  sasl_secret_t *secret = (sasl_secret_t *)&buf;
  struct scram_entry *ent = (struct scram_entry *)&secret->data;
  MD5_CTX ver;
  unsigned char pad[64];
  size_t lupe;

  if (errstr)
    *errstr = NULL;
  
  result = sparams->utils->getcallback(sparams->utils->conn,
				       SASL_CB_SERVER_PUTSECRET,
				       &putsecret,
				       &putsecret_context);
  if (result != SASL_OK)
    return 0;

  /* Get some salt... */
  sparams->utils->rand(sparams->utils->rpool,
		       (char *)&ent->salt,
		       sizeof(ent->salt));

  /* Create the pads... */
  memset(pad, 0, sizeof(pad));
  memcpy(pad, pass, passlen < sizeof(pad) ? passlen : sizeof(pad));
  
  for (lupe = 0; lupe < sizeof(pad); lupe++) {
    pad[lupe] ^= 0x36;
  }

  sparams->utils->MD5Init(&ver);
  sparams->utils->MD5Update(&ver, pad, sizeof(pad));
  
  memcpy(&ent->verifier, ver.state, sizeof(ent->verifier));

  memset(pad, 0, sizeof(pad));
  memcpy(pad, pass, passlen < sizeof(pad) ? passlen : sizeof(pad));
  
  for (lupe = 0; lupe < sizeof(pad); lupe++) {
    pad[lupe] ^= 0x5c;
  }

  sparams->utils->MD5Init(&ver);
  sparams->utils->MD5Update(&ver, pad, sizeof(pad));
  
  memcpy(&ent->serverkey, ver.state, sizeof(ent->serverkey));

  secret->len = sizeof(struct scram_entry);

  return putsecret(putsecret_context,
		   "SCRAM-MD5",
		   user,
		   secret);
}

static sasl_server_plug_t plugins[] = 
{
  {
    "SCRAM-MD5",
    0,
    0,
    NULL,
    &start,
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

int sasl_server_plug_init(sasl_utils_t *utils, int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  global_context_t *glob;

  if (maxversion<SCRAM_MD5_VERSION)
    return SASL_BADVERS;

  glob=utils->malloc(sizeof(global_context_t));
  if (glob==NULL) return SASL_NOMEM;
  glob->number=1;
  plugins->glob_context=glob;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=SCRAM_MD5_VERSION;

  return SASL_OK;
}

/* put in sasl_wrongmech */
static int c_start(void *glob_context __attribute__((unused)), 
		 sasl_client_params_t *params,
		 void **conn)
{
  context_t *text;

/* should be no client data
   if there is then ignore it i guess */

  /* holds state are in */
  text= params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;  
  *conn=text;

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

  /* doesn't really matter how the server responds */

  if (text->state==1)
  {     
    /* authorization NUL authentication NUL client nonce */
    int pos=0, result;
    char nonce[1024];
    char *time=gettime(params->utils);
    char *randdigits=randomdigits(params->utils);
    char *authorid="";
    char *authenid="";
    char hostname[256];
    int *intp;

    if ((time==NULL) || (randdigits==NULL)) return SASL_NOMEM;

    /* get ssf */
    result = sasl_getprop(params->utils->conn,
			  SASL_SSF_EXTERNAL, (void **)&intp);  
    if (result!=SASL_OK) return result;
    text->ssf = *intp;

    /* set hostname */
    result=gethostname(hostname,sizeof(hostname));
    if (result!=0) return SASL_FAIL;

    result=sasl_getprop(params->utils->conn, 
			SASL_USERNAME, (void **)&authenid);
    if (result!=SASL_OK) return result;

    memset(nonce, 0, 100);
    sprintf(nonce,"<%s%i%s@%s>",time, 12, randdigits ,hostname);
    params->utils->free(time);
    params->utils->free(randdigits);

    *clientoutlen=strlen(nonce)+2+strlen(authorid)+strlen(authenid);    
    *clientout=params->utils->malloc(*clientoutlen+1);    
    if ((*clientout) == NULL) return SASL_NOMEM;

    memset((char *) *clientout, 0, *clientoutlen+1);

    memcpy((char *) *clientout, authorid, strlen(authorid));
    pos+=strlen(authorid)+1;
    memcpy((char *) *clientout+pos, authenid, strlen(authenid));
    pos+=strlen(authenid)+1;    
    memcpy((char *) *clientout+pos, nonce, strlen(nonce));


    text->clientinitmsg=params->utils->malloc(*clientoutlen+1);
    if (text->clientinitmsg==NULL) return SASL_NOMEM;

    text->clientinitmsglen=*clientoutlen;
    memcpy( text->clientinitmsg, *clientout, *clientoutlen+1);
    
    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {    
    int len;
    char *parte;
    char bitmask[4];
    unsigned char digest1[16];
    unsigned char digest2[16];
    unsigned char digest3[16];
    unsigned char digest4[16];
    unsigned char digest8[16];
    unsigned char xor_value[16];

    char secret[65]; 
    int lup;
    MD5_CTX tctx; 

    /* need to prompt for password */
    if (*prompt_need==NULL)
    {
      *prompt_need=params->utils->malloc(sizeof(sasl_interact_t));
      if ((*prompt_need) ==NULL) return SASL_NOMEM;
      (*prompt_need)->id=1;
      (*prompt_need)->challenge="password";
      (*prompt_need)->prompt="Please enter your password";
      (*prompt_need)->defresult="";

      return SASL_INTERACT;
    }
        
    memcpy(secret, (*prompt_need)->result, (*prompt_need)->len);

    for (lup= (*prompt_need)->len ;lup<64;lup++)
      secret[lup]='\0';

    params->utils->free((void *) (*prompt_need)->result);
    params->utils->free(*prompt_need);
    (*prompt_need)=NULL;

    /* need the salt later */
    memcpy( text->entry.salt, serverin, 8);

    params->utils->hmac_md5((unsigned char *) serverin,8,
			    (unsigned char *) secret,64,digest1);

    /* this is needed later */
    memcpy( text->digest1, digest1, 16);

    /* erase secret from memory */
    


    /* step C */
    params->utils->MD5Init(&tctx); 
    params->utils->MD5Update(&tctx, digest1, 16); 
    params->utils->MD5Final(digest2, &tctx); 


    /* step D */
    params->utils->MD5Init(&tctx); 
    params->utils->MD5Update(&tctx, digest2, 16); 
    params->utils->MD5Final(digest3, &tctx); 


    /* create buffer */
    bitmask[0]=text->ssf;
    bitmask[1]=0x00;
    bitmask[2]=0x00;
    bitmask[3]=0x00;

    /* need later initserver msg*/
    text->serverinitmsg=params->utils->malloc(serverinlen);
    if (text->serverinitmsg==NULL) return SASL_NOMEM;
    text->serverinitmsglen=serverinlen;
    memcpy( text->serverinitmsg, serverin, serverinlen);

    len=text->serverinitmsglen+text->clientinitmsglen+4;
    parte=params->utils->malloc(len);
    if (parte==NULL) return SASL_NOMEM;
    memcpy(parte, serverin, serverinlen);
    memcpy(parte+serverinlen, text->clientinitmsg, text->clientinitmsglen);
    memcpy(parte+serverinlen+text->clientinitmsglen,bitmask ,4);


    /* step F */
    params->utils->hmac_md5((unsigned char *) parte,len,
			    (unsigned char *) digest3,16,digest4);


    /* this is needed for integrity protection */
    params->utils->hmac_md5((unsigned char *) parte,len,
			    (unsigned char *) digest2,16,digest8);
    memcpy( text->integrity, digest8, 16);
    params->utils->free(parte);


    /* step G */
    for (lup=0;lup<16;lup++)
      xor_value[lup]= digest2[lup] ^ digest4[lup];


    *clientout=params->utils->malloc(21);
    if ((*clientout)==NULL) return SASL_NOMEM;

    memcpy((char *) *clientout, bitmask, 4);
    memcpy((char *) *clientout+4, xor_value, 16);
    memset((char *) *clientout+20, 0, 1);
    *clientoutlen=20;

    oparams->doneflag=1;
    text->state=3;
    return SASL_CONTINUE;
  }
  if (text->state==3)
  {    
    unsigned char digest2[16], digest3[16];
    int len,lup;
    char *parti;
    char bitmask[4];

    if (serverinlen!=16)
      return SASL_FAIL;

    /* part H */
    params->utils->hmac_md5((unsigned char *) text->entry.salt,8,
			    (unsigned char *) text->digest1,16,digest2);

    bitmask[0]=text->ssf;
    bitmask[1]=0x00;
    bitmask[2]=0x00;
    bitmask[3]=0x00;


    /* part I */
    len=text->clientinitmsglen+text->serverinitmsglen+4;

    parti=params->utils->malloc(len);
    if (parti==NULL) return SASL_NOMEM;
    memset(parti, 0, len);
    memcpy(parti, text->clientinitmsg, text->clientinitmsglen+1);
    memcpy(parti+text->clientinitmsglen, text->serverinitmsg, text->serverinitmsglen);
    memcpy(parti+text->serverinitmsglen+text->clientinitmsglen,
	   bitmask, 4);

    /* step J */
    params->utils->hmac_md5((unsigned char *) parti, len,
			    (unsigned char *) digest2,16,digest3);
    
    params->utils->free(parti);
    /* step K */
    for (lup=0;lup<16;lup++)
      if (serverin[lup]!=(char)digest3[lup])
	return SASL_FAIL;

    *clientout = params->utils->malloc(1);
    if (! *clientout) return SASL_NOMEM;

    *clientoutlen = 0;


    if (text->ssf==0)             /* no encryption */
    {
      oparams->encode=NULL;
      oparams->decode=NULL;
    } else if (text->ssf==1) {    /* integrity protection */
      text->utils=params->utils;
      text->sendnum=1;
      text->recvnum=1;
      oparams->encode=&encode;
      oparams->decode=&decode;
    } else {
      return SASL_FAIL;
    }

    /* set oparams */
    oparams->mech_ssf=text->ssf;
    oparams->maxoutbuf=0; /* no clue what this should be */

    oparams->user="anonymous"; /* set username */
    oparams->authid="anonymous";
    oparams->realm=NULL;
    oparams->param_version=0;

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "SCRAM-MD5",
    0,
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

int sasl_client_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<SCRAM_MD5_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;  

  *plugcount=1;
  *out_version=SCRAM_MD5_VERSION;


  return SASL_OK;
}
