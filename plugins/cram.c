/* CRAM-MD5 SASL plugin
 * Tim Martin 
 * $Id: cram.c,v 1.3 1998/11/17 02:32:29 rob Exp $
 */
/***********************************************************
        Copyright 1998 by Carnegie Mellon University

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
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sasl.h>
#include <saslplug.h>
#include <saslutil.h>

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define CRAM_MD5_VERSION 2;

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

struct scram_entry
{
  unsigned char salt[8];
  unsigned char verifier[16];
  unsigned char serverkey[16];
};

typedef struct context {

  int state;    /* holds state are in */
  char *msgid;  /* timestamp used for md5 transforms */
  int msgidlen;

  int secretlen;

} context_t;

static int start(void *glob_context __attribute__((unused)),
		 sasl_server_params_t *sparams,
		 const char *challenge __attribute__((unused)),
		 int challen __attribute__((unused)),
		 void **conn,
		 const char **errstr)
{
  context_t *text;

  if (errstr)
    *errstr = NULL;

  text= sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;
  
  *conn=text;

  return SASL_OK;
}



static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  utils->free(text->msgid);
  utils->free(text);
}

static void mech_free(void *global_context, sasl_utils_t *utils)
{

  utils->free(global_context);  
}

static char * randomdigits(sasl_server_params_t *sparams)
{
  unsigned long num;
  char *ret;
 
  /* random 32-bit number */
  unsigned char temp[5];


  sparams->utils->rand(sparams->utils->rpool,(char *) temp,4);


  num=(temp[0] *256*256*256) +
      (temp[1] *256*256) +
      (temp[2] * 256) +
      (temp[3] );

  ret= sparams->utils->malloc(15);
  if (ret==NULL) return NULL;
  sprintf(ret,"%lu",num);

  return ret;
}

static char *gettime(sasl_server_params_t *sparams)
{
  char *ret;
  time_t t;

  t=time(NULL);
  ret= sparams->utils->malloc(15);
  if (ret==NULL) return NULL;
  sprintf(ret,"%lu",t);
  
  return ret;
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


static int continue_step (void *conn_context,
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
    /* arbitrary string of random digits 
     * time stamp
     * primary host
     */
    char *time=gettime(sparams);
    char *randdigits=randomdigits(sparams);
    if ((time==NULL) || (randdigits==NULL)) return SASL_NOMEM;

    *serverout=sparams->utils->malloc(1024);
    if (*serverout==NULL) return SASL_NOMEM;
    sprintf((char *)*serverout,"<%s.%s@%s>",randdigits,time,
	    sparams->local_domain);
    sparams->utils->free(time);    
    sparams->utils->free(randdigits);    
    
    *serveroutlen=strlen(*serverout);
    text->msgidlen=*serveroutlen;

    text->msgid=sparams->utils->malloc(*serveroutlen);
    if (text->msgid==NULL) return SASL_NOMEM;

    memcpy(text->msgid,*serverout,*serveroutlen);

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    /* verify digest */
    char *in16;
    char userid[256];
    unsigned char digest[1024];
    sasl_secret_t *sec;
    int lup,pos;
    MD5_CTX ver_i, ver_o;
    int len=sizeof(MD5_CTX);
    int result;
    sasl_server_getsecret_t *getsecret;
    void *getsecret_context;

    /* extract userid; everything before last space*/
    pos=clientinlen-1;
    while ((pos>0) && (clientin[pos]!=' '))
    {
      pos--;
    }
    if (pos==0) return -99; /*SASL_FAIL;*/
      
    for (lup=0;lup<pos;lup++)
      userid[lup]=clientin[lup];
    userid[lup]=0;

    result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_GETSECRET,
					 &getsecret,
					 &getsecret_context);
    if (result != SASL_OK)
      return result;

    if (! getsecret)
      return SASL_FAIL;

    /* We use the user's SCRAM secret */
    result = getsecret(getsecret_context, "SCRAM-MD5", userid, &sec);
    if (result != SASL_OK)
      return result;

    if (! sec)
      return SASL_FAIL;

    memcpy(ver_i.state,sec->data+8 , len);
    memcpy(ver_o.state,sec->data+len+8, len); 
    sparams->utils->free(sec);

    /* load veri and vero */

    sparams->utils->MD5Update(&ver_i,
			      (unsigned char *)text->msgid,
			      text->msgidlen);
    sparams->utils->MD5Final(digest, &ver_i);
    sparams->utils->MD5Update(&ver_o, digest, 16);
    sparams->utils->MD5Final(digest, &ver_o);
    
    in16=convert16(digest,16,sparams->utils);
    if (in16==NULL) return SASL_NOMEM;

    sparams->utils->free(sec);

    /* if ok verified */
    if (strcmp(in16,clientin)!=0)
    {
      sparams->utils->free(in16);    
      return SASL_BADAUTH;
    }
    sparams->utils->free(in16);    

    /* nothing more to do; authenticated 
     * set oparams information
     */
    oparams->doneflag=1;

    oparams->user=userid; /* set username */
    oparams->authid=userid;

    oparams->mech_ssf=1;

    oparams->maxoutbuf=1024; /* no clue what this should be */
  
    oparams->encode=NULL;
    oparams->decode=NULL;

    oparams->realm=NULL;
    oparams->param_version=0;

    /*    lup=strdup("CRAM-MD5 authenticated",sparams->utils->malloc,serverout,serveroutlen);
    if (lup!=SASL_OK) return lup;*/
    *serverout = NULL;
    *serveroutlen = 0;

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
	int flags,
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

  /* We're actually constructing a SCRAM secret... */
  return putsecret(putsecret_context,
		   "SCRAM-MD5",
		   user,
		   secret);
}

const sasl_server_plug_t plugins[] = 
{
  {
    "CRAM-MD5",
    0,
    0,
    NULL,
    &start,
    &continue_step,
    &dispose,
    &mech_free,
    &setpass,
    NULL,
    NULL
  }
};

int sasl_server_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<1)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=CRAM_MD5_VERSION;

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

  oparams->mech_ssf=1;
  oparams->maxoutbuf=1024; /* no clue what this should be */
  oparams->encode=NULL;
  oparams->decode=NULL;
  oparams->user="anonymous"; /* set username */
  oparams->authid="anonymous";
  oparams->realm=NULL;
  oparams->param_version=0;

  /* doesn't really matter how the server responds */

  if (text->state==1)
  {     
    sasl_security_properties_t secprops;
    int external;

    text->msgid=params->utils->malloc(1);
    if (text->msgid==NULL) return SASL_NOMEM;
    text->msgidlen=0;
    *clientout=NULL;
    *clientoutlen=0;

    /* check if sec layer strong enough */
    secprops=params->props;
    external=params->external_ssf;

    if (secprops.min_ssf>0)
      return SASL_TOOWEAK;

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    unsigned char digest[1024];
    char secret[65]; 
    int lup;
    char *in16;
    char *userid;

    /* need to prompt for password */
    if (*prompt_need==NULL)
    {
      *prompt_need=params->utils->malloc(sizeof(sasl_interact_t));
      if ((*prompt_need)==NULL) return SASL_NOMEM;
      (*prompt_need)->id=1;
      (*prompt_need)->challenge="password";
      (*prompt_need)->prompt="Please enter your password";
      (*prompt_need)->defresult="";

      return SASL_INTERACT;
    }
        
    memcpy(secret, (*prompt_need)->result, (*prompt_need)->len);

    /*    memcpy(secret,8,"password");
	  (*prompt_need)->len=8;*/

    for (lup= (*prompt_need)->len ;lup<64;lup++)
      secret[lup]='\0';



    params->utils->free((void *)((*prompt_need)->result));
    params->utils->free(*prompt_need);
    *prompt_need = NULL;

    /* username
     * space
     * digest (keyed md5 where key is passwd)
     */
    serverin="<1970676461.902464610@alive.andrew.cmu.edu>";
    serverinlen=43;

    VL(("serverin=[%s]\n",serverin));
    VL(("serverinlen=[%i]\n",serverinlen));
    VL(("sec=%s\n",secret));

    params->utils->hmac_md5((unsigned char *) serverin,serverinlen,
			    (unsigned char *) secret,64,digest);

    memset(digest,11,100);
    
    params->utils->hmac_md5((unsigned char *) "1234567890",10,
			    (unsigned char *) "abcdef",6,digest);



    params->utils->getprop(params->utils->conn, SASL_USERNAME,
			   (void **)&userid);



    *clientout=params->utils->malloc(32+1+strlen(userid)+1);
    if ((*clientout) == NULL) return SASL_NOMEM;
    
    in16=convert16(digest,16,params->utils);
    if (in16==NULL) return SASL_NOMEM;



    sprintf((char *)*clientout,"%s %s",userid,in16);
    params->utils->free(in16);    

    *clientoutlen=strlen(*clientout);

    /*nothing more to do; authenticated */
    oparams->doneflag=1;

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

const sasl_client_plug_t client_plugins[] = 
{
  {
    "CRAM-MD5",
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
  if (maxversion<1)
    return SASL_BADVERS;

  *pluglist=client_plugins;
  *plugcount=1;
  *out_version=CRAM_MD5_VERSION;

  return SASL_OK;
}
