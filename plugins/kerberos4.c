/* Kerberos4 SASL plugin
 * Tim Martin 
 * $Id: kerberos4.c,v 1.13 1998/11/30 20:05:50 rob Exp $
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
#ifdef WIN32
# include "winconfig.h"
#endif /* WIN32 */
#include <stdlib.h>
#if STDC_HEADERS
# include <string.h>
#else
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
char *strchr(), *strrchr();
# ifndef HAVE_MEMCPY
#  define memcpy(d, s, n) bcopy ((s), (d), (n))
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# endif
#endif
#include <krb.h>
#include <des.h>
#include <sys/types.h>
#ifdef WIN32
# include <winsock.h>
#else
# include <sys/param.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif /* WIN32 */
#if HAVE_UNISTD_H
# include <sys/types.h>
# include <unistd.h>
#endif
#include <fcntl.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslKERBEROSV4.h"

/* KClient doesn't define this */
typedef struct krb_principal {
    char name[ANAME_SZ];
    char instance[INST_SZ];
    char realm[REALM_SZ];
} krb_principal;

/* This isn't defined under WIN32.  For access() */
#ifndef R_OK
#define R_OK 04
#endif

#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

#ifdef sun
/* gotta define gethostname ourselves on suns */
extern int gethostname(char *, int);
#endif

#define KERBEROS_VERSION 2;
#define KEYS_FILE NULL

typedef struct context {
  int state;

  unsigned long challenge;

  char *service;
  char instance[ANAME_SZ];
  char pname[ANAME_SZ];
  char pinst[INST_SZ];
  char prealm[REALM_SZ];
  char *hostname;
  char *realm;
  char *auth;
  unsigned long ip;
  
  CREDENTIALS credentials;

  des_cblock key;     /* session key */
  des_cblock session; /* session key */

  des_key_schedule init_keysched;   /* key schedule for initialization */
  des_key_schedule enc_keysched;    /* encryption key schedule */
  des_key_schedule dec_keysched;    /* decryption key schedule */


  struct sockaddr_in ip_local;
  struct sockaddr_in ip_remote;

  sasl_ssf_t ssf; /* security layer type */

  sasl_malloc_t *malloc;
  sasl_free_t *free;

  char *buffer;
  char sizebuf[4];
  int cursize;
  int size;
  int needsize;
  int secflags; /* client/server supports layers? */

} context_t;

static int privacy_encode(void *context, const char *input, unsigned inputlen,
			  char **output, unsigned *outputlen)
{
  int len;
  context_t *text;
  text=context;

  *output=text->malloc(inputlen+30);
  if ((*output) ==NULL) return SASL_NOMEM;
  
  len=krb_mk_priv((char *) input, *output+4,
		  inputlen,  text->enc_keysched, 
		  &(text->session), &(text->ip_local),
		  &(text->ip_remote));

  *outputlen=len+4;

  len=htonl(len);

  memcpy(*output, &len, 4);
  
  return SASL_OK;
}


static int privacy_decode(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen)
{
    int len, diff, tocopy;
    MSG_DAT *data;
    context_t *text=context;
    char *extra;
    unsigned int extralen=0;
  
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

	if (text->size>0xFFFF) return SASL_FAIL; /* too big probably error */
	
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

    if (inputlen< diff) /* not enough for a decode */
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
  
    data=text->malloc(sizeof(MSG_DAT));
    if (data==NULL) return SASL_NOMEM;
    memset(data,0,sizeof(MSG_DAT));

    len= krb_rd_priv((char *) text->buffer,text->size,  text->dec_keysched, 
		     &(text->session),
		     &(text->ip_remote), &(text->ip_local), data);

    if (len!=0)
    {
      text->free(text->buffer);
      return SASL_FAIL;
    }

    *output=text->malloc(data->app_length+1);
    if ((*output) == NULL) {
      text->free(text->buffer);
      return SASL_NOMEM;
    }
 
    *outputlen=data->app_length;
    memcpy(*output, data->app_data,data->app_length);
    (*output)[*outputlen] = '\0';
    text->free(text->buffer);

    text->free(data);
    text->size=-1;
    text->needsize=4;

    /* if received more than the end of a packet */
    if (inputlen!=0)
    {
      
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



static int integrity_encode(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen)
{
  int len;
  char *out;
  context_t *text;
  text=context;

  out=text->malloc(200);
  if (out==NULL) return SASL_NOMEM;

  *output=text->malloc(inputlen+30);
  if ((*output) ==NULL) return SASL_NOMEM;
  len=krb_mk_safe((char *) input, out,
		  inputlen, /* text->keysched, */
		  &(text->session), &(text->ip_local),
		  &(text->ip_remote));

  

  *outputlen=len+4;
  len=htonl(len);
  *output=malloc(500);

  memcpy(*output, &len, 4);
  memcpy(*output+4, out, (*outputlen)-4);

  return SASL_OK;
}

static int integrity_decode(void *context, const char *input, unsigned inputlen,
		  char **output, unsigned *outputlen)
{
    int len, diff, tocopy;
    MSG_DAT *data;
    context_t *text=context;
    char *extra;
    unsigned int extralen=0;
  
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
	if (text->size>0xFFFF) return SASL_FAIL; /* too big probably error */
	free(text->buffer);
	text->buffer=malloc(text->size);
      }

      *outputlen=0;
      *output=NULL;
      if (inputlen==0) /* have to wait until next time for data */
	return SASL_OK;

      if (text->size==0)  /* should never happen */
	return SASL_FAIL;
    }

    diff=text->size - text->cursize; /* bytes need for full message */

    if (inputlen< diff) /* not enough for a decode */
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
  
    data=text->malloc(sizeof(MSG_DAT));
    if (data==NULL) return SASL_NOMEM;

    len= krb_rd_safe((char *) text->buffer,text->size, /* text->keysched, */
		     &(text->session),
		     &(text->ip_remote), &(text->ip_local), data);



    if (len!=0)
    {
      return SASL_FAIL;
    }

    *output=text->malloc(data->app_length+1);
    if ((*output) == NULL) return SASL_NOMEM;
 
    *outputlen=data->app_length;
    memcpy((char *)*output, data->app_data,data->app_length);

    text->free(data);
    text->size=-1;
    text->needsize=4;

    /* if received more than the end of a packet */
    if (inputlen!=0)
    {
      integrity_decode(text, input, inputlen,
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


static int server_start(void *glob_context, 
		 sasl_server_params_t *sparams,
		 const char *challenge, int challen,
		 void **conn,
		 const char **errstr)
{
  context_t *text;

  if (errstr)
    *errstr = NULL;

  /* holds state are in */
  text= sparams->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->malloc = sparams->utils->malloc;
  text->free = sparams->utils->free;
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
  int result;

  context_t *text;
  text=conn_context;

  if (errstr)
    *errstr = NULL;

  if (text->state==1)
  {    
    /* random 32-bit number */
    unsigned long randocts,nchal;

    sparams->utils->rand(sparams->utils->rpool,(char *) &randocts ,
			 sizeof(randocts));    
    text->challenge=randocts; 
    nchal=htonl(text->challenge);


    *serverout=sparams->utils->malloc(5);     
    if ((*serverout) == NULL) return SASL_NOMEM;
    memcpy((char *)*serverout,&nchal,4);

    *serveroutlen=4;

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    unsigned long nchal;
    unsigned char sout[8];  
    AUTH_DAT ad;
    KTEXT_ST ticket;
    int lup;
    struct sockaddr_in addr;


    /* received authenticator */

    /* create ticket */
    ticket.length=clientinlen;
    for (lup=0;lup<clientinlen;lup++)      
      ticket.dat[lup]=clientin[lup];

    text->realm=krb_realmofhost(sparams->local_domain);    

    /* get instance */
    strncpy (text->instance, krb_get_phost (sparams->local_domain),
	     sizeof (text->instance));
    text->instance[sizeof(text->instance)-1] = 0;

    /* get ip number in addr*/
    result = sparams->utils->getprop(sparams->utils->conn,
				     SASL_IP_REMOTE, (void **)&addr);
    if (result != SASL_OK)
      return SASL_BADAUTH;

    /* check ticket */
    result=krb_rd_req(&ticket, (char *) sparams->service,
		      text->instance,addr.sin_addr.s_addr,&ad, "");

    if (result!=SASL_OK) /* if fails mechanism fails */
      return SASL_BADAUTH;

    /* 8 octets of data
     * 1-4 checksum+1
     * 5 security layers
     * 6-8max cipher text buffer size
     * use DES ECB in the session key
     */
    
    nchal=text->challenge+1;
    
    sout[0]=nchal >> 24;
    sout[1]=nchal >> 16;
    sout[2]=nchal >> 8;
    sout[3]=nchal ;
    sout[4]=1 | 2 | 4;     /* bitmask sec layers supported by server */
    sout[5]=0xFF;  /* max ciphertext buffer size */
    sout[6]=0xFF;
    sout[7]=0xFF;

    memcpy(text->session, ad.session, 8);
    memcpy(text->pname, ad.pname, sizeof(text->pname));
    memcpy(text->pinst, ad.pinst, sizeof(text->pinst));
    memcpy(text->prealm, ad.prealm, sizeof(text->prealm));
    des_key_sched(ad.session, text->init_keysched);

    des_key_sched(ad.session, text->enc_keysched); /* make keyschedule for */
    des_key_sched(ad.session, text->dec_keysched); /* encryption and decryption */
    
    des_ecb_encrypt(sout, sout, text->init_keysched, DES_ENCRYPT);
   
    *serverout=sparams->utils->malloc(9);
    if ((*serverout) == NULL) return SASL_NOMEM;
    memcpy((char *) *serverout, sout, 8);
    *serveroutlen=8;
   
    text->state=3;
    return SASL_CONTINUE;
  }

  if (text->state==3)
  {
    int result;
    unsigned long testnum;
    int lup;
    unsigned char in[1024];

    for (lup=0;lup<clientinlen;lup++)
      in[lup]=clientin[lup];

    in[lup]=0;

    /* decrypt; verify checksum */

    des_pcbc_encrypt((unsigned char *)in,
		     (unsigned char *)in,
		     clientinlen, text->init_keysched, text->session, DES_DECRYPT);

    testnum=(in[0]*256*256*256)+(in[1]*256*256)+(in[2]*256)+in[3];


    if (testnum!=text->challenge)
    {
      return SASL_BADAUTH;
    }

    text->ssf=in[4];
    /* get requested ssf */
    
          
    if (text->ssf==1)  /* no encryption */
    {
      oparams->encode=NULL;
      oparams->decode=NULL;
      oparams->mech_ssf=0;
      text->ssf=1;
    } else if (text->ssf==2) { /* integrity */
      oparams->encode=&integrity_encode;
      oparams->decode=&integrity_decode;
      oparams->mech_ssf=1;
      text->ssf=2;
    } else if (text->ssf==4) { /* privacy */
      oparams->encode=&privacy_encode;
      oparams->decode=&privacy_decode;
      oparams->mech_ssf=56;
      text->ssf=4;
    } else {
      /* not a supported encryption layer */
      return SASL_FAIL;
    }

    /* get ip data */
    result = sparams->utils->getprop(sparams->utils->conn,
				     SASL_IP_LOCAL,
				     (void **)&text->ip_local);
    if (result != SASL_OK) return result;

    result = sparams->utils->getprop(sparams->utils->conn,
				     SASL_IP_REMOTE,
				     (void **)&text->ip_remote);

    if (result!=SASL_OK) return result;

    text->malloc=sparams->utils->malloc;        
    text->free=sparams->utils->free;

    /* fill in oparams */
    oparams->maxoutbuf=1024; /* no clue what this should be */
    oparams->param_version=0;
    
    {
      size_t len = strlen(text->pname);
      if (text->pinst[0])
	len += strlen(text->pinst) + 1 /* for the . */;

      oparams->authid = sparams->utils->malloc(len + 1);
      if (! oparams->authid)
	return SASL_NOMEM;
      strcpy(oparams->authid, text->pname);
      if (text->pinst[0]) {
	strcat(oparams->authid, ".");
	strcat(oparams->authid, text->pinst);
      }

      oparams->user = sparams->utils->malloc(len + 1);
      if (! oparams->user) {
	sparams->utils->free(oparams->authid);
	return SASL_NOMEM;
      }
      strcpy(oparams->user, text->pname);
      if (text->pinst[0]) {
	strcat(oparams->user, ".");
	strcat(oparams->user, text->pinst);
      }

      oparams->realm = sparams->utils->malloc(strlen(text->prealm) + 1);
      if (! oparams->realm) {
	sparams->utils->free(oparams->authid);
	sparams->utils->free(oparams->user);
	return SASL_NOMEM;
      }
      strcpy(oparams->realm, text->prealm);
    }

    /* output */
    *serverout = NULL;
    *serveroutlen = 0;

    /* nothing more to do; authenticated */
    oparams->doneflag=1;

    text->size=-1;
    text->needsize=4;
    text->buffer=NULL;

    return SASL_OK;
  }


  return SASL_FAIL; /* should never get here */
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "KERBEROS_V4",
    56, /* max ssf */
    0,
    NULL,
    &server_start,
    &server_continue_step,
    &dispose,
    &mech_free,
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
  if (access(KEYFILE, R_OK)!=0)
    return SASL_FAIL;

  if (maxversion<1)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=KERBEROS_VERSION;

  return SASL_OK;
}

/* put in sasl_wrongmech */
static int c_start(void *glob_context, 
		 sasl_client_params_t *params,
		 void **conn)
{
  context_t *text;

  /* holds state are in */
  text= params->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->malloc= params->utils->malloc;
  text->free= params->utils->free;
  text->state=0;  
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

  KTEXT_ST authent;
  context_t *text;
  text=conn_context;

  authent.length = MAX_KTXT_LEN;
  
  if (text->state==0)
  {
    *clientout = text->malloc(1);
    if (! *clientout) return SASL_NOMEM;
    **clientout = '\0';
    *clientoutlen = 0;

    text->state=1;

    return SASL_CONTINUE;
  }

  if (text->state==1)
  {
    /* We should've just recieved a 32-bit number in network byte order.
     * We want to reply with an authenticator. */
    int result;
    KTEXT_ST ticket;
    char *service=(char *)params->service;

    memset(&ticket, 0L, sizeof(ticket));
    ticket.length=MAX_KTXT_LEN;   

    if (serverinlen != 4) { return SASL_FAIL; }

    memcpy(&text->challenge, serverin, 4);

    text->challenge=ntohl(text->challenge); 

    if (params->serverFQDN==NULL)
	return SASL_BADAUTH;
    if (params->service==NULL)
	return SASL_BADAUTH;

    text->realm=krb_realmofhost(params->serverFQDN);

    text->hostname=(char *) params->serverFQDN;

    strncpy (text->instance, krb_get_phost (params->serverFQDN), sizeof (text->instance));
    text->instance[sizeof(text->instance)-1] = 0;

    VL (("service=%s\n", service));
    VL (("instance=%s\n",text->instance));

    if ((result=krb_mk_req(&ticket, service, text->instance,
			   text->realm,text->challenge)))
    {
      return SASL_FAIL;
    }
    
    *clientout=params->utils->malloc(ticket.length);
    memcpy((char *) (*clientout), ticket.dat, ticket.length);
    *clientoutlen=ticket.length;

    text->state=2;
    return SASL_CONTINUE;
  }

  /* challenge #2 */
  if (text->state==2)
  {
    unsigned long testnum;
    unsigned long nchal;    
    char sout[1024];
    int lup,len;
    unsigned char in[8];
    char *userid;
    int result;
    int external;
    krb_principal principal;
    sasl_security_properties_t secprops;
    char ipstr[4];

    params->utils->getprop(params->utils->conn, SASL_USERNAME,
			   (void **)&userid);

#ifndef WIN32
    if (! userid) {
      krb_get_default_principal(principal.name,
				principal.instance,
				principal.realm);
      userid = principal.name;
    }
#endif /* WIN32 */

    /* must be 8 octets */
    if (serverinlen!=8)
    {
      return SASL_BADAUTH;
    }

    for (lup=0;lup<8;lup++)
      in[lup]=serverin[lup];

    /* get credentials */
    if ((krb_get_cred((char *)params->service,
		      text->instance,
		      text->realm,
		      &text->credentials)))
    {

      return SASL_BADAUTH;
    }
    memcpy(text->session, text->credentials.session, 8);
    des_key_sched(text->session, text->init_keysched);

    des_key_sched(text->session, text->enc_keysched); /* make keyschedule for */
    des_key_sched(text->session, text->dec_keysched); /* encryption and decryption */


    /* verify data 1st 4 octets must be equal to chal+1 */
    des_ecb_encrypt(in,in,text->init_keysched,DES_DECRYPT);

    testnum=(unsigned long) in;




    testnum=(in[0]*256*256*256)+(in[1]*256*256)+(in[2]*256)+in[3];



    if (testnum!=text->challenge+1)
    {
      return SASL_BADAUTH;
    }

    /* construct 8 octets
     * 1-4 - original checksum
     * 5 - bitmask of sec layer
     * 6-8 max buffer size
     */

    /* get requested ssf */
    secprops=params->props;
    external=params->external_ssf;
    VL (("external ssf=%i\n",external));

    if (secprops.min_ssf>56+external)
      return SASL_TOOWEAK;

    if (secprops.max_ssf<external)
      return SASL_FAIL;

    if (secprops.min_ssf>secprops.max_ssf)
      return SASL_FAIL;

    VL (("minssf=%i maxssf=%i\n",secprops.min_ssf,secprops.max_ssf));
    /* if client didn't set use strongest layer */
    if (secprops.max_ssf>1)
    {
      /* encryption */
      oparams->encode=&privacy_encode;
      oparams->decode=&privacy_decode;
      oparams->mech_ssf=56;
      text->ssf=4;
      VL (("Using encryption layer\n"));
    } else if ((secprops.min_ssf<=1+external) && (secprops.max_ssf>=1+external)) {
      /* integrity */
      oparams->encode=&integrity_encode;
      oparams->decode=&integrity_decode;
      oparams->mech_ssf=1;
      text->ssf=2;
      VL (("Using integrity layer\n"));
    } else if ((secprops.min_ssf<=external) && (secprops.max_ssf>=external)) {
      /* no layer */
      oparams->encode=NULL;
      oparams->decode=NULL;
      oparams->mech_ssf=0;
      text->ssf=1;
      VL (("Using no layer\n"));
    } else {
      /* error */
      return SASL_TOOWEAK;
    }

    /* server told me what layers support. make sure trying one it supports */
    if ( (in[4] & text->ssf)==0)
    {
      return SASL_WRONGMECH;
    }

    /* create stuff to send to server */
    nchal=text->challenge;
    sout[0]=nchal >> 24;
    sout[1]=nchal >> 16;
    sout[2]=nchal >> 8;
    sout[3]=nchal;
    sout[4]= text->ssf;     /*bitmask sec layers */
    sout[5]=0x0F;  /* max ciphertext buffer size */
    sout[6]=0xFF;
    sout[7]=0xFF;

    for (lup=0;lup<strlen(userid);lup++)
      sout[8+lup]=userid[lup];
    
    len=9+strlen(userid)-1;

    /* append 0 based octets so is multiple of 8 */
    while(len%8)
    {
      sout[len]=0;
      len++;
    }
    sout[len]=0;
    
    des_key_sched(text->session, text->init_keysched);
    des_pcbc_encrypt((unsigned char *)sout,
		     (unsigned char *)sout,
		     len, text->init_keysched, text->session, DES_ENCRYPT);

    *clientout = params->utils->malloc(len);
    memcpy((char *) *clientout, sout, len);

    *clientoutlen=len;

    /*nothing more to do; should be authenticated */
    oparams->doneflag=1;
    oparams->maxoutbuf=1024; /* no clue what this should be */

    oparams->user=userid;      /* set username */
    oparams->authid=userid;

    oparams->param_version=0;

    result = params->utils->getprop(params->utils->conn,
                          SASL_IP_LOCAL, (void **)&text->ip_local);
    if (result!=SASL_OK) return result;

    result = params->utils->getprop(params->utils->conn,
                          SASL_IP_REMOTE, (void **)&text->ip_remote);
    if (result!=SASL_OK) return result;

    text->size=-1;
    text->needsize=4;
    text->buffer=NULL;

    text->state++;

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "KERBEROS_V4",
    56, /* max ssf */
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
  if (maxversion<1)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=KERBEROS_VERSION;

  return SASL_OK;
}

