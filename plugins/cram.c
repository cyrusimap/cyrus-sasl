/* CRAM-MD5 SASL plugin
 * Tim Martin 
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
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sasl.h>
#include <saslplug.h>
#include <saslutil.h>

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslCRAM.h"
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#define CRAM_MD5_VERSION (3)

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (1)
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

  char *authid;
  sasl_secret_t *password;

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


static void free_secret(sasl_utils_t *utils,
			sasl_secret_t **secret)
{
  size_t lup;

  VL(("Freeing secret\n"));

  if (secret==NULL) return;
  if (*secret==NULL) return;

  /* overwrite the memory */
  for (lup=0;lup<(*secret)->len;lup++)
    (*secret)->data[lup]='X';

  (*secret)->len=0;

  utils->free(*secret);

  *secret=NULL;
}

static void free_string(sasl_utils_t *utils,
			char **str)
{
  size_t lup;
  size_t len;
  VL(("Freeing string\n"));

  if (str==NULL) return;
  if (*str==NULL) return;

  len=strlen(*str);

  /* overwrite the memory */
  for (lup=0;lup<len;lup++)
    (*str)[lup]='\0';

  utils->free(*str);

  *str=NULL;
}

static void dispose(void *conn_context, sasl_utils_t *utils)
{
  context_t *text;
  text=conn_context;

  /* get rid of all sensetive info */
  free_string(utils,&(text->msgid));
  free_string(utils,&(text->authid));
  free_secret(utils,&(text->password));

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

/*
 * Returns the current time (or part of it) in string form
 *  maximum length=15
 */

static char *gettime(sasl_server_params_t *sparams)
{
  char *ret;
  time_t t;

  t=time(NULL);
  ret= sparams->utils->malloc(15);
  if (ret==NULL) return NULL;
  
  /* the bottom bits are really the only random ones so if
     we overflow we don't want to loose them */
  snprintf(ret,15,"%lu",t%(0xFFFFFF));
  
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

static char *make_hashed(sasl_secret_t *sec, char *nonce, int noncelen, 
			 void *inparams)
{
  char secret[65];
  unsigned char digest[24];  
  int lup;
  char *in16;

  sasl_server_params_t *params=(sasl_server_params_t *) inparams;

  if (sec==NULL) return NULL;

  if (sec->len<64)
  {
    memcpy(secret, sec->data, sec->len);

    /* fill in rest with 0's */
    for (lup= sec->len ;lup<64;lup++)
      secret[lup]='\0';

  } else {
    memcpy(secret, sec->data, 64);
  }

  VL(("secret=[%s] %lu\n",secret,sec->len));
  VL(("nonce=[%s] %i\n",nonce, noncelen));

  /* do the hmac md5 hash output 128 bits */
  params->utils->hmac_md5((unsigned char *) nonce,noncelen,
			  (unsigned char *) secret,64,digest);

  /* convert that to hex form */
  in16=convert16(digest,16,params->utils);
  if (in16==NULL) return NULL;

  return in16;
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
    char *time, *randdigits;
    /* arbitrary string of random digits 
     * time stamp
     * primary host
     */
    VL(("CRAM-MD5 step 1\n"));

    /* get time and a random number for the nonce */
    time=gettime(sparams);
    randdigits=randomdigits(sparams);
    if ((time==NULL) || (randdigits==NULL)) return SASL_NOMEM;

    /* allocate some space for the nonce */
    *serverout=sparams->utils->malloc(200);
    if (*serverout==NULL) return SASL_NOMEM;

    /* create the nonce */
    snprintf((char *)*serverout,200,"<%s.%s@%s>",randdigits,time,
	    sparams->serverFQDN);

    /* free stuff */
    sparams->utils->free(time);    
    sparams->utils->free(randdigits);    
    
    *serveroutlen=strlen(*serverout);
    text->msgidlen=*serveroutlen;

    /* save nonce so we can check against it later */
    text->msgid=sparams->utils->malloc(*serveroutlen);
    if (text->msgid==NULL) return SASL_NOMEM;
    memcpy(text->msgid,*serverout,*serveroutlen);

    VL(("nonce=[%s]\n",text->msgid));

    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    /* verify digest */
    char *in16=NULL;
    char *userid=NULL;
    sasl_secret_t *sec=NULL;
    int lup,pos;
    int result;
    sasl_server_getsecret_t *getsecret;
    void *getsecret_context;

    VL(("CRAM-MD5 Step 2\n"));
    VL(("Clientin: %s\n",clientin));

    /* extract userid; everything before last space*/
    pos=clientinlen-1;
    while ((pos>0) && (clientin[pos]!=' '))
    {
      pos--;
    }
    if (pos==0)
    {
      VL(("There was no userid\n"));
      return SASL_FAIL;
    }

    /* allocate for userid */
    userid=(char *) sparams->utils->malloc(pos+1);
    if (userid==NULL) return SASL_NOMEM;

    /* copy userid out */
    for (lup=0;lup<pos;lup++)
      userid[lup]=clientin[lup];
    userid[lup]=0;

    /* get callback so we can request the secret */
    result = sparams->utils->getcallback(sparams->utils->conn,
					 SASL_CB_SERVER_GETSECRET,
					 &getsecret,
					 &getsecret_context);
    if (result != SASL_OK)
    {
      VL(("result = %i trying to get secret callback\n",result));
      return result;
    }
    if (! getsecret)
    {
      VL(("Received NULL getsecret callback\n"));
      return SASL_FAIL;
    }


    /* We use the user's SCRAM secret */
    /* Request secret */
    result = getsecret(getsecret_context, "CRAM-MD5", userid, &sec);
    if (result != SASL_OK)
    {
      VL(("userid=%s\n",userid));
      sparams->utils->free(userid);
      VL(("error %i in getsecret\n",result));
      return result;
    }

    if (! sec)
    {
      VL(("Received NULL sec from getsecret\n"));
      return SASL_FAIL;
    }
    
    VL(("password=[%s]\n",sec->data));

    /* create thing with password to check against */
    in16=make_hashed(sec,text->msgid ,text->msgidlen , sparams);
    if (in16==NULL)
    {
      VL(("make_hashed failed\n"));
      return SASL_FAIL;
    }
    /* XXX this needs to be safer */

    /* free sec */
    free_secret(sparams->utils,&sec);

    VL(("[%s] vs [%s]\n",in16,clientin+pos+1));

    /* if same then verified 
     *  - we know in16 is null terminated but clientin might not be
     */    
    if (strncmp(in16,clientin+pos+1,strlen(in16))!=0)
    {
      /* free string and wipe out sensetive data */
      free_string(sparams->utils,&in16);

      VL(("bad auth here\n"));
      return SASL_BADAUTH;
    }

    /* free string and wipe out sensetive data */
    free_string(sparams->utils,&in16);

    /* nothing more to do; authenticated 
     * set oparams information
     */
    oparams->doneflag=1;

    oparams->user=userid; /* set username */
    oparams->authid=userid;

    oparams->mech_ssf=0;

    oparams->maxoutbuf=1024; /* no clue what this should be */
  
    oparams->encode=NULL;
    oparams->decode=NULL;

    oparams->realm=NULL;
    oparams->param_version=0;

    *serverout = NULL;
    *serveroutlen = 0;

    text->state=3; /* if called again will fail */

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
  /* this saves cleartext password */
  sasl_secret_t *sec=(sasl_secret_t *) malloc(sizeof(sasl_secret_t)+passlen);
  
  sec->len=passlen;
  strcpy(sec->data,pass);


  if (errstr)
    *errstr = NULL;

  result = sparams->utils->getcallback(sparams->utils->conn,
				       SASL_CB_SERVER_PUTSECRET,
				       &putsecret,
				       &putsecret_context);
  if (result != SASL_OK)
    return result;

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
  result=putsecret(putsecret_context,
		   "CRAM-MD5",
		   user,
		   sec);

  /* clean up sensitive info */
  /* wish we could call free secret here */

  return result;
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "CRAM-MD5",
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

int sasl_server_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<CRAM_MD5_VERSION)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=CRAM_MD5_VERSION;

  return SASL_OK;
}


static int c_start(void *glob_context __attribute__((unused)), 
		 sasl_client_params_t *params,
		 void **conn)
{
  context_t *text;

  /* holds state are in */
    text= params->utils->malloc(sizeof(context_t));
    if (text==NULL) return SASL_NOMEM;
    text->state=1;  
    text->authid=NULL;
    text->password=NULL;

  *conn=text;

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
  sasl_interact_t *prompt;

  /* see if we were given the authname in the prompt */
  prompt=find_prompt(*prompt_need,SASL_CB_AUTHNAME);
  if (prompt!=NULL)
  {
    /* copy it */
    *authid=params->utils->malloc(strlen(prompt->result)+1);
    if ((*authid)==NULL) return SASL_NOMEM;

    strcpy(*authid, prompt->result);
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
			  (const char **)authid,
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


static int get_password(sasl_client_params_t *params,
		      sasl_secret_t **password,
		      sasl_interact_t **prompt_need)
{

  int result;
  sasl_getsecret_t *getpass_cb;
  void *getpass_context;
  sasl_interact_t *prompt;

  /* see if we were given the password in the prompt */
  prompt=find_prompt(*prompt_need,SASL_CB_PASS);
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

  oparams->mech_ssf=0;
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
    /*    unsigned char digest[1024];*/
    char *in16;
    int auth_result=SASL_OK;
    int pass_result=SASL_OK;
    int maxsize;

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
    free_prompts(params,*prompt_need);

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

    /* username
     * space
     * digest (keyed md5 where key is passwd)
     */

    in16=make_hashed(text->password,(char *) serverin, serverinlen, params);

    if (in16==NULL) return SASL_FAIL;

    VL(("authid=[%s]\n",text->authid));
    VL(("in16=[%s]\n",in16));

    maxsize=32+1+strlen(text->authid)+30;
    *clientout=params->utils->malloc(maxsize);
    if ((*clientout) == NULL) return SASL_NOMEM;

    snprintf((char *)*clientout,maxsize ,"%s %s",text->authid,in16);

    /* get rid of private information */
    free_string(params->utils, &in16);

    *clientoutlen=strlen(*clientout);

    /*nothing more to do; authenticated */
    oparams->doneflag=1;

    VL(("clientout looks like=%s %i\n",*clientout,*clientoutlen));

    text->state++; /* fail if called again */

    return SASL_OK;
  }

  return SASL_FAIL; /* should never get here */
}

static const long client_required_prompts[] = {
  SASL_CB_AUTHNAME,
  SASL_CB_PASS,
  SASL_CB_LIST_END
};

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "CRAM-MD5",
    0,
    0,
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

int sasl_client_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<CRAM_MD5_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;
  *plugcount=1;
  *out_version=CRAM_MD5_VERSION;

  return SASL_OK;
}
