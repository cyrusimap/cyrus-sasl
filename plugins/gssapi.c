/* GSSAPI SASL plugin
 * Leif Johansson
 */
/*****************************************************************
        Copyright 1998 by Stockholm University 
            and Carnegie Mellon University

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
#include <string.h>
#include <gssapi.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>

/* GSSAPI SASL Mechanism by Leif Johansson <leifj@matematik.su.se>
 * inspired by the kerberos mechanism and the gssapi_server and
 * gssapi_client from the heimdal distribution by Assar Westerlund
 * <assar@sics.se> and Johan Danielsson <joda@pdc.kth.se>. This
 * code has not been tested with the MIT implementation of gssapi
 * but it should work. See the configure.in file for details.
 * Heimdal can be obtained from http://www.pdc.kth.se/heimdal
 */

#define GSSAPI_VERSION 2

typedef struct context {
  int state;
  
  gss_ctx_id_t gss_ctx;
  gss_name_t   client_name;
  gss_name_t   server_name;
  
  sasl_ssf_t ssf; /* security layer type */

  sasl_malloc_t *malloc;
  sasl_free_t *free;
  
} context_t;

#define SASL_GSSAPI_STATE_AUTHNEG 1
#define SASL_GSSAPI_STATE_SSFCAP  2
#define SASL_GSSAPI_STATE_SSFREQ  3
#define SASL_GSSAPI_STATE_AUTHENTICATED    4

static int 
sasl_gss_encode(void *context, const char *input, unsigned inputlen,
		char **output, unsigned *outputlen, int privacy)
{
  context_t *text = (context_t *)context;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_t input_token, output_token;
  gss_buffer_desc real_input_token, real_output_token;

  if (text->state != SASL_GSSAPI_STATE_AUTHENTICATED)
    return SASL_FAIL;
  
  input_token = &real_input_token; 
  real_input_token.value  = (char *)input;
  real_input_token.length = inputlen;
  
  output_token = &real_output_token;
  input_token->value = NULL;

  maj_stat = gss_wrap (&min_stat,
		       text->gss_ctx,
		       privacy, /* Just integrity checking here */
		       GSS_C_QOP_DEFAULT,
		       input_token,
		       NULL,
		       output_token);
  
  if (GSS_ERROR(maj_stat))
    {
      if (output_token->value)
	text->free(output_token->value);
      return SASL_FAIL;
    }

  if (output_token->value && output)
    *output = output_token->value;
  if (outputlen)
    *outputlen = output_token->length;
  
  return SASL_OK;
}

static int
sasl_gss_privacy_encode(void *context, const char *input, unsigned inputlen,
		char **output, unsigned *outputlen)
{
  return sasl_gss_encode(context,input,inputlen,output,outputlen,1);
}


static int
sasl_gss_integrity_encode(void *context, const char *input, unsigned inputlen,
			  char **output, unsigned *outputlen)
{
  return sasl_gss_encode(context,input,inputlen,output,outputlen,0);
}

static int 
sasl_gss_decode(void *context, const char *input, unsigned inputlen,
		char **output, unsigned *outputlen)
{
  context_t *text = (context_t *)context;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_t input_token, output_token;
  gss_buffer_desc real_input_token, real_output_token;

  if (text->state != SASL_GSSAPI_STATE_AUTHENTICATED)
    return SASL_FAIL;
  
  input_token = &real_input_token; 
  real_input_token.value = (char *)input;
  real_input_token.length = inputlen;
  
  output_token = &real_output_token;
  input_token->value = NULL;
  
  maj_stat = gss_unwrap (&min_stat,
			 text->gss_ctx,
			 input_token,
			 output_token,
			 NULL,
			 NULL);
    
  if (GSS_ERROR(maj_stat))
    {
      if (output_token->value)
	text->free(output_token->value);
      return SASL_FAIL;
    }

  if (output_token->value && output)
    *output = output_token->value;
  if (outputlen)
    *outputlen = output_token->length;
  
  return SASL_OK;
}

static int 
sasl_gss_server_start(void *glob_context, 
		      sasl_server_params_t *sparams,
		      const char *challenge, int challen,
		      void **conn,
		      const char **errstr)
{
  context_t *text;
  
  text = sparams->utils->malloc(sizeof(context_t));
  if (text == NULL) 
    return SASL_NOMEM;
  memset(text,0,sizeof(context_t));
  text->malloc = sparams->utils->malloc;
  text->free = sparams->utils->free;
  text->gss_ctx = GSS_C_NO_CONTEXT;
  text->client_name = GSS_C_NO_NAME;
  text->server_name = GSS_C_NO_NAME;
  text->state = SASL_GSSAPI_STATE_AUTHNEG;

  *conn = text;

  return SASL_OK;
}

static void 
sasl_gss_free_context_contents(context_t *text)
{
  OM_uint32 maj_stat, min_stat;
  
  if (text->gss_ctx != GSS_C_NO_CONTEXT)
    maj_stat = gss_delete_sec_context (&min_stat,&text->gss_ctx,GSS_C_NO_BUFFER);
  
  if (text->client_name != GSS_C_NO_NAME)
    maj_stat = gss_release_name(&min_stat,&text->client_name);

  if (text->server_name != GSS_C_NO_NAME)
    maj_stat = gss_release_name(&min_stat,&text->server_name);
}

static void 
sasl_gss_dispose(void *conn_context, sasl_utils_t *utils)
{
  sasl_gss_free_context_contents((context_t *)conn_context);
  utils->free(conn_context);
}

static void 
sasl_gss_free(void *global_context, sasl_utils_t *utils)
{
  utils->free(global_context);
}

static int 
sasl_gss_server_step (void *conn_context,
		      sasl_server_params_t *sparams,
		      const char *clientin,
		      int clientinlen,
		      char **serverout,
		      int *serveroutlen,
		      sasl_out_params_t *oparams,
		      const char **errstr)
{
  context_t *text = (context_t *)conn_context;
  gss_buffer_t input_token, output_token;
  gss_buffer_desc real_input_token, real_output_token;
  OM_uint32 maj_stat, min_stat;
  
  input_token = &real_input_token;
  output_token = &real_output_token;
  output_token->value = NULL;
  input_token->value = NULL;
  
  switch (text->state)
    {
    case SASL_GSSAPI_STATE_AUTHNEG:
      real_input_token.value = (void *)clientin;
      real_input_token.length = clientinlen;
      
      maj_stat =
	gss_accept_sec_context (&min_stat,
				&(text->gss_ctx),
				GSS_C_NO_CREDENTIAL,
				input_token,
				GSS_C_NO_CHANNEL_BINDINGS,
				&text->client_name,
				NULL,
				output_token,
				NULL,
				NULL,
				NULL);

      if (GSS_ERROR(maj_stat))
	{
	  if (output_token->value)
	    text->free(output_token->value);
	  sasl_gss_free_context_contents(text);
	  return SASL_FAIL;
	}
      
      if (serverout && output_token->length)
	*serverout = output_token->value;
      if (*serveroutlen)
	*serveroutlen = output_token->length;
      
      if (maj_stat & GSS_S_COMPLETE)
	text->state = SASL_GSSAPI_STATE_SSFCAP; /* Switch to ssf negotiation */
      
      return(SASL_CONTINUE);
      break;
    case SASL_GSSAPI_STATE_SSFCAP:
      {
	unsigned char sasldata[4];
	gss_buffer_desc name_token;
	
	name_token.value = NULL;
	
	/* We ignore whatever the client sent us at this stage */
	
	maj_stat = gss_display_name (&min_stat,
				     text->client_name,
				     &name_token,
				     NULL);

	if (GSS_ERROR(maj_stat))
	  {
	    if (name_token.value)
	      text->free(name_token.value);
	    sasl_gss_free_context_contents(text);
	    return SASL_BADAUTH;
	  }

	oparams->user = (char *)name_token.value;

	sasldata[0] = 1 | 2 | 4;
	sasldata[1] = 0x0F; /* XXX use something non-artificial */
	sasldata[2] = 0xFF;
	sasldata[3] = 0xFF;
	
	real_input_token.value = (void *)sasldata;
	real_input_token.length = 4;
	
	maj_stat = gss_wrap (&min_stat,
			     text->gss_ctx,
			     0, /* Just integrity checking here */
			     GSS_C_QOP_DEFAULT,
			     input_token,
			     NULL,
			     output_token);
	
	if (GSS_ERROR(maj_stat))
	  {
	    if (output_token->value)
	      text->free(output_token->value);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	  }
	
	if (serverout && output_token->length)
	  *serverout = output_token->value;
	if (*serveroutlen)
	  *serveroutlen = output_token->length;
	
	text->state = SASL_GSSAPI_STATE_SSFREQ; /* Wait for ssf request and authid */
	
	return SASL_CONTINUE;
	
	break;
      }
    case SASL_GSSAPI_STATE_SSFREQ:
      {
	real_input_token.value = (void *)clientin;
	real_input_token.length = clientinlen;
	
	maj_stat = gss_unwrap (&min_stat,
			       text->gss_ctx,
			       input_token,
			       output_token,
			       NULL,
			       NULL);
	
	if (GSS_ERROR(maj_stat))
	  {
	    if (output_token->value)
	      text->free(output_token->value);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	  }
	
	text->ssf = (int)(((char *)(output_token->value))[0]);
	if (text->ssf==1)  /* no encryption */
	  {
	    oparams->encode=NULL;
	    oparams->decode=NULL;
	    oparams->mech_ssf=0;
	    text->ssf=1;
	  } else if (text->ssf==2) { /* integrity */
	    oparams->encode=&sasl_gss_integrity_encode;
	    oparams->decode=&sasl_gss_decode;
	    oparams->mech_ssf=1;
	    text->ssf=2;
	  } else if (text->ssf==4) { /* privacy */
	    oparams->encode=&sasl_gss_privacy_encode;
	    oparams->decode=&sasl_gss_decode;
	    oparams->mech_ssf=56;
	    text->ssf=4;
	  } else {
	    /* not a supported encryption layer */
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	  }
	
	if (output_token->length > 4)
	  {
	    char *authid = (char *)(*text->malloc)( (output_token->length - 3) * sizeof(char));
	    
	    if (authid == NULL)
	      {
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	      }
	    
	    memcpy(authid,((char *)real_output_token.value)+4,output_token->length - 4);
	    *(authid + output_token->length - 3) = '\0';
	    
	    memcpy(&oparams->maxoutbuf,((char *)real_output_token.value)+1,sizeof(unsigned));
	    oparams->maxoutbuf = ntohl(oparams->maxoutbuf);
	    oparams->authid = authid;
	  }
	
	text->free(output_token->value);
	/* XXX Must check for authorization here! */
	
	text->state = SASL_GSSAPI_STATE_AUTHENTICATED;
	
	return SASL_OK;
	break;
      }
    }
  /* This should not happen */
  sasl_gss_free_context_contents(text);
  return SASL_FAIL;
}

const sasl_server_plug_t plugins[] = 
{
  {
    "GSSAPI",
    56, /* max ssf */
    0,
    NULL,
    &sasl_gss_server_start,
    &sasl_gss_server_step,
    &sasl_gss_dispose,
    &sasl_gss_free,
    NULL,
    NULL,
    NULL
  }
};


int 
sasl_server_plug_init(sasl_utils_t *utils, int maxversion,
		      int *out_version,
		      const sasl_server_plug_t **pluglist,
		      int *plugcount)
{
  if (maxversion<1)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=GSSAPI_VERSION;

  return SASL_OK;
}

static int 
sasl_gss_client_start(void *glob_context, 
		      sasl_client_params_t *params,
		      void **conn)
{
  context_t *text;

  /* holds state are in */
  text = params->utils->malloc(sizeof(context_t));
  if (text == NULL) 
    return SASL_NOMEM;
  memset(text,0,sizeof(context_t));
  text->malloc = params->utils->malloc;
  text->free = params->utils->free;
  text->state = SASL_GSSAPI_STATE_AUTHNEG;
  text->gss_ctx = GSS_C_NO_CONTEXT;
  text->client_name = GSS_C_NO_NAME;
  *conn = text;

  return SASL_OK;
}

static int 
sasl_gss_client_step (void *conn_context,
		      sasl_client_params_t *params,
		      const char *serverin,
		      int serverinlen,
		      sasl_interact_t **prompt_need,
		      char **clientout,
		      int *clientoutlen,
		      sasl_out_params_t *oparams)
{
  context_t *text = (context_t *)conn_context;
  gss_buffer_t input_token, output_token;
  gss_buffer_desc real_input_token, real_output_token;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc name_token;
  
  input_token = &real_input_token;
  output_token = &real_output_token;
  output_token->value = NULL;
  input_token->value = NULL;

  switch (text->state)
    {
    case SASL_GSSAPI_STATE_AUTHNEG:
      {
	if (text->server_name == GSS_C_NO_NAME) /* only once */
	  {
	    name_token.length = strlen(params->service) + 1 + strlen(params->serverFQDN);
	    name_token.value = (char *)text->malloc((name_token.length + 1) * sizeof(char));
	    if (name_token.value == NULL)
	      {
		sasl_gss_free_context_contents(text);
		return SASL_NOMEM;
	      }
	    sprintf(name_token.value,"%s@%s", params->service, params->serverFQDN);
	    
	    maj_stat = gss_import_name (&min_stat,
					&name_token,
					GSS_C_NT_HOSTBASED_SERVICE,
					&text->server_name);
	    
	    text->free(name_token.value);
	    
	    if (GSS_ERROR(maj_stat))
	      {
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	      }
	  }
	
	if (serverinlen)
	  {
	    real_input_token.value = (void *)serverin;
	    real_input_token.length = serverinlen;
	  }
	
	maj_stat =
	  gss_init_sec_context(&min_stat,
			       GSS_C_NO_CREDENTIAL,
			       &text->gss_ctx,
			       text->server_name,
			       GSS_C_NO_OID,
			       GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG,
			       0,
			       GSS_C_NO_CHANNEL_BINDINGS,
			       input_token,
			       NULL,
			       output_token,
			       NULL,
			       NULL);
	
	if (GSS_ERROR(maj_stat))
	  {
	    if (output_token->value)
	      text->free(output_token->value);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	  }
	
	if (clientout && output_token->length)
	  *clientout = output_token->value;
	if (*clientoutlen)
	  *clientoutlen = output_token->length;
	
	if (maj_stat & GSS_S_COMPLETE)
	  text->state = SASL_GSSAPI_STATE_SSFCAP; /* Switch to ssf negotiation */
	break;
      }
    case SASL_GSSAPI_STATE_SSFCAP:
      {
	sasl_security_properties_t secprops = params->props;
	int external = params->external_ssf;
	
	if (serverinlen)
	  {
	    real_input_token.value = (void *)serverin;
	    real_input_token.length = serverinlen;
	  }
	
	maj_stat = gss_unwrap (&min_stat,
			       text->gss_ctx,
			       input_token,
			       output_token,
			       NULL,
			       NULL);
	
	if (GSS_ERROR(maj_stat))
	  {
	    if (output_token->value)
	      text->free(output_token->value);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	  }
	
	/* taken from kerberos.c */
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
	    oparams->encode=&sasl_gss_privacy_encode;
	    oparams->decode=&sasl_gss_decode;
	    oparams->mech_ssf=56;
	    text->ssf=4;
	    VL (("Using encryption layer\n"));
	  } else if ((secprops.min_ssf<=1+external) && (secprops.max_ssf>=1+external)) {
	    /* integrity */
	    oparams->encode=&sasl_gss_integrity_encode;
	    oparams->decode=&sasl_gss_decode;
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
	    sasl_gss_free_context_contents(text);
	    return SASL_TOOWEAK;
	  }

	/* server told me what layers support. make sure trying one it supports */
	if ( (((char *)output_token->value)[0] & text->ssf) == 0 )
	  {
	    sasl_gss_free_context_contents(text);
	    return SASL_WRONGMECH;
	  }
	
	text->free(output_token->value);
	output_token->value = NULL;
	
	maj_stat = gss_display_name (&min_stat,
				     text->client_name,
				     &name_token,
				     NULL);
	

	input_token->value = text->malloc( (4 + name_token.length + 1) * sizeof(char) );
	if (input_token->value == NULL)
	  {
	    sasl_gss_free_context_contents(text);
	    return SASL_NOMEM;
	  }
	
	((unsigned char *)input_token->value)[0] = text->ssf;
	oparams->maxoutbuf = 1024; /* XXX do something real here */
	((unsigned char *)input_token->value)[1] = 0x0F;
	((unsigned char *)input_token->value)[2] = 0xFF;
	((unsigned char *)input_token->value)[3] = 0xFF;
	memcpy((char *)input_token->value+4,(char *)name_token.value,name_token.length);
	*((char *)input_token->value + 4 + name_token.length) = '\0';
	
	maj_stat = gss_wrap (&min_stat,
			     text->gss_ctx,
			     0, /* Just integrity checking here */
			     GSS_C_QOP_DEFAULT,
			     input_token,
			     NULL,
			     output_token);
	
	text->free(input_token->value);
	
	if (GSS_ERROR(maj_stat))
	  {
	    if (output_token->value)
	      text->free(output_token->value);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	  }
	
	if (clientout && output_token->length)
	  *clientout = output_token->value;
	if (*clientoutlen)
	  *clientoutlen = output_token->length;
	
	text->state = SASL_GSSAPI_STATE_AUTHENTICATED;
	
	return SASL_OK;
	
	break;
	
      }
    }
  /* This should not happen */
  sasl_gss_free_context_contents(text);
  return SASL_FAIL;
}

const sasl_client_plug_t client_plugins[] = 
{
  {
    "GSSAPI",
    56, /* max ssf */
    0,
    NULL,
    NULL,
    &sasl_gss_client_start,
    &sasl_gss_client_step,
    &sasl_gss_dispose,
    &sasl_gss_free,
    NULL,
    NULL
  }
};

int 
sasl_client_plug_init(sasl_utils_t *utils, int maxversion,
		      int *out_version, const sasl_client_plug_t **pluglist,
		      int *plugcount)
{
  if (maxversion<1)
    return SASL_BADVERS;
  
  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=GSSAPI_VERSION;

  return SASL_OK;
}
