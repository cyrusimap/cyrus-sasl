/* SASL server API implementation
 * Tim Martin
 * $Id: client.c,v 1.2 1998/11/17 00:50:22 rob Exp $
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
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include "sasl.h"
#include "saslint.h"
#include "saslutil.h"
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
#include <string.h>

typedef struct cmechanism
{
  int version;
  const sasl_client_plug_t *plug;
  void *library;

  struct cmechanism *next;  
} cmechanism_t;

typedef struct sasl_client_conn {
  sasl_conn_t base; /* parts common to server + client */

  cmechanism_t *mech;
  sasl_client_params_t *cparams;

  char *serverFQDN;

} sasl_client_conn_t;

typedef struct cmech_list {
  sasl_utils_t *utils;  /* gotten from plug_init */

  void *mutex;            /* mutex for this data */ 
  cmechanism_t *mech_list; /* list of mechanisms */
  int mech_length;       /* number of mechanisms */

} cmech_list_t;


static cmech_list_t *cmechlist; /* global var which holds the list */

static sasl_global_callbacks_t global_callbacks;

static int init_mechlist()
{
  cmechlist->utils=_sasl_alloc_utils(NULL, &global_callbacks);
  if (cmechlist->utils==NULL)
    return SASL_NOMEM;

  return SASL_OK;
}

static void client_done(void) {
  cmechanism_t *cm;
  cmechanism_t *cprevm;

  cm=cmechlist->mech_list; /* m point to begging of the list */

  while (cm!=NULL)
  {
    cprevm=cm;
    cm=cm->next;
    if (cprevm->library!=NULL)
      _sasl_done_with_plugin(cprevm->library);
    sasl_FREE(cprevm);    
  }
  sasl_FREE(cmechlist->mutex);
  _sasl_free_utils(&cmechlist->utils);
  sasl_FREE(cmechlist);
}

static int add_plugin(void *p, void *library) {
  int plugcount;
  const sasl_client_plug_t *pluglist;
  cmechanism_t *mech;
  sasl_client_plug_init_t *entry_point;
  int result;
  int version;
  int lupe;

  entry_point = (sasl_client_plug_init_t *)p;

  result = entry_point(cmechlist->utils, SASL_CLIENT_PLUG_VERSION, &version,
		       &pluglist, &plugcount);
  if (version != SASL_CLIENT_PLUG_VERSION)
    result = SASL_FAIL;
  if (result != SASL_OK) return result;

  for (lupe=0;lupe< plugcount ;lupe++)
    {
      mech = sasl_ALLOC(sizeof(cmechanism_t));
      if (! mech) return SASL_NOMEM;

      mech->plug=pluglist++;
      if (lupe==0)
	mech->library = library;
      else
	mech->library = NULL;
      mech->version = version;
      mech->next = cmechlist->mech_list;
      cmechlist->mech_list = mech;
      cmechlist->mech_length++;
    }

  return SASL_OK;
}

static int
client_idle(sasl_conn_t *conn)
{
  cmechanism_t *m;
  if (! cmechlist)
    return 0;

  for (m = cmechlist->mech_list;
       m;
       m = m->next)
    if (m->plug->idle
	&&  m->plug->idle(m->plug->glob_context,
			  conn,
			  conn ? ((sasl_client_conn_t *)conn)->cparams : NULL))
      return 1;
  return 0;
}

int sasl_client_init(const sasl_callback_t *callbacks)
{
  int ret;

  _sasl_client_cleanup_hook = &client_done;
  _sasl_client_idle_hook = &client_idle;

  global_callbacks.callbacks = callbacks;
  global_callbacks.appname = NULL;

  cmechlist=sasl_ALLOC(sizeof(cmech_list_t));
  if (cmechlist==NULL) return SASL_NOMEM;

  /* create mutex*/
  cmechlist->mutex=sasl_MUTEX_NEW();

  /* load plugins */
  ret=init_mechlist();  
  if (ret!=SASL_OK)
    return ret;

  cmechlist->mech_list=NULL;
  cmechlist->mech_length=0;

  ret=_sasl_get_mech_list("sasl_client_plug_init",
			  &add_plugin);

  return ret;
}

static void client_dispose(sasl_conn_t *pconn)
{
  sasl_client_conn_t *c_conn=(sasl_client_conn_t *) pconn;

  if (c_conn->mech)
    c_conn->mech->plug->mech_dispose(c_conn->base.context,
				     c_conn->cparams->utils);

  _sasl_free_utils(&c_conn->cparams->utils);

  if (c_conn->serverFQDN!=NULL)
    sasl_FREE(c_conn->serverFQDN);

  sasl_FREE(c_conn->cparams);

  _sasl_conn_dispose(pconn);
}

int sasl_client_new(const char *service,
		    const char *serverFQDN,
		    const sasl_callback_t *prompt_supp,
		    int secflags,
		    sasl_conn_t **pconn)
{
  int result;
  sasl_client_conn_t *conn;
  if (! pconn) return SASL_FAIL;
  if (! service) return SASL_FAIL;
  if (! serverFQDN) return SASL_FAIL;

  *pconn=sasl_ALLOC(sizeof(sasl_client_conn_t));
  if (*pconn==NULL) return SASL_NOMEM;

  (*pconn)->destroy_conn = &client_dispose;
  result = _sasl_conn_init(*pconn, service, secflags,
			   &client_idle, prompt_supp, &global_callbacks);
  if (result != SASL_OK) return result;

  conn = (sasl_client_conn_t *)*pconn;

  conn->mech = NULL;

  conn->cparams=sasl_ALLOC(sizeof(sasl_client_params_t));
  if (conn->cparams==NULL) return SASL_NOMEM;

  conn->cparams->utils=_sasl_alloc_utils(*pconn, &global_callbacks);
  if (conn->cparams->utils==NULL)
    return SASL_NOMEM;

  conn->cparams->utils->conn= *pconn;

  result = _sasl_strdup(serverFQDN, &conn->serverFQDN, NULL);
  if (result != SASL_OK) goto cleanup_conn;

  return result;

cleanup_conn:
  _sasl_conn_dispose(*pconn);
  sasl_FREE(*pconn);
  *pconn = NULL;
  return result;
}

int sasl_client_start(sasl_conn_t *conn,
		      const char *list,
		      sasl_secret_t *secret,
		      sasl_interact_t **prompt_need,
		      char **clientout,
		      unsigned *clientoutlen,
		      const char **mech)
{
  sasl_client_conn_t *c_conn= (sasl_client_conn_t *) conn;
  char name[SASL_MECHNAMEMAX + 1];
  cmechanism_t *m=NULL,*bestm=NULL;
  size_t pos=0,place;
  size_t list_len;
  sasl_ssf_t bestssf=0,
             minssf=0;

  if (name==NULL)
    return SASL_NOMEM;

  /* if prompt_need != NULL we've already been here
     and just need to do the continue step again */
   /* do a step */
  if (*prompt_need!=NULL)
      return c_conn->mech->plug->mech_step(conn->context,
					   c_conn->cparams,
					   NULL,
					   0,
					   prompt_need,
					   clientout, (int *) clientoutlen,
					   conn->oparams);


  /* set secret */
  conn->secret=secret;

  /* Get app's desired sec props */
  minssf=conn->props.min_ssf;

  /* parse mechlist */
  list_len = strlen(list);
  while (pos<list_len)
  {
    place=0;
    while ((pos<list_len) && (isalnum((unsigned char)list[pos])
			      || list[pos] == '_'
			      || list[pos] == '-'))
    {
      name[place]=list[pos];
      pos++;
      place++;
      if (SASL_MECHNAMEMAX <= place) {
	place--;
	while(pos<list_len && (isalnum((unsigned char)list[pos])
			       || list[pos] == '_'
			       || list[pos] == '-'))
	  pos++;
      }
    }
    pos++;
    name[place]=0;

    if (! place) continue;


    /* foreach in server list */
    m=cmechlist->mech_list;
    while (m!=NULL)
    {
      VL(("%s %s\n",name, m->plug->mech_name));
      if (strcasecmp(m->plug->mech_name, name)==0)
      {	
	if (mech
	    && (! bestm || m->plug->max_ssf > bestssf)
	    && m->plug->max_ssf >= minssf)
	{
	  *mech=m->plug->mech_name;
	  bestssf=m->plug->max_ssf;
	  bestm=m;
	}
      }
      m=m->next;      
    }
  }

  if (bestm == NULL)
    return SASL_NOMECH;

  /* make cparams */
  
  c_conn->cparams->serverFQDN=c_conn->serverFQDN; 
  c_conn->cparams->service=conn->service;

  c_conn->cparams->external_ssf=conn->ssf;
  c_conn->cparams->props=conn->props;

  c_conn->mech=bestm;

    /* init that plugin */
  c_conn->mech->plug->mech_new(NULL,
			       c_conn->cparams,
			       &(conn->context));


  conn->oparams=sasl_ALLOC(sizeof(sasl_out_params_t));
  if (conn->oparams==NULL) return SASL_NOMEM;
  memset(conn->oparams, 0, sizeof(sasl_out_params_t));

    /* do a step */
  return c_conn->mech->plug->mech_step(conn->context,
				    c_conn->cparams,
				    NULL,
				    0,
				    prompt_need,
				    clientout, (int *) clientoutlen,
				    conn->oparams);
}


int sasl_client_step(sasl_conn_t *conn,
		     const char *serverin,
		     unsigned serverinlen,
		     sasl_interact_t **prompt_need,
		     char **clientout,
		     unsigned *clientoutlen)
{
  sasl_client_conn_t *c_conn= (sasl_client_conn_t *) conn;
  /* do a step */
   return c_conn->mech->plug->mech_step(conn->context,
				    c_conn->cparams,
				    serverin,
				    serverinlen,
				    prompt_need,
				    clientout, (int *)clientoutlen,
				    conn->oparams);
}


int sasl_client_auth(sasl_conn_t *conn,
		     const char *user,
		     const char *pass, unsigned passlen,
		     sasl_interact_t *prompts, sasl_secret_t **keepcopy)
{
  return SASL_OK;
}

void sasl_free_secret(sasl_secret_t **secret)
{
  size_t lup;

  if (secret==NULL) return;
  if (*secret==NULL) return;

  /* overwrite the memory */
  for (lup=0;lup<(*secret)->len;lup++)
    (*secret)->data[lup]='X';

  sasl_FREE(*secret);

  *secret=NULL;
}

