/* canonusr.c - user canonicalization support
 * Rob Siemborski
 * $Id: canonusr.c,v 1.3 2001/12/06 18:12:16 rjs3 Exp $
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
#include <sasl.h>
#include <string.h>
#include <ctype.h>
#include <prop.h>
#include <stdio.h>

#include "saslint.h"

typedef struct canonuser_plug_list 
{
    struct canonuser_plug_list *next;
    char name[PATH_MAX];
    const sasl_canonuser_plug_t *plug;
} canonuser_plug_list_t;

static canonuser_plug_list_t *canonuser_head = NULL;

/* default behavior:
 *                   eliminate leading & trailing whitespace,
 *                   null-terminate, and get into the outparams
 *
 *                   (handled by INTERNAL plugin) */
/* Also does auxprop lookups once username is canonoicalized */
/* a zero ulen or alen indicates that it is strlen(value) */
int _sasl_canon_user(sasl_conn_t *conn,
                     const char *user, unsigned ulen,
                     const char *authid, unsigned alen,
                     unsigned flags,
                     sasl_out_params_t *oparams)
{
    canonuser_plug_list_t *ptr;
    sasl_server_conn_t *sconn = NULL;
    sasl_client_conn_t *cconn = NULL;
    sasl_canon_user_t *cuser_cb;
    sasl_getopt_t *getopt;
    void *context;
    int result;
    const char *plugin_name = NULL;

    if(!conn) return SASL_BADPARAM;    
    if(!user || !authid || !oparams) return SASL_BADPARAM;

    if(conn->type == SASL_CONN_SERVER) sconn = (sasl_server_conn_t *)conn;
    else if(conn->type == SASL_CONN_CLIENT) cconn = (sasl_client_conn_t *)conn;
    else return SASL_FAIL;
    
    if(!ulen) ulen = strlen(user);
    if(!alen) alen = strlen(authid);
    
    /* check to see if we have a callback to make*/
    result = _sasl_getcallback(conn, SASL_CB_CANON_USER,
			       &cuser_cb, &context);
    if(result == SASL_OK && cuser_cb) {
	result = cuser_cb(conn, context,
			user, ulen, authid, alen,
			flags, (conn->type == SASL_CONN_SERVER ?
				((sasl_server_conn_t *)conn)->user_realm :
				NULL),
			conn->user_buf, CANON_BUF_SIZE, &ulen,
			conn->authid_buf, CANON_BUF_SIZE, &alen);

	if (result != SASL_OK) return result;

	/* Point the inputs at the new copies */
	user = conn->user_buf;
	authid = conn->authid_buf;
    }

    /* which plugin are we supposed to use? */
    result = _sasl_getcallback(conn, SASL_CB_GETOPT,
			       &getopt, &context);
    if(result == SASL_OK && getopt) {
	getopt(context, NULL, "canon_user_plugin", &plugin_name, NULL);
    }

    if(!plugin_name) {
	/* Use Defualt */
	plugin_name = "INTERNAL";
    }
    
    for(ptr = canonuser_head; ptr; ptr = ptr->next) {
	if(!strcmp(plugin_name, ptr->name)) break;
    }

    /* We clearly don't have this one! */
    if(!ptr) {
	sasl_seterror(conn, 0, "desired canon_user plugin %s not found",
		      plugin_name);
	return SASL_NOMECH;
    }
    
    
    if(sconn) {
	/* we're a server */
	result = ptr->plug->canon_user_server(ptr->plug->glob_context,
					      sconn->sparams,
					      user, ulen,
					      authid, alen,
					      flags,
					      conn->user_buf,
					      CANON_BUF_SIZE, &ulen,
					      conn->authid_buf,
					      CANON_BUF_SIZE, &alen);
    } else {
	/* we're a client */
	result = ptr->plug->canon_user_client(ptr->plug->glob_context,
					      cconn->cparams,
					      user, ulen,
					      authid, alen,
					      flags,
					      conn->user_buf,
					      CANON_BUF_SIZE, &ulen,
					      conn->authid_buf,
					      CANON_BUF_SIZE, &alen);
    }

    if(result != SASL_OK) return result;
	
    oparams->user = conn->user_buf;
    oparams->ulen = ulen;
    oparams->authid = conn->authid_buf;
    oparams->alen = alen;

#ifndef macintosh
    /* finally, do auxprop lookups (server only) */
    if(sconn) {
	_sasl_auxprop_lookup(sconn->sparams, 0,
			     oparams->authid, oparams->alen);
    }
#endif

    RETURN(conn, SASL_OK);
}

void _sasl_canonuser_free() 
{
    canonuser_plug_list_t *ptr, *ptr_next;
    
    for(ptr = canonuser_head; ptr; ptr = ptr_next) {
	ptr_next = ptr->next;
	if(ptr->plug->canon_user_free)
	    ptr->plug->canon_user_free(ptr->plug->glob_context,
				       sasl_global_utils);
	sasl_FREE(ptr);
    }

    canonuser_head = NULL;
}

int sasl_canonuser_add_plugin(const char *plugname,
			      sasl_canonuser_init_t *canonuserfunc) 
{
    int result, out_version;
    canonuser_plug_list_t *new_item;
    sasl_canonuser_plug_t *plug;

    if(!plugname || strlen(plugname) > (PATH_MAX - 1)) {
	sasl_seterror(NULL, 0,
		      "bad plugname passed to sasl_canonuser_add_plugin\n");
	return SASL_BADPARAM;
    }
    
    result = canonuserfunc(sasl_global_utils, SASL_AUXPROP_PLUG_VERSION,
			   &out_version, &plug, plugname);

    if(result != SASL_OK) {
	_sasl_log(NULL, SASL_LOG_ERR, "canonuserfunc error %i\n",result);
	return result;
    }

    if(!plug->canon_user_server && !plug->canon_user_client) {
	/* We need atleast one of these implemented */
	_sasl_log(NULL, SASL_LOG_ERR,
		  "canonuser plugin without either client or server side");
	return SASL_BADPROT;
    }
    
    new_item = sasl_ALLOC(sizeof(canonuser_plug_list_t));
    if(!new_item) return SASL_NOMEM;

    strncpy(new_item->name, plugname, PATH_MAX);

    new_item->plug = plug;
    new_item->next = canonuser_head;
    canonuser_head = new_item;

    return SASL_OK;
}

#ifdef MIN
#undef MIN
#endif
#define MIN(a,b) (((a) < (b))? (a):(b))

static int _canonuser_internal(const sasl_utils_t *utils,
			       const char *user, unsigned ulen,
			       const char *authid, unsigned alen,
			       unsigned flags __attribute__((unused)),
			       char *out_user,
			       unsigned out_umax, unsigned *out_ulen,
			       char *out_authid,
			       unsigned out_amax, unsigned *out_alen) 
{
    unsigned i;
    char *in_buf, *userin, *authidin;
    const char *begin_u, *begin_a;
    unsigned u_apprealm = 0, a_apprealm = 0;
    sasl_server_conn_t *sconn = NULL;

    if(!utils || !user || !authid) return SASL_BADPARAM;

    in_buf = sasl_ALLOC((ulen + alen + 2) * sizeof(char));
    if(!in_buf) return SASL_NOMEM;

    userin = in_buf;
    authidin = userin + ulen + 1;

    memcpy(userin, user, ulen);
    userin[ulen] = '\0';
    memcpy(authidin, authid, alen);
    authidin[alen] = '\0';
    
    /* Strip User ID */
    for(i=0;isspace((int)userin[i]) && i<ulen;i++);
    begin_u = &(userin[i]);
    if(i>0) ulen -= i;

    for(;isspace((int)begin_u[ulen-1]) && ulen > 0; ulen--);
    if(begin_u == &(userin[ulen])) {
	sasl_FREE(in_buf);
	utils->seterror(utils->conn, 0, "All-whitespace username.");
	return SASL_FAIL;
    }

    /* Strip Auth ID */
    for(i=0;isspace((int)authidin[i]) && i<alen;i++);
    begin_a = &(authidin[i]);
    if(i>0) alen -= i;

    for(;isspace((int)begin_a[alen-1]) && alen > 0; alen--);
    if(begin_a == &(authidin[alen])) {
	sasl_FREE(in_buf);
	utils->seterror(utils->conn, 0, "All-whitespace authid.");
	return SASL_FAIL;
    }

    if(utils->conn && utils->conn->type == SASL_CONN_SERVER)
	sconn = (sasl_server_conn_t *)utils->conn;

    /* Need to append realm if necessary (see sasl.h) */
    if(sconn && sconn->user_realm && !strchr(user, '@')) {
	u_apprealm = strlen(sconn->user_realm) + 1;
    }
    if(sconn && sconn->user_realm && !strchr(authid, '@')) {
	a_apprealm = strlen(sconn->user_realm) + 1;
    }
    
    /* Now copy! (FIXME: check for SASL_BUFOVER?) */
    memcpy(out_user, begin_u, MIN(ulen, out_umax));
    if(u_apprealm) {
	out_user[ulen] = '@';
	memcpy(&(out_user[ulen+1]), sconn->user_realm,
	       MIN(u_apprealm-1, out_umax-ulen-1));
    }
    out_user[MIN(ulen + u_apprealm,out_umax)] = '\0';

    if(out_ulen) *out_ulen = MIN(ulen + u_apprealm,out_umax);
    
    memcpy(out_authid, begin_a, MIN(alen, out_amax));
    if(a_apprealm) {
	out_authid[alen] = '@';
	memcpy(&(out_authid[alen+1]), sconn->user_realm,
	       MIN(a_apprealm-1, out_amax-ulen-1));
    }
    out_authid[MIN(alen + a_apprealm, out_amax)] = '\0';

    if(out_alen) *out_alen = MIN(alen + a_apprealm, out_amax);

    sasl_FREE(in_buf);
    return SASL_OK;
}

static int _cu_internal_server(void *glob_context __attribute__((unused)),
			       sasl_server_params_t *sparams,
			       const char *user, unsigned ulen,
			       const char *authid, unsigned alen,
			       unsigned flags,
			       char *out_user,
			       unsigned out_umax, unsigned *out_ulen,
			       char *out_authid,
			       unsigned out_amax, unsigned *out_alen) 
{
    return _canonuser_internal(sparams->utils,
			       user, ulen, authid, alen,
			       flags, out_user, out_umax, out_ulen,
			       out_authid, out_amax, out_alen);
}

static int _cu_internal_client(void *glob_context __attribute__((unused)),
			       sasl_client_params_t *cparams,
			       const char *user, unsigned ulen,
			       const char *authid, unsigned alen,
			       unsigned flags,
			       char *out_user,
			       unsigned out_umax, unsigned *out_ulen,
			       char *out_authid,
			       unsigned out_amax, unsigned *out_alen) 
{
    return _canonuser_internal(cparams->utils,
			       user, ulen, authid, alen,
			       flags, out_user, out_umax, out_ulen,
			       out_authid, out_amax, out_alen);
}

static sasl_canonuser_plug_t canonuser_internal_plugin = {
        0, /* features */
	0, /* spare */
	NULL, /* glob_context */
	"INTERNAL", /* spare */
	NULL, /* canon_user_free */
	_cu_internal_server,
	_cu_internal_client,
	NULL,
	NULL,
	NULL
};

int internal_canonuser_init(const sasl_utils_t *utils __attribute__((unused)),
                            int max_version,
                            int *out_version,
                            sasl_canonuser_plug_t **plug,
                            const char *plugname __attribute__((unused))) 
{
    if(!out_version || !plug) return SASL_BADPARAM;

    if(max_version < SASL_CANONUSER_PLUG_VERSION) return SASL_BADVERS;
    
    *out_version = SASL_CANONUSER_PLUG_VERSION;

    *plug = &canonuser_internal_plugin;

    return SASL_OK;
}
