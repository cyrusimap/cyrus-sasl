/*
    @copyright 2018-21, opaque@ctrlc.hu
    This file is part of the cyrus-sasl opaque mechansim.

    The cyrus-sasl opaque mechanism is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    The cyrus-sasl opaque mechanism is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with The cyrus-sasl opaque mechanism. If not, see <http://www.gnu.org/licenses/>.
*/

#include <opaque.h>
#include <string.h>
#include "plugin_common.h"

static const uint8_t OPAQUE_CONTEXT[]="SASL OPAQUE Mechanism";
static const size_t OPAQUE_CONTEXT_BYTES=sizeof OPAQUE_CONTEXT - 1;

static int get_idu_ids(const char** ids, unsigned short *idu_len, const char* user_realm, const char *serverFQDN, const char *input) {
  const char *ptr;
  // search for @ separating user from realm
  for(ptr = input;*ptr && ptr >= input;ptr++) {
    if(*ptr != '@') continue;
    if(*(ptr+1)==0) break; // '@\0'
    // found @ and it is not followed by a \0
    if(ptr-1-input > 65535) {
      return !SASL_OK; // username too big
    }
    if(ids) {
      *ids = ptr+1;
    }
    *idu_len=ptr-input;
    return SASL_OK;
  }

  if(ptr<input) {
    return !SASL_OK; // ptr overflow
  }

  if(ptr-1-input > 65535) {
    return !SASL_OK; // username too big
  }

  *idu_len=ptr-input;

  if(ids) {
    if(user_realm && *user_realm) {
      *ids = user_realm;
    } else {
      *ids = serverFQDN;
    }
    if(*ids==NULL || strlen(*ids)>65535) {
      return !SASL_OK;
    }
  }
  return SASL_OK;
}

/* The main OPAQUE context */
typedef struct context {
  int state;

  char *authid;		/* authentication id (server) */
  char *userid;		/* authorization id (server) */

  uint8_t *client_sec;
  uint8_t *sk;
  uint8_t *authU;

  /* copy of utils from the params structures */
  const sasl_utils_t *utils;

  /* per-step mem management */
  char *out_buf;
  unsigned out_buf_len;
} context_t;

static int opaque_server_mech_new(void *glob_context __attribute__((unused)),
                                  sasl_server_params_t *params,
                                  const char *challenge __attribute__((unused)),
                                  unsigned challen __attribute__((unused)),
                                  void **conn_context) {
    context_t *ctx;

    /* holds state are in */
    ctx = params->utils->malloc(sizeof(context_t));
    if (ctx == NULL) {
      (params->utils)->seterror( (params->utils)->conn, 0, "Out of Memory in " __FILE__ " near line %d", __LINE__ );
      return SASL_NOMEM;
    }

    memset(ctx, 0, sizeof(context_t));

    ctx->state = 1;
    ctx->utils = params->utils;

    *conn_context = ctx;

    return SASL_OK;
}

/*
 * Dispose of a OPAQUE context (could be server or client)
 */
static void opaque_common_mech_dispose(void *conn_context, const sasl_utils_t *utils) {
    context_t *ctx = (context_t *) conn_context;

    if (!ctx) return;

    if (ctx->authid)		 utils->free(ctx->authid);
    if (ctx->userid)		 utils->free(ctx->userid);
    if (ctx->client_sec)	 utils->free(ctx->client_sec);
    if (ctx->sk)	 		 utils->free(ctx->sk);
    if (ctx->authU)	         utils->free(ctx->authU);

    utils->free(ctx);
}

static int opaque_setpass(void *glob_context __attribute__((unused)),
		       sasl_server_params_t *sparams,
		       const char *userstr,
		       const char *pass,
		       unsigned passlen,
		       const char *oldpass __attribute__((unused)),
		       unsigned oldpasslen __attribute__((unused)),
		       unsigned flags) {
    int r;
    uint16_t idU_len;
    const char *realm = NULL;
    sasl_secret_t *sec = NULL;
    struct propctx *propctx = NULL;
    const char *store_request[] = { "cmusaslsecretOPAQUE", NULL };

    /* Do we have a backend that can store properties? */
    if (!sparams->utils->auxprop_store ||
        sparams->utils->auxprop_store(NULL, NULL, NULL) != SASL_OK) {
      (sparams->utils)->seterror( (sparams->utils)->conn, 0,  "OPAQUE: auxprop backend can't store properties");
      return SASL_NOMECH;
    }

    r = get_idu_ids(&realm, &idU_len, sparams->user_realm, sparams->serverFQDN, userstr);
    if (r) {
      sparams->utils->seterror(sparams->utils->conn, 0, "Error parsing user");
      return r;
    }
    char user[idU_len+1];
    memcpy(user,userstr,idU_len);
    user[idU_len]=0;

    if ((flags & SASL_SET_DISABLE) || pass == NULL) {
      sec = NULL;
    } else {
      uint8_t rec[OPAQUE_USER_RECORD_LEN];
      const Opaque_Ids ids={idU_len,(uint8_t*)userstr,strlen(realm),(uint8_t*)realm};
      //fprintf(stderr,"idU: \"%s\"(%d), idS: \"%s\"(%d)\n", ids.idU, ids.idU_len, ids.idS, ids.idS_len);

      r = opaque_Register((uint8_t*)pass, passlen, NULL, &ids, rec, NULL);
      if(r) {
        sparams->utils->seterror(sparams->utils->conn, 0, "Error registering with opaque");
        goto end;
      }
      /* Put 'rec' into sasl_secret_t.
       * This will be base64 encoded, so make sure its big enough.
       */
      const unsigned long alloclen = (sizeof(rec)/3 + 1) * 4 + 1;
      sec = sparams->utils->malloc(sizeof(sasl_secret_t)+alloclen);
      if (!sec) {
        r = SASL_NOMEM;
        goto end;
      }
      sec->len = 0; // clear len, as we are downcasting from unsigned long to unsigned int ↓
      sparams->utils->encode64((char*)rec, sizeof(rec), (char *) sec->data, alloclen, (unsigned*) &sec->len);

      /* Clean everything up */
    end:

      if (r) return r;
    }

    /* do the store */
    propctx = sparams->utils->prop_new(0);
    if (!propctx)
      r = SASL_FAIL;
    if (!r)
      r = sparams->utils->prop_request(propctx, store_request);
    if (!r)
      r = sparams->utils->prop_set(propctx, "cmusaslsecretOPAQUE",
                                   (char *) (sec ? sec->data : NULL),
                                   (sec ? sec->len : 0));
    if (!r)
      r = sparams->utils->auxprop_store(sparams->utils->conn, propctx, user);
    if (propctx)
      sparams->utils->prop_dispose(&propctx);

    if (r) {
      sparams->utils->seterror(sparams->utils->conn, 0,
                               "Error putting OPAQUE secret");
      goto cleanup;
    }

    sparams->utils->log(NULL, SASL_LOG_DEBUG, "Setpass for OPAQUE successful\n");

cleanup:

    if (sec) sparams->utils->free(sec);
    return r;
}

static int opaque_mech_avail(void *glob_context __attribute__((unused)),
			  sasl_server_params_t *sparams  __attribute__((unused)),
			  void **conn_context __attribute__((unused))) {
    return SASL_OK;
}


static int opaque_server_mech_step1(context_t *ctx,
                                    sasl_server_params_t *params,
                                    const char *clientin,
                                    unsigned clientinlen,
                                    const char **serverout,
                                    unsigned *serveroutlen,
                                    sasl_out_params_t *oparams) {
  int result;
  char *realm = NULL;
  char *authid = NULL;
  char *user = NULL;
  const char *password_request[] = { "*cmusaslsecretOPAQUE", SASL_AUX_PASSWORD, NULL };
  struct propval auxprop_values[3];

  //fprintf(stderr, "opaque server step 1\n");
  if(clientinlen < OPAQUE_USER_SESSION_PUBLIC_LEN+2) {
    SETERROR(params->utils, "Invalid client input in OPAQUE step 1");
    //fprintf(stderr, "bad inputsize: %d\n", clientinlen);
    return SASL_BADPARAM;
  }

  /* Expect:
   * Credential Request
   * authentication identity \0
   * authorization identity \0
   */

  authid = (char*) clientin + OPAQUE_USER_SESSION_PUBLIC_LEN;
  size_t authid_len, user_len;
  authid_len = strlen(authid);
  if(authid_len > 65535) {
    SETERROR(params->utils, "Authid too big in OPAQUE step 1");
    return SASL_BADPARAM;
  }

  user = authid+authid_len+1;
  user_len = strlen(user);
  if(user_len > 65535) {
    SETERROR(params->utils, "User too big in OPAQUE step 1");
    return SASL_BADPARAM;
  }
  if(user_len+authid_len+OPAQUE_USER_SESSION_PUBLIC_LEN+2 != clientinlen) {
    SETERROR(params->utils, "Params sizes do not add up to input size in OPAQUE step 1");
    return SASL_BADPARAM;
  }

  //fprintf(stderr,"user(%ld): \"%s\"\n", user_len, user);
  //fprintf(stderr,"authid(%ld): \"%s\"\n", authid_len, authid);

  /* Get the realm */
  result = _plug_parseuser(params->utils, &user, &realm, params->user_realm, params->serverFQDN, authid);
  if (result) {
    SETERROR(params->utils, "Error getting realm");
    goto cleanup;
  }

  /* Get user secret */
  result = params->utils->prop_request(params->propctx, password_request);
  if (result != SASL_OK) goto cleanup;

  /* this will trigger the getting of the aux properties */
  result = params->canon_user(params->utils->conn, authid, 0, SASL_CU_AUTHID, oparams);
  if (result != SASL_OK) goto cleanup;

  result = params->canon_user(params->utils->conn, user, 0, SASL_CU_AUTHZID, oparams);
  if (result != SASL_OK) goto cleanup;

  result = params->utils->prop_getnames(params->propctx, password_request, auxprop_values);
  if (result < 0 || ((!auxprop_values[0].name || !auxprop_values[0].values))) {
    /* We didn't find this username */
    SETERROR(params->utils, "no record in database");
    result = params->transition ? SASL_TRANS : SASL_NOUSER;
    goto cleanup;
  }

  //if(auxprop_values[0].name) {
  //  fprintf(stderr, "ap_v[0] name: %s size %d\n", auxprop_values[0].name, auxprop_values[0].valsize);
  //}


  uint8_t rec[OPAQUE_USER_RECORD_LEN+1]; // +1 because for some
                                         // utterly braindead reason
                                         // decode64 actually puts a
                                         // terminating 0 at the end
                                         // of the decoded buffer.
  unsigned outlen;

  result = params->utils->decode64(auxprop_values[0].values[0], auxprop_values[0].valsize,
                                    (char*)rec, sizeof(rec),
                                    &outlen);
  if(result) {
    goto cleanup;
  }

  if(outlen!=OPAQUE_USER_RECORD_LEN) {
    SETERROR(params->utils, "Invalid OPAQUE record size\n");
    goto cleanup;
  }

  //fprintf(stderr,"user(%ld): \"%s\"\n", strlen(user), user);
  //fprintf(stderr,"realm(%ld): \"%s\"\n", strlen(realm), realm);
  const unsigned short realm_len = strlen(realm);
  const Opaque_Ids ids={strlen(user),(uint8_t*)user,realm_len,(uint8_t*)realm};
  //fprintf(stderr,"idU: \"%s\"(%d), idS: \"%s\"(%d)\n", ids.idU, ids.idU_len, ids.idS, ids.idS_len);

  ctx->out_buf = params->utils->malloc(OPAQUE_SERVER_SESSION_LEN+realm_len+1);
  if (ctx->out_buf == NULL) {
    MEMERROR(params->utils);
    result = SASL_NOMEM;
    goto cleanup;
  }
  ctx->out_buf_len=OPAQUE_SERVER_SESSION_LEN+realm_len+1;
  memcpy(ctx->out_buf + OPAQUE_SERVER_SESSION_LEN, realm, realm_len+1);

  ctx->sk = params->utils->malloc(OPAQUE_SHARED_SECRETBYTES);
  if (ctx->sk == NULL) {
    MEMERROR(params->utils);
    result = SASL_NOMEM;
    goto cleanup;
  }

  ctx->authU = params->utils->malloc(crypto_auth_hmacsha512_BYTES);
  if (ctx->authU == NULL) {
    MEMERROR(params->utils);
    result = SASL_NOMEM;
    goto cleanup;
  }

  if(0!=opaque_CreateCredentialResponse((uint8_t*)clientin, rec, &ids,
                                        OPAQUE_CONTEXT, OPAQUE_CONTEXT_BYTES,
                                        (uint8_t*)ctx->out_buf, ctx->sk, ctx->authU)) {
    SETERROR(params->utils,"opaque_CreateCredentialResponse failed.\n");
    goto cleanup;
  }

  *serverout = ctx->out_buf;
  *serveroutlen = ctx->out_buf_len;

  ctx->state = 2;
  result = SASL_CONTINUE;

 cleanup:
  if (realm) params->utils->free(realm);

  return result;
}

static int opaque_server_mech_step2(context_t *ctx,
                                    sasl_server_params_t *params,
                                    const char *clientin,
                                    unsigned clientinlen,
                                    const char **serverout __attribute__((unused)),
                                    unsigned *serveroutlen __attribute__((unused)),
                                    sasl_out_params_t *oparams) {
  if(clientinlen!=crypto_auth_hmacsha512_BYTES) {
    SETERROR(params->utils, "Invalid client input in OPAQUE step 2");
    //fprintf(stderr, "bad inputsize: %d\n", clientinlen);
    return SASL_BADPARAM;
  }

  if(-1==opaque_UserAuth(ctx->authU, (const uint8_t*)clientin)) {
    return SASL_BADAUTH;
  }

  /* set oparams */
  oparams->doneflag = 1;

  return SASL_OK;
}

static int opaque_server_mech_step(void *conn_context,
                                   sasl_server_params_t *sparams,
                                   const char *clientin,
                                   unsigned clientinlen,
                                   const char **serverout,
                                   unsigned *serveroutlen,
                                   sasl_out_params_t *oparams) {
  context_t *ctx = (context_t *) conn_context;

  if (!sparams
      || !serverout
      || !serveroutlen
      || !oparams)
    return SASL_BADPARAM;

  *serverout = NULL;
  *serveroutlen = 0;

  if (ctx == NULL) {
    return SASL_BADPROT;
  }

  sparams->utils->log(NULL, SASL_LOG_DEBUG, "OPAQUE server step %d\n", ctx->state);

  switch (ctx->state) {

  case 1:
    return opaque_server_mech_step1(ctx, sparams, clientin, clientinlen, serverout, serveroutlen, oparams);

  case 2:
    return opaque_server_mech_step2(ctx, sparams, clientin, clientinlen, serverout, serveroutlen, oparams);

  default:
    sparams->utils->seterror(sparams->utils->conn, 0, "Invalid OPAQUE server step %d", ctx->state);
    return SASL_FAIL;
  }

  return SASL_FAIL; /* should never get here */
}


static sasl_server_plug_t opaque_server_plugins[] = {
    {
     "OPAQUE",				/* mech_name */
     0,                     /* max_ssf */
     SASL_SEC_NOPLAINTEXT
     | SASL_SEC_NOACTIVE
     | SASL_SEC_NODICTIONARY
     | SASL_SEC_FORWARD_SECRECY
     | SASL_SEC_NOANONYMOUS
     | SASL_SEC_MUTUAL_AUTH,		/* security_flags */
     SASL_FEAT_WANT_CLIENT_FIRST
     | SASL_FEAT_ALLOWS_PROXY,	/* features */
     NULL,				/* glob_context */
     &opaque_server_mech_new,		/* mech_new */
     &opaque_server_mech_step,		/* mech_step */
     &opaque_common_mech_dispose,	/* mech_dispose */
     NULL, 		/* mech_free */
     &opaque_setpass,	/* setpass */
     NULL,				/* user_query */
     NULL,				/* idle */
     &opaque_mech_avail,		/* mech avail */
     NULL				/* spare */
    }
};

int opaque_server_plug_init(const sasl_utils_t *utils,
			 int maxversion,
			 int *out_version,
			 const sasl_server_plug_t **pluglist,
			 int *plugcount,
			 const char *plugname __attribute__((unused))) {
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
      utils->seterror(utils->conn, 0, "OPAQUE version mismatch");
      return SASL_BADVERS;
    }

    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = opaque_server_plugins;
    *plugcount = 1;

    return SASL_OK;
}



/////////////////////////// client stuff ///////////////////////////

static int opaque_client_mech_new(void *glob_context __attribute__((unused)),
                                  sasl_client_params_t *params,
                                  void **conn_context) {
    context_t *ctx;

    /* holds state are in */
    ctx = params->utils->malloc(sizeof(context_t));
    if (ctx == NULL) {
      (params->utils)->seterror( (params->utils)->conn, 0, "Out of Memory in " __FILE__ " near line %d", __LINE__ );
      return SASL_NOMEM;
    }

    memset(ctx, 0, sizeof(context_t));

    ctx->state = 1;
    ctx->utils = params->utils;

    *conn_context = ctx;

    return SASL_OK;
}

static int opaque_client_mech_step1(context_t *ctx,
                                    sasl_client_params_t *params,
                                    const char *serverin __attribute__((unused)),
                                    unsigned serverinlen,
                                    sasl_interact_t **prompt_need,
                                    const char **clientout,
                                    unsigned *clientoutlen,
                                    sasl_out_params_t *oparams) {

  const char *authid = NULL, *userid = NULL;
  sasl_secret_t *password = NULL;
  unsigned int free_password = 0; /* set if we need to free password */
  int auth_result = SASL_OK;
  int pass_result = SASL_OK;
  int user_result = SASL_OK;
  int result;

  if (serverinlen > 0) {
    params->utils->seterror(params->utils->conn, 0, "Invalid input to OPAQUE client 1st step\n");
    return SASL_BADPROT;
  }

  /* try to get the authid */
  if (oparams->authid==NULL) {
    auth_result = _plug_get_authid(params->utils, &authid, prompt_need);

    if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
      return auth_result;
  }

  /* try to get the userid */
  if (oparams->user == NULL) {
    user_result = _plug_get_userid(params->utils, &userid, prompt_need);

    if ((user_result != SASL_OK) && (user_result != SASL_INTERACT))
      return user_result;
  }

  /* try to get the password */
  if (password == NULL) {
    pass_result=_plug_get_password(params->utils, &password,
                                   &free_password, prompt_need);

    if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
      return pass_result;
  }

  /* free prompts we got */
  if (prompt_need && *prompt_need) {
    params->utils->free(*prompt_need);
    *prompt_need = NULL;
  }

  /* if there are prompts not filled in */
  if ((auth_result == SASL_INTERACT) || (user_result == SASL_INTERACT) ||
      (pass_result == SASL_INTERACT)) {
    /* make the prompt list */
    result =
      _plug_make_prompts(params->utils, prompt_need,
                         user_result == SASL_INTERACT ?
                         "Please enter your authorization name" : NULL,
                         NULL,
                         auth_result == SASL_INTERACT ?
                         "Please enter your authentication name" : NULL,
                         NULL,
                         pass_result == SASL_INTERACT ?
                         "Please enter your password" : NULL, NULL,
                         NULL, NULL, NULL,
                         NULL, NULL, NULL);
    if (result != SASL_OK) return result;

    return SASL_INTERACT;
  }

  if (!password) {
    PARAMERROR(params->utils);
    return SASL_BADPARAM;
  }
  //fprintf(stderr, "got password(%ld): %s\n",password->len, password->data);

  if (!userid || !*userid) {
    result = params->canon_user(params->utils->conn, authid, 0, SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
  }
  else {
    result = params->canon_user(params->utils->conn, authid, 0, SASL_CU_AUTHID, oparams);
    if (result != SASL_OK) return result;

    result = params->canon_user(params->utils->conn, userid, 0, SASL_CU_AUTHZID, oparams);
  }
  if (result != SASL_OK) return result;

  //fprintf(stderr, "userid: \"%s\"\n", oparams->user);
  //fprintf(stderr, "authid: \"%s\"\n", oparams->authid);
  /* Send out:
   *
   * U - authentication identity
   * I - authorization identity
   *
   * { utf8(U) utf8(I) utf8(sid) os(cn) }
   */

  ctx->client_sec = params->utils->malloc(OPAQUE_USER_SESSION_SECRET_LEN+password->len);
  if (ctx->client_sec == NULL) {
    MEMERROR(params->utils);
    return SASL_NOMEM;
  }

  *clientoutlen = (OPAQUE_USER_SESSION_PUBLIC_LEN +
                   strlen(oparams->authid) + 1 +
                   strlen(oparams->user) + 1);

  ctx->out_buf = params->utils->malloc(*clientoutlen);
  if (ctx->out_buf == NULL) {
    MEMERROR(params->utils);
    clientoutlen=0;
    return SASL_NOMEM;
  }
  ctx->out_buf_len=*clientoutlen;

  opaque_CreateCredentialRequest(password->data, password->len, ctx->client_sec, (uint8_t*)ctx->out_buf);
  char *ptr = ctx->out_buf + OPAQUE_USER_SESSION_PUBLIC_LEN;
  memcpy(ptr, oparams->authid, strlen(oparams->authid));
  ptr+=strlen(oparams->authid);
  ptr++[0]=0;
  memcpy(ptr, oparams->user, strlen(oparams->user));
  ptr+=strlen(oparams->user);
  ptr[0]=0;

  *clientout = ctx->out_buf;

  ctx->state = 2;

  result = SASL_CONTINUE;

//cleanup:

  return result;
}

static int opaque_client_mech_step2(context_t *ctx,
                                    sasl_client_params_t *params,
                                    const char *serverin,
                                    unsigned serverinlen,
                                    sasl_interact_t **prompt_need __attribute__((unused)),
                                    const char **clientout,
                                    unsigned *clientoutlen,
                                    sasl_out_params_t *oparams) {
  int result;
  if(serverinlen<OPAQUE_SERVER_SESSION_LEN+2) {
    SETERROR(params->utils,"Server Response has incorrect size\n");
    return SASL_BADPARAM;
  }
  if(!ctx->client_sec) {
    SETERROR(params->utils,"Missing secret OPAQUE client context\n");
    return SASL_FAIL;
  }

  const char* realm = serverin + OPAQUE_SERVER_SESSION_LEN;
  size_t realm_len=strlen(realm);
  if(realm_len > 65535) {
    SETERROR(params->utils, "Realm too big in OPAQUE step 2");
    return SASL_BADPARAM;
  }

  result = _plug_buf_alloc(params->utils,
                           &ctx->out_buf, &ctx->out_buf_len,
                           crypto_auth_hmacsha512_BYTES);
  if(result) {
    MEMERROR(params->utils);
    return SASL_NOMEM;
  }

  uint16_t idU_len;
  result = get_idu_ids(NULL, &idU_len, NULL, NULL, oparams->user);
  if (result) {
    params->utils->seterror(params->utils->conn, 0, "Error parsing user");
    return SASL_BADPARAM;
  }

  const Opaque_Ids ids={idU_len,(uint8_t*)oparams->user,realm_len,(uint8_t*)realm};
  //fprintf(stderr,"idU: \"%s\"(%d), idS: \"%s\"(%d)\n", ids.idU, ids.idU_len, ids.idS, ids.idS_len);

  ctx->sk = params->utils->malloc(OPAQUE_SHARED_SECRETBYTES);
  if (ctx->sk == NULL) {
    MEMERROR(params->utils);
    result = SASL_NOMEM;
    goto cleanup;
  }

  result = opaque_RecoverCredentials((uint8_t*) serverin, ctx->client_sec,
                                     OPAQUE_CONTEXT, OPAQUE_CONTEXT_BYTES, &ids,
                                     ctx->sk, (uint8_t*)ctx->out_buf, NULL);
  if(result) {
    SETERROR(params->utils, "Failed to recover OPAQUE credentials\n");
    result = SASL_BADAUTH;
    goto cleanup;
  }

  *clientout = ctx->out_buf;
  *clientoutlen = crypto_auth_hmacsha512_BYTES;

  ctx->state = 3;

  result = SASL_CONTINUE;

cleanup:

  return result;
}

static int opaque_client_mech_step(void *conn_context,
                                   sasl_client_params_t *params,
                                   const char *serverin,
                                   unsigned serverinlen,
                                   sasl_interact_t **prompt_need,
                                   const char **clientout,
                                   unsigned *clientoutlen,
                                   sasl_out_params_t *oparams) {
  context_t *ctx = (context_t *) conn_context;

  params->utils->log(NULL, SASL_LOG_DEBUG,
                     "OPAQUE client step %d\n", ctx->state);

  *clientout = NULL;
  *clientoutlen = 0;

  switch (ctx->state) {

  case 1:
    return opaque_client_mech_step1(ctx, params, serverin, serverinlen, prompt_need, clientout, clientoutlen, oparams);

  case 2:
    return opaque_client_mech_step2(ctx, params, serverin, serverinlen, prompt_need, clientout, clientoutlen, oparams);

  default:
    params->utils->log(NULL, SASL_LOG_ERR, "Invalid OPAQUE client step %d\n", ctx->state);
    return SASL_FAIL;
  }

  return SASL_FAIL; /* should never get here */
}


static sasl_client_plug_t opaque_client_plugins[] =
{
    {
	"OPAQUE",				/* mech_name */
	0,				        /* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_NOACTIVE
	| SASL_SEC_NODICTIONARY
	| SASL_SEC_FORWARD_SECRECY
	| SASL_SEC_MUTUAL_AUTH,		/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST
	| SASL_FEAT_ALLOWS_PROXY,	/* features */
	NULL,				/* required_prompts */
	NULL,				/* glob_context */
	&opaque_client_mech_new,		/* mech_new */
	&opaque_client_mech_step,		/* mech_step */
	&opaque_common_mech_dispose,	/* mech_dispose */
	NULL,		        /* mech_free */
	NULL,				/* idle */
	NULL,				/* spare */
	NULL				/* spare */
    }
};

int opaque_client_plug_init(const sasl_utils_t *utils __attribute__((unused)),
                          int maxversion,
                          int *out_version,
                          const sasl_client_plug_t **pluglist,
                          int *plugcount,
                          const char *plugname __attribute__((unused))) {
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
      utils->seterror(utils->conn, 0, "OPAQUE version mismatch");
      return SASL_BADVERS;
    }

    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = opaque_client_plugins;
    *plugcount=1;

    return SASL_OK;
}
