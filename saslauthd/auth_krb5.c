/* MODULE: auth_krb5 */

/* COPYRIGHT
 * Copyright (c) 1997 Messaging Direct Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY MESSAGING DIRECT LTD. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL MESSAGING DIRECT LTD. OR
 * ITS EMPLOYEES OR AGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * END COPYRIGHT */

/* ok, this is  wrong but the most convenient way of doing 
 * it for now. We assume (possibly incorrectly) that if GSSAPI exists then 
 * the Kerberos 5 headers and libraries exist.   
 * What really should be done is a configure.in check for krb5.h and use 
 * that since none of this code is GSSAPI but rather raw Kerberos5.
 */


/* Also, at some point one would hope it would be possible to
 * have less divergence between Heimdal and MIT Kerberos 5.
 *
 * As of the summer of 2003, the obvious issues are that
 * MIT doesn't have krb5_verify_opt_*() and Heimdal doesn't
 * have krb5_sname_to_principal().
 */

/* PUBLIC DEPENDENCIES */
#include "mechanisms.h"
#include "globals.h" /* mech_option */
#include "cfile.h"
#include "krbtf.h"

#ifdef AUTH_KRB5
# include <krb5.h>
static cfile config = 0;
static char *keytabname = NULL; /* "system default" */
static char *verify_principal = "host"; /* a principal in the default keytab */
static char *servername = NULL; /* server name to use in principal */
#endif /* AUTH_KRB5 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include "auth_krb5.h"

/* END PUBLIC DEPENDENCIES */

int					/* R: -1 on failure, else 0 */
auth_krb5_init (
  /* PARAMETERS */
  void					/* no parameters */
  /* END PARAMETERS */
  )
{
#ifdef AUTH_KRB5
    char *configname = 0;

    if (krbtf_init() == -1) {
	syslog(LOG_ERR, "auth_krb5_init krbtf_init failed");
	return -1;
    }

    if (mech_option)
	configname = mech_option;
    else if (access(SASLAUTHD_CONF_FILE_DEFAULT, F_OK) == 0)
	configname = SASLAUTHD_CONF_FILE_DEFAULT;
 
    if (configname) {
	char complaint[1024];

	if (!(config = cfile_read(configname, complaint, sizeof (complaint)))) {
	    syslog(LOG_ERR, "auth_krb5_init %s", complaint);
	    return -1;
	}
    }

    if (config) {
	keytabname = (char *) cfile_getstring(config, "krb5_keytab", keytabname);
	verify_principal = (char *) cfile_getstring(config, "krb5_verify_principal", verify_principal);
	servername = (char *) cfile_getstring(config, "krb5_servername", servername);
    }

    return 0;

#else
    return -1;
#endif
}

#ifdef AUTH_KRB5

static int
form_principal_name (
  const char *user,
  const char *service,
  const char *realm,
  char *pname,
  int pnamelen
  )
{
    const char *forced_instance = 0;
	int plen;

    plen = strlcpy(pname, user, pnamelen);
    user = pname;

    if (config && cfile_getswitch(config, "krb5_conv_krb4_instance", 0)) {
       char *krb4_instance;

       if ((krb4_instance = strchr(pname, '.'))) *krb4_instance = '/';
    }

    if (config) {
	char keyname[1024];

	snprintf(keyname, sizeof (keyname), "krb5_%s_instance", service);
	forced_instance = cfile_getstring(config, keyname, 0);
    }

    if (forced_instance) {
	char *user_specified;

	if ((user_specified = strchr(user, '/'))) {
	    if (strcmp(user_specified + 1, forced_instance)) {
		/* user not allowed to override sysadmin */
		return -1;
	    } else {
		/* don't need to force--user already asked for it */
		forced_instance = 0;
	    }
	}
    }

    /* form user[/instance][@realm] */
    plen += snprintf(pname+plen, pnamelen-plen, "%s%s%s%s",
	(forced_instance ? "/" : ""),
	(forced_instance ? forced_instance : ""),
	((realm && realm[0]) ? "@" : ""),
	((realm && realm[0]) ? realm : "")
	);
    if ((plen <= 0) || (plen >= pnamelen))
	return -1;

    /* Perhaps we should uppercase the realm? */

    return 0;
}

static void k5support_log_err(int priority,
                              krb5_context context,
                              krb5_error_code code,
                              char const *msg)
{
    const char *k5_msg = krb5_get_error_message(context, code);

    syslog(priority, "auth_krb5: %s: %s (%d)\n", msg, k5_msg, code);
    krb5_free_error_message(context, k5_msg);
}

#ifdef KRB5_HEIMDAL

char *                                  /* R: allocated response string */
auth_krb5 (
  /* PARAMETERS */
  const char *user,                     /* I: plaintext authenticator */
  const char *password,                 /* I: plaintext password */
  const char *service,                  /* I: service authenticating to */
  const char *realm,                    /* I: user's realm */
  const char *remote                    /* I: remote host address */
  /* END PARAMETERS */
  )
{
    /* VARIABLES */
    krb5_context context;
    krb5_error_code rc;
    krb5_keytab kt = NULL;
    krb5_principal auth_user;
    krb5_principal server;
    krb5_get_init_creds_opt *opt;
    krb5_verify_init_creds_opt vopt;
    krb5_creds cred;
    char * result;
    char principalbuf[2048];
    /* END VARIABLES */

    if (!user || !password) {
        syslog(LOG_ERR, "auth_krb5: NULL password or username?");
        return strdup("NO saslauthd NULL password or username");
    }

    if (krb5_init_context(&context)) {
        syslog(LOG_ERR, "auth_krb5: krb5_init_context");
        return strdup("NO saslauthd internal error");
    }

    if (form_principal_name(user, service, realm, principalbuf, sizeof (principalbuf))) {
        syslog(LOG_ERR, "auth_krb5: form_principal_name");
        return strdup("NO saslauthd principal name error");
    }

    if ((rc = krb5_parse_name(context, principalbuf, &auth_user))) {
        k5support_log_err(LOG_ERR, context, rc, "krb5_parse_name");
        krb5_free_context(context);
        return strdup("NO saslauthd internal error");
    }

    if ((rc = krb5_get_init_creds_opt_alloc(context, &opt))) {
        k5support_log_err(LOG_ERR, context, rc, "krb5_get_init_creds_opt_alloc");
        krb5_free_principal(context, auth_user);
        krb5_free_context(context);
        return strdup("NO saslauthd internal error");
    }

    krb5_get_init_creds_opt_set_default_flags(context, NULL,
                                              krb5_principal_get_realm(context, auth_user),
                                              opt);

    rc = krb5_get_init_creds_password(context, &cred, auth_user, password, NULL,
                                 NULL, 0, NULL, opt);
    krb5_get_init_creds_opt_free(context, opt);
    if (rc) {
        k5support_log_err(LOG_ERR, context, rc, "krb5_get_init_creds_password");
        krb5_free_principal(context, auth_user);
        krb5_free_context(context);
        return strdup("NO krb5_get_init_creds_password failed");
    }

    if (keytabname) {
        if ((rc = krb5_kt_resolve(context, keytabname, &kt))) {
            k5support_log_err(LOG_DEBUG, context, rc, "krb5_kt_resolve");
            krb5_free_principal(context, auth_user);
            krb5_free_cred_contents(context, &cred);
            krb5_free_context(context);
            return strdup("NO saslauthd internal error");
        }
    }

    if ((rc = krb5_sname_to_principal(context, servername, verify_principal,
                                KRB5_NT_SRV_HST, &server))) {
        k5support_log_err(LOG_DEBUG, context, rc, "krb5_sname_to_principal");
        krb5_free_principal(context, auth_user);
        krb5_free_cred_contents(context, &cred);
        if (kt) {
            krb5_kt_close(context, kt);
        }
        krb5_free_context(context);
        return strdup("NO saslauthd internal error");
    }

    krb5_verify_init_creds_opt_init(&vopt);
    krb5_verify_init_creds_opt_set_ap_req_nofail(&vopt, 1);

    if ((rc = krb5_verify_init_creds(context, &cred, server, kt, NULL, &vopt))) {
        result = strdup("NO krb5_verify_init_creds failed");
        k5support_log_err(LOG_ERR, context, rc, "krb5_verify_init_creds");
    } else {
        result = strdup("OK");
    }

    krb5_free_principal(context, auth_user);
    krb5_free_principal(context, server);
    krb5_free_cred_contents(context, &cred);
    if (kt) {
        krb5_kt_close(context, kt);
    }
    krb5_free_context(context);

    return result;
}

#else /* !KRB5_HEIMDAL */

/* returns 0 for failure, 1 for success */
static int k5support_verify_tgt(krb5_context context, 
				krb5_ccache ccache) 
{
    krb5_principal server;
    krb5_data packet;
    krb5_keyblock *keyblock = NULL;
    krb5_auth_context auth_context = NULL;
    krb5_error_code k5_retcode;
    krb5_keytab kt = NULL;
    char thishost[BUFSIZ];
    int result = 0;
    
    memset(&packet, 0, sizeof(packet));

    if ((k5_retcode = krb5_sname_to_principal(context, servername,
					      verify_principal,
					      (servername ? KRB5_NT_UNKNOWN : KRB5_NT_SRV_HST),
					      &server))) {
	k5support_log_err(LOG_DEBUG, context, k5_retcode, "krb5_sname_to_principal()");
	return 0;
    }

    if (keytabname) {
	if ((k5_retcode = krb5_kt_resolve(context, keytabname, &kt))) {
	    k5support_log_err(LOG_DEBUG, context, k5_retcode, "krb5_kt_resolve()");
	    goto fini;
	}
    }
    
    if ((k5_retcode = krb5_kt_read_service_key(context, kt, server, 0,
					       0, &keyblock))) {
	k5support_log_err(LOG_DEBUG, context, k5_retcode, "krb5_kt_read_service_key()");
	goto fini;
    }
    
    if (keyblock) {
	krb5_free_keyblock(context, keyblock);
    }
    
    /* this duplicates work done in krb5_sname_to_principal
     * oh well.
     */
    if ( servername ) {
        strncpy( thishost, servername, BUFSIZ );
    } else if (gethostname(thishost, BUFSIZ) < 0) {
	goto fini;
    }
    thishost[BUFSIZ-1] = '\0';
    
    if ((k5_retcode = krb5_mk_req(context, &auth_context, 0, verify_principal, 
				  thishost, NULL, ccache, &packet))) {
	k5support_log_err(LOG_DEBUG, context, k5_retcode, "krb5_mk_req()");
    }
    
    if (auth_context) {
	krb5_auth_con_free(context, auth_context);
	auth_context = NULL;
    }
    
    if (k5_retcode) {
	goto fini;
    }
    
    if ((k5_retcode = krb5_rd_req(context, &auth_context, &packet, 
				  server, NULL, NULL, NULL))) {
	k5support_log_err(LOG_DEBUG, context, k5_retcode, "krb5_rd_req()");
	goto fini;
    }

    if (auth_context) {
      krb5_auth_con_free(context, auth_context);
      auth_context = NULL;
    }
    
    /* all is good now */
    result = 1;
 fini:
    if (!k5_retcode) {
        krb5_free_data_contents(context, &packet);
    }
    krb5_free_principal(context, server);
    
    return result;
}

/* FUNCTION: auth_krb5 */

/* SYNOPSIS
 * Authenticate against Kerberos V.
 * END SYNOPSIS */

char *					/* R: allocated response string */
auth_krb5 (
  /* PARAMETERS */
  const char *user,			/* I: plaintext authenticator */
  const char *password,			/* I: plaintext password */
  const char *service,			/* I: service authenticating to */
  const char *realm,			/* I: user's realm */
  const char *remote                    /* I: remote host address */
  /* END PARAMETERS */
  )
{
    /* VARIABLES */
    krb5_context context;
    krb5_ccache ccache = NULL;
    krb5_principal auth_user;
    krb5_creds creds;
    krb5_get_init_creds_opt opts;
    char * result;
    char tfname[2048];
    char principalbuf[2048];
    krb5_error_code code;
    /* END VARIABLES */

    if (!user|| !password) {
	syslog(LOG_ERR, "auth_krb5: NULL password or username?");
	return strdup("NO saslauthd internal error");
    }

    if (krb5_init_context(&context)) {
	syslog(LOG_ERR, "auth_krb5: krb5_init_context");
	return strdup("NO saslauthd internal error");
    }

    if (form_principal_name(user, service, realm, principalbuf, sizeof (principalbuf))) {
	syslog(LOG_ERR, "auth_krb5: form_principal_name");
	return strdup("NO saslauthd principal name error");
    }

    if ((code = krb5_parse_name (context, principalbuf, &auth_user))) {
	k5support_log_err(LOG_ERR, context, code, "krb5_parse_name()");
	krb5_free_context(context);
	return strdup("NO saslauthd internal error");
    }
    
    if (krbtf_name(tfname, sizeof (tfname)) != 0) {
	syslog(LOG_ERR, "auth_krb5: could not generate ticket file name");
	return strdup("NO saslauthd internal error");
    }

    if ((code = krb5_cc_resolve(context, tfname, &ccache))) {
	k5support_log_err(LOG_ERR, context, code, "krb5_cc_resolve()");
	krb5_free_principal(context, auth_user);
	krb5_free_context(context);
	return strdup("NO saslauthd internal error");
    }
    
    if ((code = krb5_cc_initialize (context, ccache, auth_user))) {
	k5support_log_err(LOG_ERR, context, code, "krb5_cc_initialize()");
	krb5_free_principal(context, auth_user);
	krb5_free_context(context);
	return strdup("NO saslauthd internal error");
    }
    
    krb5_get_init_creds_opt_init(&opts);
    /* 15 min should be more than enough */
    krb5_get_init_creds_opt_set_tkt_life(&opts, 900); 
    if ((code = krb5_get_init_creds_password(context, &creds, 
                                             auth_user, password, NULL, NULL, 
                                             0, NULL, &opts))) {
	k5support_log_err(LOG_ERR, context, code, "krb5_get_init_creds_password()");
	krb5_cc_destroy(context, ccache);
	krb5_free_principal(context, auth_user);
	krb5_free_context(context);
	return strdup("NO saslauthd internal error");
    }
    
    /* at this point we should have a TGT. Let's make sure it is valid */
    if ((code = krb5_cc_store_cred(context, ccache, &creds))) {
	k5support_log_err(LOG_ERR, context, code, "krb5_cc_store_cred()");
	krb5_free_principal(context, auth_user);
	krb5_cc_destroy(context, ccache);
	krb5_free_context(context);
	return strdup("NO saslauthd internal error");
    }
    
    if (!k5support_verify_tgt(context, ccache)) {
	syslog(LOG_ERR, "auth_krb5: k5support_verify_tgt");
	result = strdup("NO saslauthd internal error");
	goto fini;
    }
    
    /* 
     * fall through -- user is valid beyond this point  
     */
    
    result = strdup("OK");
 fini:
/* destroy any tickets we had */
    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, auth_user);
    krb5_cc_destroy(context, ccache);
    krb5_free_context(context);

    return result;
}

#endif /* KRB5_HEIMDAL */

#else /* ! AUTH_KRB5 */

char *
auth_krb5 (
  const char *login __attribute__((unused)),
  const char *password __attribute__((unused)),
  const char *service __attribute__((unused)),
  const char *realm __attribute__((unused)),
  const char *remote __attribute__((unused))
  )
{
    return NULL;
}

#endif /* ! AUTH_KRB5 */

/* END FUNCTION: auth_krb5 */

/* END MODULE: auth_krb5 */
