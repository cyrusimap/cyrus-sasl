/* SASL server API implementation
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

/* checkpw stuff */

#include <sasl.h>
#include <saslint.h>

#ifdef HAVE_KRB
#include <krb.h>
#endif
#include <stdlib.h>

#ifndef WIN32
#include <strings.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/param.h>
#else
#include <string.h>
#endif

#include <sys/types.h>
#include <ctype.h>

#ifndef SASL_MINIMAL_SERVER
#include <pwd.h>
#endif /* SASL_MINIMAL_SERVER */
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif /* HAVE_CRYPT_H */
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif /* HAVE_SHADOW_H */

#ifdef HAVE_PAM
#include <security/pam_appl.h>
#endif

#ifdef HAVE_KRB

/* This defines the Andrew string_to_key function.  It accepts a password
 * string as input and converts its via a one-way encryption algorithm to a DES
 * encryption key.  It is compatible with the original Andrew authentication
 * service password database.
 */

static int
afs_cmu_StringToKey (str, cell, key)
char *str;
char *cell;                  /* cell for password */
des_cblock key;
{   char  password[8+1];              /* crypt is limited to 8 chars anyway */
    int   i;
    int   passlen;

    memset(key, 0, sizeof(des_cblock));
    memset((void *)password, 0, sizeof(password));

    strncpy (password, cell, 8);
    passlen = strlen (str);
    if (passlen > 8) passlen = 8;

    for (i=0; i<passlen; i++)
        password[i] = str[i] ^ cell[i];

    for (i=0;i<8;i++)
        if (password[i] == '\0') password[i] = 'X';

    /* crypt only considers the first 8 characters of password but for some
       reason returns eleven characters of result (plus the two salt chars). */
    strncpy((void *)key,(const char *) (crypt(password, "p1") + 2), sizeof(des_cblock));

    /* parity is inserted into the LSB so leftshift each byte up one bit.  This
       allows ascii characters with a zero MSB to retain as much significance
       as possible. */
    {   char *keybytes = (char *)key;
        unsigned int temp;

        for (i = 0; i < 8; i++) {
            temp = (unsigned int) keybytes[i];
            keybytes[i] = (unsigned char) (temp << 1);
        }
    }
    des_fixup_key_parity (key);

    return SASL_OK;
}

static int
afs_transarc_StringToKey (str, cell, key)
char *str;
char *cell;                  /* cell for password */
des_cblock key;
{   des_key_schedule schedule;
    char temp_key[8];
    char ivec[8];
    char password[BUFSIZ];
    int  passlen;

    strncpy (password, str, sizeof(password));
    if ((passlen = strlen (password)) < (int) sizeof(password)-1)
        strncat (password, cell, sizeof(password)-passlen);
    if ((passlen = strlen(password)) > (int) sizeof(password)) passlen = sizeof(password);

    memcpy (ivec, "kerberos", 8);
    memcpy (temp_key, "kerberos", 8);
    des_fixup_key_parity ((void *)temp_key);
    des_key_sched (temp_key, schedule);
    des_cbc_cksum (password, ivec, passlen, schedule, ivec);

    memcpy (temp_key, ivec, 8);
    des_fixup_key_parity ((void *)temp_key);
    des_key_sched (temp_key, schedule);
    des_cbc_cksum (password, (void *)key, passlen, schedule, ivec);

    des_fixup_key_parity (key);

    return SASL_OK;
}

static int krb_afs_string_to_key(str, key, cell)
char *str;
des_cblock key;
char *cell;                  /* cell for password */
{
    if (strlen(str) > 8) {
	afs_transarc_StringToKey (str, cell, key);
    }
    else {
	afs_cmu_StringToKey (str, cell, key);
    }
    return SASL_OK;
}

/* convert string to all lower case
 */
char *lcase(char* str)
{
    char *scan = str;
    
    while (*scan) {
	*scan = tolower((int) *scan);
	scan++;
    }

    return (str);
}

static int use_key(char *user __attribute__((unused)), 
		   char *instance __attribute__((unused)), 
		   char *realm __attribute__((unused)), 
		   des_cblock key, des_cblock returned_key)
{
    memcpy (returned_key, key, sizeof(des_cblock));
    return 0;
}

/*
 * Securely verify the plaintext password 'passwd' for user 'user'
 * against the Kerberos database.  "service" is the name of a service
 * we can verify the returned ticket against.  Returns 1 for success,
 * 0 for failure.  On failure, 'reply' is filled in with a pointer to
 * the reason.
 */
int _sasl_kerberos_verify_password(sasl_conn_t *conn,
				   const char *user, const char *passwd,
				   const char *service, const char **reply)
{
    int result;
    des_cblock key;
    char tfname[40];
    char realm[REALM_SZ];
    char cell[REALM_SZ];
    char hostname[MAXHOSTNAMELEN+1];
    char phost[MAXHOSTNAMELEN+1];
    KTEXT_ST authent;
    char instance[INST_SZ];
    AUTH_DAT kdata;
    char *srvtab = "";
    sasl_getopt_t *getopt;
    void *context;

    if (!userid || !password) {
	return SASL_BADPARAM;
    }
    if (reply) { *reply = NULL; }

    /* check to see if the user configured a srvtab */
    if (_sasl_getcallback(conn, SASL_CB_GETOPT, &getopt, &context) 
	== SASL_OK) {
	getopt(context, NULL, "srvtab", &srvtab, NULL);
	if (!srvtab) srvtab = "";
    }


    if (krb_get_lrealm(realm, 1)) return SASL_FAIL;

    sprintf(tfname, "/tmp/tkt_%d", getpid());
    krb_set_tkt_string(tfname);

    /* First try Kerberos string-to-key */
    des_string_to_key(passwd, key);
    
    result = krb_get_in_tkt(user, "", realm,
			    "krbtgt", realm, 1, use_key, NULL, key);

    if (result == INTK_BADPW) {
	/* Now try andrew string-to-key */
	strcpy(cell, realm);
	lcase(cell);
	krb_afs_string_to_key(passwd, key, cell);
    
	result = krb_get_in_tkt(user, "", realm,
				"krbtgt", realm, 1, use_key, NULL, key);
    }

    memset(key, 0, sizeof(key));

    if (result != 0) {
	dest_tkt();
	if (reply) *reply = krb_err_txt[result];
	return SASL_FAIL;
    }

    /* Check validity of returned ticket */
    gethostname(hostname, sizeof(hostname));
    strcpy(phost, krb_get_phost(hostname));
    result = krb_mk_req(&authent, service, phost, realm, 0);
    if (result != 0) {
	memset(&authent, 0, sizeof(authent));
	dest_tkt();
	if (reply) *reply = krb_err_txt[result];
	return SASL_FAIL;
    }
    strcpy(instance, "*");
    result = krb_rd_req(&authent, service, instance, 0L, &kdata, srvtab); 
    memset(&authent, 0, sizeof(authent));
    memset(kdata.session, 0, sizeof(kdata.session));
    if (result != 0 || strcmp(kdata.pname, user) != 0 || kdata.pinst[0] ||
	strcmp(kdata.prealm, realm) != 0) {
	if (result != 0) {
	    if (reply) *reply = krb_err_txt[result];
	}
	else {
	    if (reply) *reply = "Kerberos ID does not match user name";
	}
	result = SASL_FAIL;
    }
    else result = SASL_OK;

    dest_tkt();
    return result;
}

#endif /* HAVE_KRB */

int _sasl_shadow_verify_password(sasl_conn_t *conn __attribute__((unused)),
				 const char *userid, const char *password,
				 const char **reply __attribute__((unused)) )
{
#ifdef HAVE_GETSPNAM

  char *salt;
  char *crypted;

  if (!userid || !password) {
      return SASL_BADPARAM;
  }
  if (reply) { *reply = NULL; }

  /* Let's attempt the shadow password file, and see if that gets
   * us anywhere. */
  struct spwd *spwd = getspnam(userid);
  if (! spwd)
    return SASL_BADAUTH; /* can't use it */
  salt = spwd->sp_pwdp;
  crypted = crypt(password, salt);
  if (strcmp(crypted, spwd->sp_pwdp))
    return SASL_BADAUTH;	/* we lose. */

  return SASL_OK;

#else  /* HAVE_GETSPNAM */
  return SASL_FAIL;
#endif

}
#ifndef SASL_MINIMAL_SERVER
int _sasl_passwd_verify_password(sasl_conn_t *conn __attribute__((unused)),
				 const char *userid,
				 const char *password,
				 const char **reply)
{
  struct passwd *pwd;
  char *salt;
  char *crypted;

  if (!userid || !password) {
      return SASL_BADPARAM;
  }
  if (reply) { *reply = NULL; }

  pwd=getpwnam(userid);
  if (pwd==NULL) return SASL_NOUSER;

  salt = pwd->pw_passwd;

  crypted= crypt(password, salt);

  if (strcmp(crypted, pwd->pw_passwd)==0)
    return SASL_OK;

  return SASL_BADAUTH;
}
#endif /* SASL_MINIMAL_SERVER */
#ifdef HAVE_PAM
struct sasl_pam_data {
    const char *userid;
    const char *password;
    int pam_error;
};

static int sasl_pam_conv(int num_msg, struct pam_message **msg,
			 struct pam_response **resp, void *appdata_ptr)
{
    struct pam_response *reply = NULL;
    struct sasl_pam_data *pd = (struct sasl_pam_data *) appdata_ptr;
    int i;
    int ret;

    reply = (struct pam_response *) sasl_ALLOC(sizeof(struct pam_response) * 
					       num_msg);
    if (reply == NULL)
	return PAM_CONV_ERR;

    for (i = 0; i < num_msg; i++) {
	switch (msg[i]->msg_style) {
	    /* making the blatant assumption that echo on means user,
	       echo off means password */
	case PAM_PROMPT_ECHO_ON:
	    reply[i].resp_retcode = PAM_SUCCESS;
	    ret = _sasl_strdup(pd->userid, &reply[i].resp, NULL);
	    if (ret != SASL_OK)
		return PAM_CONV_ERR;
	    break;
	case PAM_PROMPT_ECHO_OFF:
	    reply[i].resp_retcode = PAM_SUCCESS;
	    ret = _sasl_strdup(pd->password, &reply[i].resp, NULL);
	    if (ret != SASL_OK)
		return PAM_CONV_ERR;
	    break;
	case PAM_TEXT_INFO:
	case PAM_ERROR_MSG:
	    /* ignore it, but pam still wants a NULL response... */
	    reply[i].resp_retcode = PAM_SUCCESS;
	    reply[i].resp = NULL;
	    break;
	default:		/* error! */
	    sasl_FREE(reply);
	    pd->pam_error = 1;
	    return PAM_CONV_ERR;
	}
    }
    *resp = reply;
    return PAM_SUCCESS;
}

static struct pam_conv my_conv = {
    &sasl_pam_conv,		/* int (*conv) */
    NULL			/* appdata_ptr */
};

int _sasl_PAM_verify_password(sasl_conn_t *conn __attribute__((unused)),
			      const char *userid, const char *password,
			      const char *service,
			      const char **reply)
{
    pam_handle_t *pamh;
    struct sasl_pam_data pd;
    int pam_error;

    if (!userid || !password) {
	return SASL_BADPARAM;
    }
    if (reply) { *reply = NULL; }

    my_conv.appdata_ptr = &pd;

    pd.userid = userid;
    pd.password = password;
    pd.pam_error = 0;

    pam_error = pam_start(service, userid, &my_conv, &pamh);
    if (pam_error != PAM_SUCCESS) {
	goto pam_err;
    }
    pam_error = pam_authenticate(pamh, PAM_SILENT);
    if (pam_error != PAM_SUCCESS) {
	goto pam_err;
    }
    pam_end(pamh, PAM_SUCCESS);

    return SASL_OK;    

pam_err:
    return SASL_BADAUTH;
}

#endif /* HAVE_PAM */

int _sasl_sasldb_verify_password(sasl_conn_t *conn,
				 const char *userid, const char *passwd,
				 const char **reply)
{
    sasl_server_getsecret_t *getsec;
    void *context;
    int ret;
    sasl_secret_t *secret;

    if (!userid || !password) {
	return SASL_BADPARAM;
    }
    if (reply) { *reply = NULL; }
    ret = _sasl_getcallback(conn, SASL_CB_SERVER_GETSECRET, &getsec, &context);
    if (ret != SASL_OK) {
	return ret;
    }

    ret = getsec(context, "PLAIN", userid, &secret);
    if (ret != SASL_OK) {
	return ret;
    }

    if (strlen(passwd) != secret->len) {
	sasl_free_secret(secret);
	return SASL_BADAUTH;
    }

    if (!strcmp(passwd, secret->data)) {
	ret = SASL_OK;
    } else {
	ret = SASL_BADAUTH;
    }

    sasl_free_secret(secret);
    return ret;
}

