/* javasasl.c--Java SASL JNI implementation
 * Tim Martin
 */
/***********************************************************
        Copyright 1998 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#include <stdio.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "javasasl.h"

static char *username="tmartin";
static char *authid="tmartin";
static JNIEnv *globalenv;
static jobject globalobj;

static void throwinteract(JNIEnv *env, sasl_interact_t *interact)
{
  jclass newExcCls;
  char *errstr;
  newExcCls = (*env)->FindClass(env, "sasl/InteractException");


  errstr=(char *) malloc(1024);
  sprintf(errstr, "%s",interact->prompt);
			  
  (*env)->ThrowNew(env, newExcCls, errstr);
  free(errstr);

}

static void throwexception(JNIEnv *env, int error)
{
  char *errstr;
  jclass newExcCls;

  switch(error)
    {
    case SASL_CONTINUE:
      newExcCls = (*env)->FindClass(env, "sasl/ContinueException");
      break;
    case SASL_NOMECH:
      newExcCls = (*env)->FindClass(env, "sasl/NoMechException");
      break;
    case SASL_NOTDONE:
      newExcCls = (*env)->FindClass(env, "sasl/NotDoneException");
      break;
    case SASL_INTERACT:
      newExcCls = (*env)->FindClass(env, "sasl/InteractException");
      break;
    case SASL_BADAUTH:
      newExcCls = (*env)->FindClass(env, "sasl/BadAuthException");
      break;
      
    default: 
      newExcCls = (*env)->FindClass(env, "sasl/GenericException");
      break;
    }
  if (newExcCls == 0) { 
    return;
  }
  
  errstr=(char *) malloc(1024);
  sprintf(errstr, "Error %i: %s",error,sasl_errstring(error,NULL,NULL));

  (*env)->ThrowNew(env, newExcCls, errstr);
  free(errstr);
}

/* server init */

JNIEXPORT jint JNICALL Java_sasl_ServerFactory_jni_1sasl_1server_1init
  (JNIEnv *env, jobject obj, jstring jstr)
{
  /* Obtain a C-copy of the Java string */
  const char *str = (*env)->GetStringUTFChars(env, jstr, 0);
  int result;

  result=sasl_server_init(NULL,str);
  if (result!=SASL_OK)
    throwexception(env,result);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  return result;
}

static int
simple(void *context __attribute__((unused)),
       int id,
       const char **result,
       unsigned *len)
{
  if (! result)
    return SASL_BADPARAM;
  switch (id) {
  case SASL_CB_USER:
    *result = username;
    if (len)
      *len = username ? strlen(username) : 0;
    printf("retrieved userid through callback\n");
    break;
  case SASL_CB_AUTHNAME:
    authid=username;
    *result = authid;
    if (len)
      *len = authid ? strlen(authid) : 0;
    printf("retrieved authid through callback\n");
      break;
  case SASL_CB_LANGUAGE:
    *result = NULL;
    if (len)
      *len = 0;
    break;
  default:
    return SASL_BADPARAM;
  }
  return SASL_OK;
}

#define PASSWORD "password"

static int
getsecret(sasl_conn_t *conn,
	  void *context __attribute__((unused)),
	  int id,
	  sasl_secret_t **psecret)
{
  jclass cls;
  jmethodID mid;
  const char *str;
  jstring jstr;

  printf("Trying to call password callback\n");
  cls = (*globalenv)->GetObjectClass(globalenv, globalobj);
  mid = (*globalenv)->GetMethodID(globalenv, cls, "callback_password",
				  "(I)Ljava/lang/String;");
  if (mid == 0) {
      printf("failure to getmethod\n");
      return SASL_FAIL;
  }
  jstr=(jstring) (*globalenv)->CallObjectMethod(globalenv, globalobj, mid, 2);

  str = (*globalenv)->GetStringUTFChars(globalenv, jstr, 0);

  printf("suceeded %s\n",str);

  /* make sure we got here ok */
  if (! conn || ! psecret || id != SASL_CB_PASS)
    return SASL_BADPARAM;

  *psecret = (sasl_secret_t *) malloc(sizeof(sasl_secret_t)+strlen(PASSWORD)+1);
  if (! *psecret)
    return SASL_FAIL;

  strcpy((*psecret)->data, str);
  (*psecret)->len=strlen(str);

  /* Now we are done with str */
  (*globalenv)->ReleaseStringUTFChars(globalenv, jstr, str);

  printf("retrieved password through callback\n");
  return SASL_OK;
}

static sasl_callback_t callbacks[] = {
  {
    SASL_CB_PASS,     NULL, NULL
  }, {
    SASL_CB_USER,     NULL, NULL /* we'll handle these ourselves */
  }, {
    SASL_CB_AUTHNAME, NULL, NULL /* we'll handle these ourselves */
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

/* client init */
JNIEXPORT jint JNICALL Java_sasl_ClientFactory_jni_1sasl_1client_1init
  (JNIEnv *env, jobject obj, jstring jstr)
{
  /* Obtain a C-copy of the Java string */
  const char *str = (*env)->GetStringUTFChars(env, jstr, 0);
  int result;

  printf("initing\n");

  result=sasl_client_init(callbacks);
  printf("initing %i\n",result);
  if (result!=SASL_OK)
    throwexception(env,result);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  return result;
}

/* server new */

JNIEXPORT jint JNICALL Java_sasl_ServerFactory_jni_1sasl_1server_1new
  (JNIEnv *env, jobject obj, jstring jservice, jstring jlocal, 
   jstring juser, jint jsecflags)
{
  sasl_conn_t *conn;

  const char *service = (*env)->GetStringUTFChars(env, jservice, 0);
  const char *local_domain = (*env)->GetStringUTFChars(env, jlocal, 0);
  const char *user_domain = (*env)->GetStringUTFChars(env, juser, 0);
  int result;

  result=sasl_server_new(service, local_domain, user_domain, 
			 NULL, jsecflags, &conn);
  if (result!=SASL_OK)
    throwexception(env,result);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jservice, service);  
  (*env)->ReleaseStringUTFChars(env, jlocal, local_domain);  
  (*env)->ReleaseStringUTFChars(env, juser, user_domain);  

  return (jint) conn;
}


JNIEXPORT jint JNICALL Java_sasl_ClientFactory_jni_1sasl_1client_1new
  (JNIEnv *env, jobject obj,
   jstring jservice, jstring jserver, jint jsecflags)
{
  sasl_conn_t *conn;

  const char *service = (*env)->GetStringUTFChars(env, jservice, 0);
  const char *serverFQDN = (*env)->GetStringUTFChars(env, jserver, 0);
  int result;

  result=sasl_client_new(service, serverFQDN, NULL, jsecflags, &conn);
  printf("client_new res=%i\n",result);
  if (result!=SASL_OK)
    throwexception(env,result);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jservice, service);  
  (*env)->ReleaseStringUTFChars(env, jserver, serverFQDN);  

  return (jint) conn;
}

/* server start */

JNIEXPORT jbyteArray JNICALL Java_sasl_ServerConn_jni_1sasl_1server_1start
  (JNIEnv *env, jobject obj, jint ptr, jstring jstr, jbyteArray jarr, jint jlen)
{
  sasl_conn_t *conn;
  const char *mech = (*env)->GetStringUTFChars(env, jstr, 0);
  char *out;
  unsigned int outlen;
   int result;
  jbyteArray arr;
  signed char *a;
  const char *errstr;
  const char *fillin;
  signed char *in;

  if (jarr!=NULL)
      in = (*env)->GetByteArrayElements(env, jarr, 0);

  conn=(sasl_conn_t *) ptr;

  result=sasl_server_start(conn, mech,
			   (const char *) in, jlen,
			   &out, &outlen,
			   &errstr);

  if ((result!=SASL_OK) && (result!=SASL_CONTINUE))
  {

    throwexception(env,result);
    return NULL;
  }
  

  arr=(*env)->NewByteArray(env,outlen+1);

  if (result==SASL_CONTINUE)
    (*env)->SetByteArrayRegion(env,arr, 0, 1,(signed char *) "C");
  else
    (*env)->SetByteArrayRegion(env,arr, 0, 1,(signed char *)  "O");

  (*env)->SetByteArrayRegion(env,arr, 1, outlen, (signed char *) out);

  return arr;
}

extern int _sasl_debug;

static void interaction (sasl_interact_t *t)
{
  char result[1024];

  printf("%s:",t->prompt);
  scanf("%s",&result);

  t->len=strlen(result);
  printf("setting len to %i\n",t->len);
  t->result=(char *) malloc(t->len+1);
  memset(t->result, 0, t->len+1);
  memcpy((char *) t->result, result, t->len);

  printf("done interaction\n");

}

/* call_pass()
 * 
 *   This function calls back to the java layer with some parameters 
 *  for the prompt. It gets a String from the java layer and fills
 *  it into the prompt and returns it to sasl
 */
static int call_pass(JNIEnv *env, jobject obj, sasl_interact_t *t)
{
  jclass cls;
  jmethodID mid;
  const char *str;
  jstring jstr;
  jstring defaul, prompt;

  /* set up for java callback */
  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_password",
				  "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
  if (mid == 0) {
    return SASL_FAIL;
  }

  /* make default result into a java string */
  if (t->defresult!=NULL)
    defaul= (*env)->NewStringUTF(env,t->defresult);
  else
    defaul= (*env)->NewStringUTF(env,"");

  /* make prompt into a java string */
  prompt= (*env)->NewStringUTF(env,t->prompt);

  /* do the callback */
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid,defaul,prompt);

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  /* copy it into the result */
  t->result=(char *) malloc( strlen(str));
  t->len=strlen(str);
  strcpy(t->result, str);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  return SASL_OK;
}

/* call_authname()
 * 
 *   This function calls back to the java layer with some parameters 
 *  for the prompt. It gets a String from the java layer and fills
 *  it into the prompt and returns it to sasl
 */
static int call_authname(JNIEnv *env, jobject obj, sasl_interact_t *t)
{
  jclass cls;
  jmethodID mid;
  const char *str;
  jstring jstr;
  jstring defaul, prompt;

  /* set up for java callback */
  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_authID",
				  "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
  if (mid == 0) {
    return SASL_FAIL;
  }

  /* make default result into a java string */
  if (t->defresult!=NULL)
    defaul= (*env)->NewStringUTF(env,t->defresult);
  else
    defaul= (*env)->NewStringUTF(env,"");

  /* make prompt into a java string */
  prompt= (*env)->NewStringUTF(env,t->prompt);

  /* do the callback */
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid,defaul,prompt);

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  /* copy it into the result */
  t->result=(char *) malloc( strlen(str));
  t->len=strlen(str);
  strcpy(t->result, str);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  return SASL_OK;
}

/* call_userid()
 * 
 *   This function calls back to the java layer with some parameters 
 *  for the prompt. It gets a String from the java layer and fills
 *  it into the prompt and returns it to sasl
 */
static int call_userid(JNIEnv *env, jobject obj, sasl_interact_t *t)
{
  jclass cls;
  jmethodID mid;
  const char *str;
  jstring jstr;
  jstring defaul, prompt;

  /* set up for java callback */
  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_userID",
			    "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
  if (mid == 0) {
    return SASL_FAIL;
  }

  /* make default result into a java string */
  if (t->defresult!=NULL)
    defaul= (*env)->NewStringUTF(env,t->defresult);
  else
    defaul= (*env)->NewStringUTF(env,"");

  /* make prompt into a java string */
  prompt= (*env)->NewStringUTF(env,t->prompt);

  /* do the callback */
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid,defaul,prompt);

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  /* copy it into the result */
  t->result=(char *) malloc( strlen(str));
  t->len=strlen(str);
  strcpy(t->result, str);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  return SASL_OK;
}

/* call_authpass()
 * 
 *   This function calls back to the java layer with some parameters 
 *  for the prompt. It gets a String from the java layer and fills
 *  it into the prompt and returns it to sasl
 */
static int call_authpass(JNIEnv *env, jobject obj, sasl_interact_t *t_a,
			 sasl_interact_t *t_p)
{
  jclass cls;
  jmethodID mid;
  const char *str;
  jstring jstr;
  jstring defaul, prompt1, prompt2;

  /* set up for java callback */
  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_authID_password",
			    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
  if (mid == 0) {
    return SASL_FAIL;
  }

  /* make default result into a java string */
  if (t_a->defresult!=NULL)
    defaul= (*env)->NewStringUTF(env,t_a->defresult);
  else
    defaul= (*env)->NewStringUTF(env,"");

  /* make prompts into a java string */
  prompt1= (*env)->NewStringUTF(env,t_a->prompt);
  prompt2= (*env)->NewStringUTF(env,t_p->prompt);

  /* do the callback */
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid,defaul,prompt1,prompt2);

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  /* copy authid into the result */
  t_a->result=(char *) malloc( strlen(str));
  t_a->len=strlen(str);
  strcpy(t_a->result, str);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_getpassword",
			    "(I)Ljava/lang/String;");

  if (mid == 0) {
    printf("null function\n");
    return SASL_FAIL;
  }

  /* do the callback to get the password*/
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid, 2);

  printf("got password too\n");

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  printf("got password too 2\n");

  /* copy password into the result */
  t_p->result=(char *) malloc( strlen(str));
  t_p->len=strlen(str);
  strcpy(t_p->result, str);

  printf("got password too 3\n");

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  printf("got password too 4\n");

  return SASL_OK;
}

/* call_userpass()
 * 
 *   This function calls back to the java layer with some parameters 
 *  for the prompt. It gets a String from the java layer and fills
 *  it into the prompt and returns it to sasl
 */
static int call_userpass(JNIEnv *env, jobject obj, sasl_interact_t *t_u,
			 sasl_interact_t *t_p)
{
  jclass cls;
  jmethodID mid;
  const char *str;
  jstring jstr;
  jstring defaul, prompt1, prompt2;

  /* set up for java callback */
  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_userID_password",
			    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
  if (mid == 0) {
    return SASL_FAIL;
  }

  /* make default result into a java string */
  if (t_u->defresult!=NULL)
    defaul= (*env)->NewStringUTF(env,t_u->defresult);
  else
    defaul= (*env)->NewStringUTF(env,"");

  /* make prompts into a java string */
  prompt1= (*env)->NewStringUTF(env,t_u->prompt);
  prompt2= (*env)->NewStringUTF(env,t_p->prompt);

  /* do the callback */
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid,defaul,prompt1,prompt2);

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  /* copy authid into the result */
  t_u->result=(char *) malloc( strlen(str));
  t_u->len=strlen(str);
  strcpy(t_u->result, str);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_getpassword",
			    "(I)Ljava/lang/String;");

  if (mid == 0) {
    printf("null function\n");
    return SASL_FAIL;
  }

  /* do the callback to get the password*/
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid, 2);

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  /* copy password into the result */
  t_p->result=(char *) malloc( strlen(str));
  t_p->len=strlen(str);
  strcpy(t_p->result, str);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  return SASL_OK;
}

/* call_userauthpass()
 * 
 *   This function calls back to the java layer with some parameters 
 *  for the prompt. It gets a String from the java layer and fills
 *  it into the prompt and returns it to sasl
 */
static int call_userauthpass(JNIEnv *env, jobject obj, 
			     sasl_interact_t *t_u,
			     sasl_interact_t *t_a,
			     sasl_interact_t *t_p)
{
  jclass cls;
  jmethodID mid;
  const char *str;
  jstring jstr;
  jstring defaul, prompt1, prompt2, prompt3;

  /* set up for java callback */
  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_userID_authID_password",
			    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
  if (mid == 0) {
    return SASL_FAIL;
  }

  /* make default result into a java string */
  if (t_a->defresult!=NULL)
    defaul= (*env)->NewStringUTF(env,t_a->defresult);
  else
    defaul= (*env)->NewStringUTF(env,"");

  /* make prompts into a java strings */
  prompt1= (*env)->NewStringUTF(env,t_u->prompt);
  prompt2= (*env)->NewStringUTF(env,t_a->prompt);
  prompt3= (*env)->NewStringUTF(env,t_p->prompt);

  /* do the callback */
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid,defaul,prompt1,prompt2,prompt3);

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  /* copy authid into the result */
  t_u->result=(char *) malloc( strlen(str));
  t_u->len=strlen(str);
  strcpy(t_u->result, str);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  /* now get the authid */
  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_getauthid",
			    "(I)Ljava/lang/String;");

  if (mid == 0) {
    printf("null function\n");
    return SASL_FAIL;
  }

  /* do the callback to get the password*/
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid, 2);

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  /* copy authid into the result */
  t_a->result=(char *) malloc( strlen(str));
  t_a->len=strlen(str);
  strcpy(t_a->result, str);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  /* now get the password */
  cls = (*env)->GetObjectClass(env, obj);
  mid = (*env)->GetMethodID(env, cls, "callback_getpassword",
			    "(I)Ljava/lang/String;");

  if (mid == 0) {
    printf("null function\n");
    return SASL_FAIL;
  }

  /* do the callback to get the password*/
  jstr=(jstring) (*env)->CallObjectMethod(env, obj, mid, 2);

  /* convert the result string into a char * */
  str = (*env)->GetStringUTFChars(env, jstr, 0);

  /* copy password into the result */
  t_p->result=(char *) malloc( strlen(str));
  t_p->len=strlen(str);
  strcpy(t_p->result, str);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  return SASL_OK;
}

static void fillin_interactions(JNIEnv *env, jobject obj, 
				sasl_interact_t *tlist)
{
  sasl_interact_t *ptr=tlist;
  sasl_interact_t *uid=NULL;
  sasl_interact_t *aid=NULL;
  sasl_interact_t *pass=NULL;

  /* First go through the prompt list to see what we have */
  while (ptr->id!=SASL_CB_LIST_END)
  {
    if (ptr->id==SASL_CB_PASS)
      pass=ptr;
    if (ptr->id==SASL_CB_AUTHNAME)
      aid=ptr;
    if (ptr->id==SASL_CB_USER)
      uid=ptr;
    ptr->result=NULL;
    
    /* increment to next sasl_interact_t */
    ptr++;
  }

  printf("%i %i %i\n",uid,aid,pass);

  /* If there are any combos we know how to handle then handle them */

  if ((aid!=NULL) && (uid!=NULL) && (pass!=NULL))
    call_userauthpass(env,obj,uid,aid,pass);
  else if ((aid!=NULL) && (pass!=NULL))
    call_authpass(env,obj,aid,pass);
  else if ((uid!=NULL) && (pass!=NULL))
    call_userpass(env,obj,aid,pass);
  

  /* Now do individual ones for anything left over */
  while (tlist->id!=SASL_CB_LIST_END)
  {
    if (tlist->result==NULL)
    {
      if (tlist->id==SASL_CB_PASS)
	call_pass(env,obj, tlist);
      else if (tlist->id==SASL_CB_AUTHNAME)
	call_authname(env,obj, tlist);
      else if (tlist->id==SASL_CB_USER)
        call_userid(env,obj, tlist);
      else
        interaction(tlist); 
    }
    tlist++;    
  }

  /* everything should now be filled in (i think) */
  printf("everything should now be filled in (i think)\n");
}

/* client start */
JNIEXPORT jbyteArray JNICALL Java_sasl_ClientConn_jni_1sasl_1client_1start
  (JNIEnv *env, jobject obj, jint ptr, jstring jstr, jstring jfill)
{    
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
   const char *mechlist = (*env)->GetStringUTFChars(env, jstr, 0);
  char *out;
  unsigned int outlen=0;
  const char *mechusing;
  int result;
  sasl_secret_t *secret;
  sasl_interact_t *client_interact=NULL;
  jbyteArray arr;
  signed char *a;
  const char *fillin;

  printf("client start\n");

  /* if got info for an interact make one */
  if (jfill!=NULL)
  {
    fillin=(*env)->GetStringUTFChars(env, jfill, 0);
    client_interact=(sasl_interact_t *) malloc(sizeof(sasl_interact_t));
    client_interact->len=strlen(fillin);
    client_interact->result=(char *) malloc(client_interact->len);
    memcpy((void *) client_interact->result, fillin, client_interact->len);
  }


 
  /* create secret XXX */
  secret=(sasl_secret_t *) malloc(sizeof(sasl_secret_t)+9);
  strcpy((char *) secret->data,"password");
  secret->len=strlen((char *) secret->data);

  do {
      printf("trying start\n");

      result=sasl_client_start(conn, mechlist,
			       secret, &client_interact,
			       &out, &outlen,
			       &mechusing);
      printf("client_start res=%i\n",result);
      printf("outlen=%i\n",outlen);
      if (result==SASL_INTERACT)
	  fillin_interactions(env,obj,client_interact);
      printf("here\n");

  } while (result==SASL_INTERACT);

  if (result==SASL_INTERACT)
  {
    throwinteract(env,client_interact);
    return NULL;
  }

  if ((result!=SASL_OK) && (result!=SASL_CONTINUE))
  {

    throwexception(env,result);
    return NULL;
  }

  if (outlen==0)
    return NULL;

  arr=(*env)->NewByteArray(env,outlen);

  (*env)->SetByteArrayRegion(env,arr, 0, outlen, (signed char *) out);

  return arr;
}

/* server step */

JNIEXPORT jbyteArray JNICALL Java_sasl_ServerConn_jni_1sasl_1server_1step
  (JNIEnv *env, jobject obj, jint ptr, jbyteArray jarr, jint jlen)
{
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  int result;
  char *out;
  unsigned int outlen;
  jbyteArray arr;
  int lup;
  const char *errstr;  
  signed char *in = (*env)->GetByteArrayElements(env, jarr, 0);
      
  result=sasl_server_step(conn, (const char *) in, jlen,
			  &out, &outlen, &errstr);

  if ((result!=SASL_OK) && (result!=SASL_CONTINUE))
  {
      /* throw exception */
    throwexception(env,result);
    return NULL;
  }

  arr=(*env)->NewByteArray(env,outlen+1);

  if (result==SASL_CONTINUE)
    (*env)->SetByteArrayRegion(env,arr, 0, 1,(signed char *) "C");
  else
    (*env)->SetByteArrayRegion(env,arr, 0, 1,(signed char *)  "O");

  (*env)->SetByteArrayRegion(env,arr, 1, outlen, (signed char *) out);



  return arr;
}





/* client step */

JNIEXPORT jbyteArray JNICALL Java_sasl_ClientConn_jni_1sasl_1client_1step
    (JNIEnv *env, jobject obj, jint ptr, jbyteArray jarr, jint jlen, jstring jstr)
{    
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  const char *fillin = NULL; 
  /*  const char *in = (*env)->GetStringUTFChars(env, jstr, 0);*/
  int result;
  sasl_interact_t *client_interact=NULL;
  char *out;
  unsigned int outlen;
  jbyteArray arr;
  int lup;
  char *errstr;
  signed char *in = (*env)->GetByteArrayElements(env, jarr, 0);

  globalenv=env;
  globalobj=obj;

  in[jlen]=0;
  printf("in client step 1\n");

  /* if got info for an interact make one */
  /*  if (jstr!=NULL)
  {
    fillin=(*env)->GetStringUTFChars(env, jstr, 0);
    client_interact=(sasl_interact_t *) malloc(sizeof(sasl_interact_t));
    client_interact->len=strlen(fillin);
    client_interact->result=(char *) malloc(client_interact->len);
    memcpy((void *)client_interact->result, fillin, client_interact->len);
    }*/

  printf("in client step 2 %s %i\n",in,jlen);

  do {

      result=sasl_client_step(conn, (const char *) in, jlen,
			      &client_interact,
			      &out, &outlen);

      if (result==SASL_INTERACT)
	  fillin_interactions(env,obj,client_interact);
      printf("here\n");

  } while (result==SASL_INTERACT);

  printf("in client step 3\n");


  if ((result!=SASL_OK) && (result!=SASL_CONTINUE))
  {
      /* throw exception */
    throwexception(env,result);
    return NULL;
  }

  /* make byte array to return with stuff to send to server */
  arr=(*env)->NewByteArray(env,outlen);

  (*env)->SetByteArrayRegion(env,arr, 0, outlen, (signed char *) out);

  printf("out looks like %s\n",out);

  return arr;
}


JNIEXPORT void JNICALL Java_sasl_CommonConn_jni_1sasl_1set_1prop_1string
  (JNIEnv *env, jobject obj, jint ptr, jint propnum, jstring val)
{
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  const char *value = (*env)->GetStringUTFChars(env, val, 0);

  int result=sasl_setprop(conn, propnum, value);

  printf("prop res=%i\n",result);

  if (result!=SASL_OK)
    throwexception(env,result);
}


JNIEXPORT void JNICALL Java_sasl_CommonConn_jni_1sasl_1set_1prop_1int
  (JNIEnv *env, jobject obj, jint ptr, jint propnum, jint jval)
{

  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  int value=jval;
  int result;

  result=sasl_setprop(conn, propnum, &value);  
  if (result!=SASL_OK)
    throwexception(env,result);
}
JNIEXPORT void JNICALL Java_sasl_CommonConn_jni_1sasl_1set_1prop_1bytes
  (JNIEnv *env, jobject obj, jint ptr, jint propnum, jbyteArray jarr)
{
  signed char *value = (*env)->GetByteArrayElements(env, jarr, 0);
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  int result;

  result=sasl_setprop(conn, propnum, value);  
  if (result!=SASL_OK)
    throwexception(env,result);

}

/* encode */

JNIEXPORT jbyteArray JNICALL Java_sasl_CommonConn_jni_1sasl_1encode
  (JNIEnv *env, jobject obj, jint ptr, jstring jstr)
{
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  const char *in = (*env)->GetStringUTFChars(env, jstr, 0);
  char *out;
  unsigned int outlen;
  int inlen=strlen(in);
  int result;
  jbyteArray arr;

  result=sasl_encode(conn, in, inlen, &out, &outlen);
  if (result!=SASL_OK)
    throwexception(env,result);

  arr=(*env)->NewByteArray(env,outlen);
  (*env)->SetByteArrayRegion(env,arr, 0, outlen, (signed char *) out);

  (*env)->ReleaseStringUTFChars(env, jstr, in);  

  return arr;
}

/* decode */

JNIEXPORT jbyteArray JNICALL Java_sasl_CommonConn_jni_1sasl_1decode
  (JNIEnv *env, jobject obj, jint ptr, jbyteArray jarr, jint jlen)
{

  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  signed char *in = (*env)->GetByteArrayElements(env, jarr, 0);
  char *out;
  unsigned int outlen;
  int inlen=jlen;
  int result,lup;
  jbyteArray arr;

  result=sasl_decode(conn, (const char *) in, inlen, &out, &outlen);
  if (result!=SASL_OK)
    throwexception(env,result);


  arr=(*env)->NewByteArray(env,outlen);
  (*env)->SetByteArrayRegion(env,arr, 0, outlen, (signed char *) out);

  (*env)->ReleaseByteArrayElements(env, jarr, in,0);

  return arr;

}

/*JNIEXPORT jbyteArray JNICALL Java_sasl_saslServerConn_jni_1sasl_1server_1decode
  (JNIEnv *env, jobject obj, jint ptr, jbyteArray in, jint inlen)
{
  return Java_sasl_saslClientConn_jni_1sasl_1client_1decode(env,obj,ptr,in,inlen);
  }*/

JNIEXPORT void JNICALL Java_sasl_CommonConn_jni_1sasl_1dispose
  (JNIEnv *env, jobject obj, jint ptr)
{
  sasl_conn_t *conn=(sasl_conn_t *) ptr;

  sasl_dispose(&conn);

}

JNIEXPORT jstring JNICALL Java_sasl_ServerConn_jni_1sasl_1server_1getlist
  (JNIEnv *env, jobject obj, jint ptr, jstring jpre, jstring jsep, jstring jsuf)
{
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  const char *pre = (*env)->GetStringUTFChars(env, jpre, 0);
  const char *sep = (*env)->GetStringUTFChars(env, jsep, 0);
  const char *suf = (*env)->GetStringUTFChars(env, jsuf, 0);
  char *list;
  unsigned int plen;
  jstring ret;

  int result=sasl_listmech(conn, NULL, pre, sep, suf, &list, &plen, NULL);

  if (result!=SASL_OK)
  {
    throwexception(env,result);  
    return NULL;
  }

  ret= (*env)->NewStringUTF(env,list);
  if (ret==NULL)
    throwexception(env, -1);

  return ret;
}

JNIEXPORT void JNICALL Java_sasl_CommonConn_jni_1sasl_1set_1server
  (JNIEnv *env, jobject obj, jint ptr, jbyteArray jarr, jint jport)
{
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  signed char *ip = (*env)->GetByteArrayElements(env, jarr, 0);
  struct sockaddr_in addr;
  int result;

  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr, ip, 4);
  addr.sin_port = htons(jport);

  result=sasl_setprop(conn,   SASL_IP_REMOTE, &addr);  

  /* if not set throw and exception */
  if (result!=SASL_OK)
    throwexception(env,result); 
}



JNIEXPORT void JNICALL Java_sasl_CommonConn_jni_1sasl_1set_1client
  (JNIEnv *env, jobject obj, jint ptr, jbyteArray jarr, jint jport)
{
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  signed char *ip = (*env)->GetByteArrayElements(env, jarr, 0);
  struct sockaddr_in addr;
  int result;

  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr, ip, 4);
  addr.sin_port = htons(jport);

  result=sasl_setprop(conn,   SASL_IP_LOCAL, &addr);  

  /* if not set throw and exception */
  if (result!=SASL_OK)
    throwexception(env,result);  
}

/* allocate a secprops structure */

static sasl_security_properties_t *make_secprops(int min,int max)
{
  sasl_security_properties_t *ret=(sasl_security_properties_t *)
    malloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize=1024;
  ret->min_ssf=min;
  ret->max_ssf=max;

  ret->security_flags=0;
  ret->property_names=NULL;
  ret->property_values=NULL;

  return ret;
}


JNIEXPORT void JNICALL Java_sasl_CommonConn_jni_1sasl_1setSecurity
  (JNIEnv *env, jobject obj, jint ptr, jint minssf, jint maxssf)
{
  int result=SASL_FAIL;
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  sasl_security_properties_t *secprops=NULL;
  

  /* set sec props */
  secprops=make_secprops(minssf,maxssf);

  if (secprops!=NULL)
    result=sasl_setprop(conn, SASL_SEC_PROPS, secprops);  

  /* if not set throw and exception */
  if (result!=SASL_OK)
    throwexception(env,result);
}
