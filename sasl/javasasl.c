/* javasasl.c--Java SASL JNI implementation
 * Tim Martin
 * $Id: javasasl.c,v 1.2 1998/11/16 23:03:21 tmartin Exp $
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

#include <config.h>
#include <stdio.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "javasasl.h"

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

JNIEXPORT jint JNICALL Java_sasl_saslServerFactory_jni_1sasl_1server_1init
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

/* client init */

JNIEXPORT jint JNICALL Java_sasl_saslClientFactory_jni_1sasl_1client_1init
  (JNIEnv *env, jobject obj, jstring jstr)
{
  /* Obtain a C-copy of the Java string */
  const char *str = (*env)->GetStringUTFChars(env, jstr, 0);
  int result;

  result=sasl_client_init(NULL);
  if (result!=SASL_OK)
    throwexception(env,result);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jstr, str);

  return result;
}

/* server new */

JNIEXPORT jint JNICALL Java_sasl_saslServerFactory_jni_1sasl_1server_1new
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


JNIEXPORT jint JNICALL Java_sasl_saslClientFactory_jni_1sasl_1client_1new
  (JNIEnv *env, jobject obj,
   jstring jservice, jstring jserver, jint jsecflags)
{
  sasl_conn_t *conn;

  const char *service = (*env)->GetStringUTFChars(env, jservice, 0);
  const char *serverFQDN = (*env)->GetStringUTFChars(env, jserver, 0);
  int result;

  result=sasl_client_new(service, serverFQDN, NULL, jsecflags, &conn);
  if (result!=SASL_OK)
    throwexception(env,result);

  /* Now we are done with str */
  (*env)->ReleaseStringUTFChars(env, jservice, service);  
  (*env)->ReleaseStringUTFChars(env, jserver, serverFQDN);  

  return (jint) conn;
}

/* server start */

JNIEXPORT jbyteArray JNICALL Java_sasl_saslServerConn_jni_1sasl_1server_1start
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



/* client start */

JNIEXPORT jbyteArray JNICALL Java_sasl_saslClientConn_jni_1sasl_1client_1start
  (JNIEnv *env, jobject obj, jint ptr, jstring jstr, jstring jfill)
{    
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
   const char *mechlist = (*env)->GetStringUTFChars(env, jstr, 0);
  char *out;
  unsigned int outlen;
  const char *mechusing;
  int result;
  sasl_secret_t *secret;
  sasl_interact_t *client_interact=NULL;
  jbyteArray arr;
  signed char *a;
  const char *fillin;



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


  result=sasl_client_start(conn, mechlist,
			   secret, &client_interact,
			   &out, &outlen,
			   &mechusing);

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

JNIEXPORT jbyteArray JNICALL Java_sasl_saslServerConn_jni_1sasl_1server_1step
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

JNIEXPORT jbyteArray JNICALL Java_sasl_saslClientConn_jni_1sasl_1client_1step
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

  /* if got info for an interact make one */
  if (jstr!=NULL)
  {
    fillin=(*env)->GetStringUTFChars(env, jstr, 0);
    client_interact=(sasl_interact_t *) malloc(sizeof(sasl_interact_t));
    client_interact->len=strlen(fillin);
    client_interact->result=(char *) malloc(client_interact->len);
    memcpy((void *)client_interact->result, fillin, client_interact->len);
  }

  out=(char *) malloc(1000);

  result=sasl_client_step(conn, (const char *) in, jlen,
			  &client_interact,
			  &out, &outlen);



  if (result==SASL_INTERACT)
  {
    throwinteract(env,client_interact);
    return NULL;
  }

  if ((result!=SASL_OK) && (result!=SASL_CONTINUE))
  {
      /* throw exception */
    throwexception(env,result);
    return NULL;
  }


  /* make byte array to return with stuff to send to server */
  arr=(*env)->NewByteArray(env,outlen);

  (*env)->SetByteArrayRegion(env,arr, 0, outlen, (signed char *) out);

  free(out);

  return arr;
}


JNIEXPORT void JNICALL Java_sasl_saslCommonConn_jni_1sasl_1set_1prop_1string
  (JNIEnv *env, jobject obj, jint ptr, jint propnum, jstring val)
{
  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  const char *value = (*env)->GetStringUTFChars(env, val, 0);

  int result=sasl_setprop(conn, propnum, value);
  if (result!=SASL_OK)
    throwexception(env,result);
}


JNIEXPORT void JNICALL Java_sasl_saslCommonConn_jni_1sasl_1set_1prop_1int
  (JNIEnv *env, jobject obj, jint ptr, jint propnum, jint jval)
{

  sasl_conn_t *conn=(sasl_conn_t *) ptr;
  int value=jval;
  int result;

  result=sasl_setprop(conn, propnum, &value);  
  if (result!=SASL_OK)
    throwexception(env,result);
}
JNIEXPORT void JNICALL Java_sasl_saslCommonConn_jni_1sasl_1set_1prop_1bytes
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

JNIEXPORT jbyteArray JNICALL Java_sasl_saslCommonConn_jni_1sasl_1encode
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

JNIEXPORT jbyteArray JNICALL Java_sasl_saslCommonConn_jni_1sasl_1decode
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

JNIEXPORT void JNICALL Java_sasl_saslCommonConn_jni_1sasl_1dispose
  (JNIEnv *env, jobject obj, jint ptr)
{
  sasl_conn_t *conn=(sasl_conn_t *) ptr;

  sasl_dispose(&conn);

}

JNIEXPORT jstring JNICALL Java_sasl_saslServerConn_jni_1sasl_1server_1getlist
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

JNIEXPORT void JNICALL Java_sasl_saslCommonConn_jni_1sasl_1set_1server
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



JNIEXPORT void JNICALL Java_sasl_saslCommonConn_jni_1sasl_1set_1client
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


JNIEXPORT void JNICALL Java_sasl_saslCommonConn_jni_1sasl_1setSecurity
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
