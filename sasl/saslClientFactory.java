package sasl;

// uses javadoc 

/** 
 * 
 * @version 1.0
 * @author Tim Martin
 */

public class saslClientFactory
{

    /* JNI functions  */
  private native int jni_sasl_client_init(String appname);
  private native int jni_sasl_client_new(String service,
					 String serverFQDN,
					 int secflags);


  /**
   * Initialize the SASL client session
   * This must be the first thing called
   *
   * @param appname string of the name of the application
   * @exception saslException thrown if the SASL library fails to initialize
   */
  private saslClientFactory(String appname) throws saslException
  {
    /* load library */
    System.loadLibrary("javasasl");

    jni_sasl_client_init(appname);
  }

  private static saslClientFactory inst = null;

 /**
  * Looks up the saslClientFactory singleton instance
  *
  * @param appname the name of the application
  * @exception saslException thrown if the SASL library fails to initialize
  */
  public static saslClientFactory instance(String appname) throws saslException
  {
    if (inst == null) {
      /* TODO: This should only be done once, even if called in
       * multiple threads... */
      inst = new saslClientFactory(appname);
    }
    return inst;
  }

  /**
   *
   * @param service SASL service name of the protocol (i.e. IMAP, SMTP, etc)
   * @param serverFQDN canonical name of the server
   * @param secflags security flags
   *
   * @return saslClientConn a saslClientConn that can be used for
   *                        interactions with this server
   */

  public saslClientConn newConnection(String service, 
				      String serverFQDN,
				      int secflags)
  {

     int result=jni_sasl_client_new(service, serverFQDN, secflags);

     saslClientConn c=new saslClientConn(result);

     return c;
  }

}
