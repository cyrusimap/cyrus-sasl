package sasl;

// uses javadoc 

/** 
 * 
 * @version 1.0
 * @author Tim Martin
 */

public class saslServerFactory
{
  private native int jni_sasl_server_init(String appname);

    /**
     * Allocates a new saslServerFactory for an application;
     * this is a factory of saslServerConn objects.
     *
     * @exception saslException thrown if the SASL library fails to initialize
     */
  private saslServerFactory(String appname) throws saslException
  {
    /* load library */
    System.loadLibrary("javasasl");

    jni_sasl_server_init(appname);
  }

  private static saslServerFactory inst = null;

 /**
  * Looks up the saslServerFactory singleton instance
  *
  * @param appname the name of the application
  * @exception saslException thrown if the SASL library fails to initialize
  */
  public static saslServerFactory instance(String appname) throws saslException
  {
    if (inst == null) {
      /* TODO: This should only be done once, even if called in
       * multiple threads... */
      inst = new saslServerFactory(appname);
    }
    return inst;
  }

  private native int jni_sasl_server_new(String service,
					 String local_domain,
					 String user_domain,
					 int secflags);

  /**
   *
   * @return saslServerConn
   */

  public saslServerConn newConnection(String service, 
				      String local_domain,
				      String user_domain,
				      int secflags)
  {

     int result=jni_sasl_server_new(service, local_domain,user_domain, secflags);

     saslServerConn c=new saslServerConn(result);

     return c;
  }
}
