package sasl;

// uses javadoc 

/** 
 * Server Factory is used by a server to support authentication. Once
 * the factory is initialized a ServerConn can be obtained with the
 * newconnection() method for each connection
 *
 * @version 1.0
 * @author Tim Martin */

public class ServerFactory
{
  private native int jni_sasl_server_init(String appname);

  /**
   * Allocates a new saslServerFactory for an application;
   * this is a factory of saslServerConn objects.
   *
   * @exception saslException thrown if the SASL library fails to initialize
   */
  private ServerFactory(String appname) throws saslException
  {
    /* load library */
    System.loadLibrary("javasasl");

    jni_sasl_server_init(appname);
  }

  private static ServerFactory inst = null;

 /**
  * Looks up the saslServerFactory singleton instance
  *
  * @param appname the name of the application
  * @exception saslException thrown if the SASL library fails to initialize
  */
  public static ServerFactory instance(String appname) throws saslException
  {
    if (inst == null) {
      /* TODO: This should only be done once, even if called in
       * multiple threads... */
      inst = new ServerFactory(appname);
    }
    return inst;
  }

  private native int jni_sasl_server_new(String service,
					 String local_domain,
					 String user_domain,
					 int secflags);

  /**
   * Creates a new connection for a use authenticating a user. A new
   * connection needs to be created for each connection. The
   * connection will be used for for the entire connection including
   * encoding and decoding
   *
   * @param service service the server implements
   * @param local_domain local domain
   * @param user_domain user domain
   * @param secflags security flags
   * @exception saslException thrown on failure
   * @return a ServerConn to be used for the connection 
   */

  public ServerConn newConnection(String service, 
				  String local_domain,
				  String user_domain,
				  int secflags) throws saslException
  {

     int result=jni_sasl_server_new(service, local_domain,user_domain, secflags);

     ServerConn c=new ServerConn(result);

     return c;
  }
}
