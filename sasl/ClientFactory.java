package sasl;

// uses javadoc 

/** 
 * 
 * @version 1.0
 * @author Tim Martin
 */

public class ClientFactory
{

  private static ClientCB cblist=null;

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
  private ClientFactory(String appname) throws saslException
  {
    /* load library */
    System.loadLibrary("javasasl");

    jni_sasl_client_init(appname);
  }

  private static ClientFactory inst = null;

 /**
  * Looks up the saslClientFactory singleton instance.
  *
  * @param appname the name of the application
  * @param callbacks callbacks class that implements one or more callbacks. 
  *                  See ClientCB for definition of available callbacks
  * @exception saslException thrown if the SASL library fails to initialize */
  public static ClientFactory instance(String appname,
				       ClientCB callbacks) throws saslException
  {
    if (inst == null) {
      cblist=callbacks;
      /* TODO: This should only be done once, even if called in
       * multiple threads... */
      inst = new ClientFactory(appname);
    }

    return inst;
  }

  /**
   * Create a new connection. A new connection must be made for each
   * connection a sever wants to a server. A ClientConn object is
   * returned which will be used for the life of the connection. The
   * props arguement specified may contain any of the properties
   * below.
   *
   * <pre>Properties: 
   *
   *  "authid" - Default authid. This overrides any authid callbacks
   *  "userid" - Default userid. This overrides any userid callbacks
   *
   *  "security.policy.encryption.min" - default value 0. Minimum
   *    security layer strength factor to negotiate. Roughly correlated
   *    to effective key length for encryption. See table below.
   *
   *  "security.policy.encryption.max" - default value 256. Maximum
   *    security layer strength factor to negotiate. See table below
   *
   *  "security.policy.encryption.external" - default value 0. External
   *    security layer strength factor. See table below
   *
   *         0   = no protection
   *         1   = integrity protection only
   *         40  = 40-bit DES or 40-bit RC2/RC4
   *         56  = DES
   *         112 = triple-DES
   *         128 = 128-bit RC2/RC4/BLOWFISH
   *
   *   "security.ipv4.local"  - Should be of form "%d.%d.%d.%d:%d"
   *   "security.ipv4.remote" - Should be of form "%d.%d.%d.%d:%d"
   *
   *   "security.ipv6.local"  - Not implemented
   *   "security.ipv6.remote" - Not implemented
   *
   *   "security.maxbuf" - The maximum buffer size that can be
   *   accepted. Default value is 65000
   * </pre>
   *
   * @param service SASL service name of the protocol (i.e. IMAP, SMTP, etc)
   * @param serverFQDN canonical name of the server
   * @param secflags security flags
   * @param props Properties for connection. See list above.
   *
   * @return saslClientConn a saslClientConn that can be used for
   *                        interactions with this server */

  public ClientConn newConnection(String service, 
				  String serverFQDN,
				  int secflags,
				  java.util.Properties props)

  {
     int result=jni_sasl_client_new(service, serverFQDN, secflags);

     ClientConn c=new ClientConn(result,cblist,serverFQDN,service,props);

     return c;
  }

}
