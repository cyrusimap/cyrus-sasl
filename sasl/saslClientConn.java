package sasl;

/**
 * This class defines a Client Connection. It is created from the
 * newconnection() method in saslClientConnection().
 */

public final class saslClientConn extends saslCommonConn
{

  saslClientConn(int cptr)
  {
    ptr=cptr;
  }


  private native byte[] jni_sasl_client_start(int ptr,
					  String mechlist,String promptreply);
					  
  /**
   * Start authentication
   *
   * @param mech mechanism to try
   * @param prompt saslPrompt structure 
   * @exception saslException sasl exception
   * @return the byte[] you should send to the server
   */

  public byte[] start(String mech,
	       saslPrompt prompt) throws saslException
  {
    String fillin=null;
    if (prompt!=null)
	fillin=prompt.result;

    byte [] out=jni_sasl_client_start(ptr, mech,fillin);

    return out;
  }

  private native byte[] jni_sasl_client_step(int ptr,
					    byte[] in,
					    int inlen,
					    String promptreply);
					    

  /**
   * Perform a step. start() should have been preformed succesfully
   * before this
   *
   * @param in String from server (must decode64 before)
   * @param prompt saslPrompt structure 
   * @exception saslException sasl exception
   * @return the byte[] you should send to the server
   */
	
  public byte[] step(String in,
	       saslPrompt prompt) throws saslException
  {

    String fillin=null;
    if (prompt!=null)
	fillin=prompt.result;

    byte[] out=null;

    if (in==null)
      out=jni_sasl_client_step(ptr, null, 0,fillin);
    else {
      out=jni_sasl_client_step(ptr, in.getBytes(), in.length(),fillin);
    }

    return out;
  }

  /**
   * Perform a step. start() should have been preformed succesfully
   * before this
   *
   * @param in byte[] from server (must decode64 before)
   * @param prompt saslPrompt structure 
   * @exception saslException sasl exception
   * @return the byte[] you should send to the server
   */

  public byte[] step(byte[] in,
	       saslPrompt prompt) throws saslException
  {
    return step(new String(in), prompt);
  }






}
