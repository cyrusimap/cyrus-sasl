package sasl;

import java.net.*;

/**
 * @author Tim Martin
 * @version 1.0
 */

public final class ServerConn extends CommonConn
{

  ServerConn(int cptr)
  {
    ptr=cptr;
    finished=false;
  }

  private native byte[] jni_sasl_server_start(int ptr,
					     String mech, byte[]in, int inlen);
  /**
   * Start authentication. 
   *
   * @param mech mechanism to try
   * @param prompt saslPrompt structure 
   * @exception saslException sasl exception
   * @return the byte[] you should send to the server
   */

  public byte[] start(String mech, byte[]in) throws saslException
  {
    byte [] out=jni_sasl_server_start(ptr, mech,in,in.length);

    if (out==null)
      return null;

    String tmp=new String(out);

    /* c layer replies O(k) or C(ontinue) as first char */
    if (tmp.charAt(0)=='O')
      finished=true;

    return tmp.substring(1).getBytes();
  }

  private native byte[] jni_sasl_server_step(int ptr,
					    byte[] in,
					    int inlen);
					    

  /**
   * Perform a step. start() must have been preformed succesfully
   * before this
   *
   * @param in String from server (must decode64 before)
   * @param prompt saslPrompt structure 
   * @exception saslException sasl exception
   * @return the byte[] you should send to the server
   */
	
  public byte[] step(byte[] in) throws saslException
  {
    byte [] out=null;

    out=jni_sasl_server_step(ptr, in, in.length );

    if (out==null)
      return null;

    String tmp=new String(out);

    /* c layer replies O(k) or C(ontinue) as first char */
    if (tmp.charAt(0)=='O')
      finished=true;

    return tmp.substring(1).getBytes();
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

  public byte[] step(String in) throws saslException
  {
    return step(in.getBytes());
  }

  private native String jni_sasl_server_getlist(int ptr, String prefix,
						String sep, String suffix);

  /**
   * Get list of supported mechanisms for the given user. The returned
   * string is prefix with prefix, sep is placed in between all
   * entries and suffix is placed at the end. If no user is specified
   * the mechanism list for all users is returned.
   *
   * @param user only mechanism available to this user returned
   * @param prefix Prefix for string
   * @param sep String to place in between items in list
   * @param suffix String appended at end
   * @exception saslException sasl exception
   * @return String representing supported mechanisms
   */
  public String getMechanismList(String user,String prefix, String sep,
				 String suffix) throws saslException
  {
      /* xxx user not implemented */
      return jni_sasl_server_getlist(ptr,prefix,sep,suffix);
  }
}
