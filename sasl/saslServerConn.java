package sasl;

import java.net.*;

public final class saslServerConn extends saslCommonConn
{

  saslServerConn(int cptr)
  {
    ptr=cptr;
    finished=false;
  }

  private native byte[] jni_sasl_server_start(int ptr,
					     String mech, byte[]in, int inlen);
  /**
   * Start authentication
   *
   * @param mech mechanism to try
   * @param prompt saslPrompt structure 
   * @exception saslException sasl exception
   * @return the byte[] you should send to the server
   */

  public byte[] start(String mech, byte[]in, int inlen) throws saslException
  {
    byte [] out=jni_sasl_server_start(ptr, mech,in,inlen);

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
   * Perform a step. start() should have been preformed succesfully
   * before this
   *
   * @param in String from server (must decode64 before)
   * @param prompt saslPrompt structure 
   * @exception saslException sasl exception
   * @return the byte[] you should send to the server
   */
	
  public byte[] step(String in) throws saslException
  {

    byte[] inn=new byte[100];
    
    for (int lup=0;lup<in.length();lup++)
    {
	inn[lup]=(byte)(in.charAt(lup));
    }

    byte [] out=null;

    out=jni_sasl_server_step(ptr, in.getBytes(), in.length() );

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

  public byte[] step(byte[] in) throws saslException
  {
    return step(new String(in) );
  }

  private native String jni_sasl_server_getlist(int ptr, String prefix,
						String sep, String suffix);

  public String getMechanismList(String prefix, String sep,
			  String suffix) throws saslException
  {

      String a=jni_sasl_server_getlist(ptr,prefix,sep,suffix);

      return a;
  }
}
