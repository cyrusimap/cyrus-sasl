package sasl;

/**
 * This class defines a Client Connection. An object of this type is
 * created from the newconnection() method in ClientFactory(). This
 * object is used for all authentication sessions for the client and
 * after completion Encode and Decode should be called with all
 * subsequent communication with the server 
 */

public final class ClientConn extends CommonConn
{
  private ClientCB callbacks;
  private String serverFQDN;
  private String service;  
  private String defaultAuthID;
  private String defaultUserID;
  private String mechanism;

  /* client specific properties */
  private void setproperties(java.util.Properties props)
  {
    defaultAuthID=props.getProperty("authid");    
    defaultUserID=props.getProperty("userid");
  }

  ClientConn(int cptr, ClientCB cblist, String servername, String service,
	     java.util.Properties props)
  {
    callbacks=cblist;
    ptr=cptr;
    serverFQDN=servername;
    this.service=service;

    /* set any of the properies we got */
    setproperties(props);
    super.setcommonproperties(props);
  }


  private native byte[] jni_sasl_client_start(int ptr,
					      String mechlist);
					  
  /**
   * Start authentication. This should be called with a list of
   * mechanisms the Server supports. This list can usually be obtain
   * from a capability challenge or similar. start() returns a byte
   * array with the initial data the client should send to the
   * server. On sucess the client should check getmechanism() to
   * obtain the name of the mechanism to use. From this data the
   * client can start an authentication attempt.
   *
   * @param mech mechanism to try
   * @exception saslException sasl exception
   * @return the byte[] you should send to the server. null on failure */

  public byte[] start(String mechlist) throws saslException
  {
    byte [] out=jni_sasl_client_start(ptr, mechlist);

    return out;
  }

  

  /**
   * Use this method to obtain the name of the mechanism being
   * negotiated with the server. After giving start() a list of
   * mechanisms one will be chosen. Use this method to determine which
   * one if being used if any.
   *
   * @return the mechanism currently negotiated or already negotiated */

  public String getmechanism()
  {
    return mechanism;
  }

  /* called from C layer */
  private void callback_setmechanism(String mech)
  {
    mechanism=mech;
  }

					    
  /**
   * Perform a step. start() must have been preformed succesfully
   * before this step() can be called. A client should call this
   * method until it receives notification from the server that
   * authentication is complete. Any protocol specific decoding (such
   * as base64 decoding) must be done before calling step(). The
   * return byte array should be encoded by the protocol specific
   * method then sent to the server
   *
   * @param in byte[] from server (must be protocol specific decode before)
   * @exception saslException sasl exception
   * @return the byte[] you should send to the server */
	
  public byte[] step(byte[] in) throws saslException
  {

    byte[] out=null;

    if (in==null)
      out=jni_sasl_client_step(ptr, null, 0);
    else {
      out=jni_sasl_client_step(ptr, in, in.length);
    }

    return out;
  }

  private native byte[] jni_sasl_client_step(int ptr,
					    byte[] in,
					    int inlen);


  /**
   * Perform a step. The byte[] version of step is preferred.
   *
   * @param in String from server (must preform decoding before)
   * @exception saslException sasl exception
   * @return the byte[] client should send to the server
   */

  public byte[] step(String in) throws saslException
  {
    return step(in.getBytes());
  }


  /* The rest of the functions in this file are callbacks. The C layer
   * calls these functions which call functions specified in the ClientCB
   * parameter. It calls the appropriate user function if available then
   * returns the result to the C layer
   *
   */


  private String callback_password(String defresult, String prompt)
  {
    if ((callbacks instanceof ClientPasswordCB)==true)
    {
	ClientPasswordCB cb=(ClientPasswordCB) callbacks;
	cb.promptPassword(defresult,
			  serverFQDN,
			  service,
			  prompt);

	return cb.getPassword();
    } else {
	return null;
    }

  }

  private String callback_authID(String defresult, String prompt)
  {
    if ((callbacks instanceof ClientAuthIDCB)==true)
    {
	ClientAuthIDCB cb=(ClientAuthIDCB) callbacks;
	cb.promptAuthID(defresult,
			serverFQDN,
			service,
			prompt);

	return cb.getAuthID();
    } else {
	return null;
    }
  }


  private String callback_userID(String defresult, String prompt)
  {
    if ((callbacks instanceof ClientUserIDCB)==true)
    {
	ClientUserIDCB cb=(ClientUserIDCB) callbacks;
	cb.promptUserID(defresult,
			serverFQDN,
			service,
			prompt);

	return cb.getUserID();
    } else {
	return null;
    }
  }

  private String callback_authID_password(String defresult, String prompt1,
					  String prompt2)
  {
    if ((callbacks instanceof ClientAuthIDPasswordCB)==true)
    {
	ClientAuthIDPasswordCB cb=(ClientAuthIDPasswordCB) callbacks;
	cb.promptAuthIDPassword(defresult,
				serverFQDN,
				service,
				prompt1,
				prompt2);

	return cb.getAuthID();
    } else {
	return null;
    }
  }

private String callback_userID_password(String defresult, String prompt1,
					String prompt2)
  {

    if ((callbacks instanceof ClientUserIDPasswordCB)==true)
    {
	ClientUserIDPasswordCB cb=(ClientUserIDPasswordCB) callbacks;
	cb.promptUserIDPassword(defresult,
				serverFQDN,
				service,
				prompt1,
				prompt2);

	return cb.getUserID();
    } else {
	return null;
    }
  }

  private String callback_userID_authID_password(String defresult, 
						 String prompt1,
						 String prompt2,
						 String prompt3)
  {
    if (defaultAuthID!=null)
      defresult=defaultAuthID;

    if ((callbacks instanceof ClientUserIDAuthIDPasswordCB)==true)
    {
	ClientUserIDAuthIDPasswordCB cb=(ClientUserIDAuthIDPasswordCB) callbacks;
	cb.promptUserIDAuthIDPassword(defresult,
				      serverFQDN,
				      service,
				      prompt1,
				      prompt2,
				      prompt3);
	return cb.getUserID();
    } else {
	return null;
    }
  }

  private String callback_getauthid(int a)
  {
      /* xxx this could try other things */

    if ((callbacks instanceof ClientAuthIDCB)==true)
    {
	ClientAuthIDCB cb=(ClientAuthIDCB) callbacks;

	return cb.getAuthID();
    } else {
	return null;
    }
  }

  private String callback_getpassword(int a)
  {
      /* xxx this could try other things */

    if ((callbacks instanceof ClientPasswordCB)==true)
    {
	ClientPasswordCB cb=(ClientPasswordCB) callbacks;

	return cb.getPassword();
    } else {
	return null;
    }
  }
  
  private void callback_log(String label, String message)
  {
    if ((callbacks instanceof ClientLogCB)==true)
    {
	ClientLogCB cb=(ClientLogCB) callbacks;

	cb.log(serverFQDN,
	       label,
	       message);

    }
  }

  private String callback_echo(String defresult, String challenge,String prompt)
  {
    if ((callbacks instanceof ClientEchoCB)==true)
    {
	ClientEchoCB cb=(ClientEchoCB) callbacks;

	cb.promptEcho(defresult,
		      serverFQDN,
		      service,
		      challenge,
		      prompt);

	return cb.getEchoResponse();
    } else {
	return null;
    }
  }

  private String callback_noecho(String defresult, String challenge, String prompt)
  {
    if ((callbacks instanceof ClientNoEchoCB)==true)
    {
	ClientNoEchoCB cb=(ClientNoEchoCB) callbacks;

	cb.promptNoEcho(defresult,
		      serverFQDN,
		      service,
		      challenge,
		      prompt);

	return cb.getNoEchoResponse();
    } else {
	return null;
    }
  }



}
