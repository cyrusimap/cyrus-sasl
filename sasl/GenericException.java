package sasl;

/*
#define SASL_FAIL       -1    generic failure 
#define SASL_NOMEM      -2    memory shortage failure 
#define SASL_BUFOVER    -3    overflowed buffer 


#define SASL_BADPROT    -5    bad protocol / cancel 

#define SASL_BADPARAM   -7    invalid parameter supplied 
#define SASL_TRYAGAIN   -8    transient failure (e.g., weak key) 
#define SASL_BADMAC	-9    integrity check failed 
                              -- client only codes -- 

#define SASL_BADSERV    -10   server failed mutual authentication step 
#define SASL_WRONGMECH  -11   mechanism doesn't support requested feature 
#define SASL_NEWSECRET  -12   new secret needed 
                              -- server only codes -- 

#define SASL_NOAUTHZ    -14   authorization failure 
#define SASL_TOOWEAK    -15   mechanism too weak for this user 
#define SASL_ENCRYPT    -16   encryption needed to use mechanism 
#define SASL_TRANS      -17   One time use of a plaintext password will
				enable requested mechanism for user 
#define SASL_EXPIRED    -18   passphrase expired, has to be reset 
#define SASL_DISABLED   -19   account disabled 
#define SASL_NOUSER     -20   user not found 
#define SASL_PWLOCK     -21   password locked 
#define SASL_NOCHANGE   -22   requested change was not needed 
define SASL_BADVERS    -23   version mismatch with plug-in 
*/

 
public class GenericException extends saslException
{

  GenericException() {}

  GenericException(String msg)
  {
    super(msg);
  }
}



