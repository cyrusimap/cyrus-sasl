package sasl;

/**
 * saslException is the base class of all SASL exceptions.
 */
public class saslException extends java.lang.Exception
{

  /** This is filled in if the appropriate exception is thrown
   */

  saslException() {}

  saslException(String msg)
  {
    super(msg);
  }
}





