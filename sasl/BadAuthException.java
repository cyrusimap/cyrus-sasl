package sasl;

/* authentication failure */

public class BadAuthException extends saslException
{

  BadAuthException() {}

  BadAuthException(String msg)
  {
    super(msg);
  }
}
