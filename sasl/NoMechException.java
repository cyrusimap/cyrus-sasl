package sasl;

/* mechanism not supported */

public class NoMechException extends saslException
{

  NoMechException() {}

  NoMechException(String msg)
  {
    super(msg);
  }
}
