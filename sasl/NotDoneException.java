package sasl;

/* can't request info until later in exchange */
public class NotDoneException extends saslException
{

  NotDoneException() {}

  NotDoneException(String msg)
  {
    super(msg);
  }
}
