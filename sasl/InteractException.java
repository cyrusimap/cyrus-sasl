package sasl;

/* needs user interaction */

public class InteractException extends saslException
{

  saslPrompt prompt;

  InteractException() {}

  InteractException(String msg)
  {
    super(msg);
  }

  void setPrompt(int id,String prompt, String defaultresult)
  {
    this.prompt=new saslPrompt(id,prompt,defaultresult);
  }

}
