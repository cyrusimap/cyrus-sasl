package sasl;

public class saslPrompt
{
  public int id;
  public String prompt;
  public String defaultresult;
  public String result;

  public saslPrompt(int id,String prompt, String dres)
  {
    this.id=id;
    this.prompt=prompt;
    this.defaultresult=dres;
  }
}
