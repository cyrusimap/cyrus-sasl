package sasl;

public interface ClientEchoCB extends ClientCB 
{

  public boolean promptEcho(String defaul,
			    String serverFQDN,
			    String protocol,
			    String challenge,
			    String prompt);
    
  public String getEchoResponse();

}
