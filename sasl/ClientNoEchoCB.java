package sasl;

public interface ClientNoEchoCB extends ClientCB 
{

  public boolean promptNoEcho(String defaul,
			      String serverFQDN,
			      String protocol,
			      String challenge,
			      String prompt);
    
  public String getNoEchoResponse();

}
