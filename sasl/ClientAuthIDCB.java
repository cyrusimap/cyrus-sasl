package sasl;

public interface ClientAuthIDCB extends ClientCB 
{

  public boolean promptAuthID(String defaultID,
			      String serverFQDN,
			      String protocol,
			      String prompt);
    
  public String getAuthID();

}
