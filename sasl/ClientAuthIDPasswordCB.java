package sasl;

public interface ClientAuthIDPasswordCB extends ClientCB 
{

  public boolean promptAuthIDPassword(String defaultID,
				      String serverFQDN,
				      String protocol,
				      String prompt1,
				      String prompt2);
    
  public String getAuthID();
  public String getPassword();

}
