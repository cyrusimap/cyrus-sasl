package sasl;

public interface ClientUserIDPasswordCB extends ClientCB 
{

  public boolean promptUserIDPassword(String defaultID,
				      String serverFQDN,
				      String protocol,
				      String prompt1,
				      String prompt2);
    
  public String getUserID();
  public String getPassword();

}
