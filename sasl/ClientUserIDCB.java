package sasl;

public interface ClientUserIDCB extends ClientCB 
{

  public boolean promptUserID(String defaultID,
			      String serverFQDN,
			      String protocol,
			      String prompt);
    
  public String getUserID();

}
