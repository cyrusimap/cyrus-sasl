package sasl;

public interface ClientUserIDAuthIDPasswordCB extends ClientCB 
{

  public boolean promptUserIDAuthIDPassword(String defaultID,
					    String serverFQDN,
					    String protocol,
					    String prompt1,
					    String prompt2,
					    String prompt3);
    
  public String getUserID();
  public String getAuthID();
  public String getPassword();

}
