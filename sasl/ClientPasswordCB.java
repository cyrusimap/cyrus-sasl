package sasl;

public interface ClientPasswordCB extends ClientCB 
{

  public boolean promptPassword(String defaultID,
				String serverFQDN,
				String protocol,
				String prompt);
    
  public String getPassword();

}
