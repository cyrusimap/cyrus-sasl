package sasl;

public interface ClientLogCB extends ClientCB 
{

  public boolean log(String serverFQDN,
		     String label,
		     String message);   

}
