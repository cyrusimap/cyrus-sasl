class saslCommonConnection
{
      
  private saslMechList mechlist;


  public saslCommonConnection() throws saslException 
  {
  }
  public saslCommonConnection(saslMechList list, 
			 String appname) throws saslException 
  {
  }

  String getProperty() throws saslException 
  {
      return null;
  }

  /**
   *
   * @returns base 64 encoded string
   */

  byte []encode64(byte []in) throws saslException 
  {
      return null;
  }

  /**
   *
   * @returns base 64 decoded string
   */

  byte []decode64(byte []in) throws saslException
  {
      return null;
  }


}
