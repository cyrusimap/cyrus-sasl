package sasl;

import java.io.*;

public class saslFilterOutputStream
{
  private static int MAXBUFFERSIZE=1000;
  private saslClientConn conn;
  OutputStream out;
    
  private byte[] buffer=new byte[MAXBUFFERSIZE];
  private int buffersize=0;

  public saslFilterOutputStream(OutputStream out, saslClientConn conn)
  {
    this.conn=conn;
    this.out=out;
  }

  public void add_sasl(saslClientConn conn) throws IOException
  {
    flush();
    this.conn=conn;
  }

  private void write_if_size() throws IOException
  {
    if ( buffersize >=MAXBUFFERSIZE)
      flush();
  }

  public void write(int b) throws IOException
  {
    buffer[buffersize]=(byte) b;
    buffersize++;
    write_if_size();
  }

  public void write(byte b[]) throws IOException
  {
    write(b,0,b.length);
  }

  public void write(byte b[],
                   int off,
                   int len) throws IOException
  {
    if (len+buffersize < MAXBUFFERSIZE)
    {
      for (int lup=0;lup<len;lup++)
      {   
	buffer[buffersize+lup]=b[lup+off];
      }
      buffersize+=len;

      write_if_size();

    } else {
      flush();

      String str=new String(b,off,len);
      if (conn==null)
	out.write( b);
      else
	out.write( conn.encode(str) );
      out.flush();
    }
  }

  public void flush() throws IOException
  {
    if (buffersize==0) return;

    String str=new String(buffer,0,buffersize);

    if (conn==null)
      out.write(buffer,0,buffersize);
    else
      out.write( conn.encode(str) );
    out.flush();
    buffersize=0;
  }

  public void close() throws IOException
  {
    flush();
    out.close();
  }


}
