package sasl;

import java.io.*;

public class saslFilterInputStream extends FilterInputStream
{
  private static int BUFFERSIZE=2048;
  private byte[] buffer=new byte[BUFFERSIZE];
  private int bufferstart=0;
  private int bufferend=0;

  private ClientConn conn;

  public InputStream in;
    
  public saslFilterInputStream(InputStream in, ClientConn conn)
  {
    super(in);
    this.in = in;
    this.conn=conn;
  }

  public void add_sasl(ClientConn conn)
  {
    this.conn=conn;
  }

  private int buffersize()
  {
    if (bufferend>=bufferstart)
      return bufferend-bufferstart;
    else
      return BUFFERSIZE-bufferend+bufferstart;
  }

  public int available() throws IOException
  {
    return buffersize();
  }

  private int contains_char(char ch)
  {
    if (bufferend>=bufferstart)
    {
      for (int lup=bufferstart;lup<bufferend;lup++)
	if (buffer[lup]==ch)
	  return lup-bufferstart;
    } else {
      for (int lup=bufferend;lup<BUFFERSIZE;lup++)
	if (buffer[lup]==ch)
	  return BUFFERSIZE-lup;
      for (int lup=0;lup<bufferstart;lup++)
	if (buffer[lup]==ch)
	  return BUFFERSIZE-bufferstart+lup;
    }

    return -1;
  }

  private void buffer_add(byte[] str,int len)
  {
    if (str==null)
      return;

    byte[] b=str;

    /* this can be optimized */
    for (int lup=0;lup<len;lup++)
    {
      buffer[bufferend]=b[lup];
      bufferend++;
      if (bufferend==BUFFERSIZE)
	bufferend=0;
      if (bufferend==bufferstart)
	System.out.println("uh oh. this is bad!");
    }
  }

  private void buffer_add(byte[] str)
  {
    buffer_add(str,str.length);
  }

  private void readsome() throws IOException
  {
    byte[]tmp=new byte[1000];

    int len=in.read(tmp,0,1000);

    /* xxx is tmp.length right? */

    if (len>0)
    {
      if (conn==null)
	buffer_add(tmp,len);
      else
	buffer_add( conn.decode(tmp) );
    }

  }
  public void close() throws IOException
  {

  }

  public synchronized void reset() throws IOException
  {
    return;
  }
  public synchronized void mark(int readlimit)
  {
    return;
  }
    
  public boolean markSupported()
  {
    return false;
  }

    /* read a single byte */
  public int read() throws IOException
  {
    int ret;

    if (buffersize()==0)
      readsome();

    ret=buffer[bufferstart];
    bufferstart++;
    if (bufferstart==BUFFERSIZE)
      bufferstart=0;

    return ret;
  }

  public int read(byte b[]) throws IOException
  {
    int len=b.length;

    if ( buffersize()<len)
      readsome();

    for (int lup=0;lup<len;lup++)
    {
      b[lup]=buffer[bufferstart];
      bufferstart++;
      if (bufferstart==BUFFERSIZE)
	bufferstart=0;
      if (bufferstart==bufferend)
	return lup;
    }


    return len;
  }

  public int read(byte b[],
		  int off,
		  int len) throws IOException
  {
    if ( buffersize()<len)
      readsome();

    for (int lup=0;lup<len;lup++)
    {
      b[off+lup]=buffer[bufferstart];
      bufferstart++;
      if (bufferstart==BUFFERSIZE)
	bufferstart=0;
      if (bufferstart==bufferend)
	return lup;
    }

    return len;
  }

  public long skip(long n) throws IOException
  {
    if (n<=0) return 0;

    if ( buffersize()<n)
      readsome();

    int skipped=0;

    while (bufferstart!=bufferend)
    {
      bufferstart++;
      if (bufferstart==BUFFERSIZE)
	bufferstart=0;

      skipped++;
      if (skipped==n)
	return n;
    }
    
    return skipped;    
  }


  public final String readLine() throws IOException
  {
    int pos=0;

    while (true)
    {
      if ((pos=contains_char('\n'))!=-1)
      {
	byte[]ret=new byte[pos];
	read(ret,0,pos);
	skip(1);
	return new String(ret);
      }


      readsome();
    }
  }


}

