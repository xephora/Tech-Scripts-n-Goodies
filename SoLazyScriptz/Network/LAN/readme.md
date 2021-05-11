### [adding/removing rules to iptables]
> Notes taken from the following ippsec video https://www.youtube.com/watch?v=2OWtEymBQfA&t=1.

```
sudo iptables -A INPUT -i <adapter_name> -p tcp --dport <PORT> -j DROP
sudo iptables -D INPUT -i <adapter_name> -p tcp --dport <PORT> -j DROP

sudo iptables -I DOCKER-USER -i <adapter_name> -p tcp --dport <PORT> -j DROP
sudo iptables -D DOCKER-USER -i <adapter_name> -p tcp --dport <PORT> -j DROP

sudo iptables -I DOCKER-USER -i <adapter_name> -p tcp --dport <PORT> -j REJECT
sudo iptables -D DOCKER-USER -i <adapter_name> -p tcp --dport <PORT> -j REJECT

sudo iptables -I DOCKER-USER -i <adapter_name> -p tcp --dport <PORT> -j REJECT --reject-with tcp-reset
sudo iptables -D DOCKER-USER -i <adapter_name> -p tcp --dport <PORT> -j REJECT --reject-with tcp-reset
```

### [Using fping to scan the whole network of a host]
```
This command will only display alive hosts and supress errors

fping -q -a -g -r 1 <IP>/24
```

### [Checking if port is communicates in powershell]

https://docs.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection?view=win10-ps

```
Test-NetConnection -ComputerName <IPAddress -Port <PORT>
```

### [manual ping sweep loop]

https://tablo.io/bryan-m-speirs/how-to-find-a-spare-ip-address-or-block-of-ip

```
FOR /L %i IN (1,1,254) DO ping -n 1 192.168.1.%i | FIND /i "Reply">>c:\path\to\ipaddresses.txt
```

### Port Knocking
https://github.com/grongor/knock

```
./knock <IP> <PORT1> <PORT2> <PORT3>
```

###  reverse lookups

```
nmap --dns-servers <nsip> -R <rhost>

nslookup
server <nsip>
set type=ptr
<rhost>

ping -a <rhost>
```
