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
