### get processes
```
ps aux
ps aux | grep <processname>
```

### get ports
```
lsof
lsof | grep <port>
```

### get services
```
systemctl list-units --type=service

active services:
systemctl list-units --type=service --state=active
```

### view cron jobs
```
crontab -l
cat /etc/crontab
```

### Kill a process
```
kill -9 <pid>
```

### Kill a port
```
lsof | grep <port>
kill -9 <pid> associated with port
```

### remove cron tab
```
crontab -r [username]
ls /var/spool/cron/crontabs
crontab -e
```

### Creation Symbolic Links
```
ln -s /path/to/original /path/to/link
```
https://www.howtogeek.com/287014/how-to-create-and-use-symbolic-links-aka-symlinks-on-linux/

### Creating Services
https://linuxconfig.org/how-to-create-systemd-service-unit-in-linux

### Port forwarding using SSH
```
ssh -R 80:127.0.0.1:80 <username>@<ipaddr>
ssh -R 80:127.0.0.1:80 -i id_rsa <username>@<ipaddr>
```
https://www.kalilinux.in/2019/07/port-forwarding-using-ssh.html

### stop, start, status of service
```
systemctl stop <servicename>
systemctl start <servicename>
systemctl status <servicename>
```

### Creating environmental variables
```
export VARIABLE=/path/to/credentials
export VARIABLE=username
export VARIABLE=key
export TERM=xterm
```

### Searching for files
```
locate python
find . | grep python

update filesystem index:
updatedb
```

### sed
```
Remove a dot at the end of a line
cat file.txt | sed -r 's/\.$//'

Remove a character from a string
sed 's/a//' example.txt
```

### awk
```
print the first column of characters
awk '{print $1}'

print specific columns
awk '{print $1,$4}'
```
