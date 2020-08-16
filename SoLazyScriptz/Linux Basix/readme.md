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

