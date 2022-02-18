### get processes
```
ps aux
ps aux | grep <processname>

ps -eaf --forest 
```

### Process managing
```
CTL+Z to suspend processes
bg to background process

jobs to view suspended processes

fg %<JOB#> returns a job
```

### get ports
```
lsof
lsof -i :<PORT>

netstat -Aan
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

### Creating cron jobs (Each Astrick represents [Minutes, Hours, Weeks, Months, Years])
```
crontab -e

This example executes script.sh every 30 minutes
30 * * * * /root/script.sh
```

### view active connections (associated processes)
```
ss -anp 
ss -ltp
ss -ltpn
ss -lpn
ss -anp | grep <pid>
ss -lpn | grep <pid> 
ss -lpn | grep 443
ss -lpn | grep 4444 | grep pid
ss -ant
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

Example:
cd /usr/bin
ln -s python2.7 python
```
https://www.howtogeek.com/287014/how-to-create-and-use-symbolic-links-aka-symlinks-on-linux/  
https://www.youtube.com/watch?v=tkuYrwzQ7N4  

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

Remove a line with a specific character thanks to @dee-see
sed '/\*/d' file

Remove lines that have less than a number of characters (Great for huge logs)
sed -r '/^.{,5}$/d' file
```

### awk
```
print the first column of characters
awk '{print $1}'

print specific columns
awk '{print $1,$4}'

Remove a character and print column of characters
awk -F \] '{print $1}'
awk -F\@ '{print $1}'

Remove lines with that have a specific character
awk -F 'C' 'NF!=2' file
```

### gunzip

```
gunzip -d filename.tar.gz
```

### tar

```
tar -xvf file.tar
```

### 7z

```
7z x file.7z
```

### zip

```
unzip file.zip
```

### rar

```
unzip file.rar
```

### Creating a new salted password hash using openssl

```
openssl passwd -1 -salt [salt] [password]
```

### sort and remove duplicates

```
sort -u
```

### permissions
https://kb.iu.edu/d/abdb#:~:text=To%20change%20file%20and%20directory,%2C%20write%2C%20and%20execute%20permissions.

```
adding read and write for all users
chmod a+w+x filename

removing permissions for all
chmod a-w+x filename
```

### cli copy paste
https://ostechnix.com/how-to-use-pbcopy-and-pbpaste-commands-on-linux/

```
cat file.txt | pbcopy
```

### echo multiple lines to a file

```
echo """
line1
line2
line3
line4
""" > dump.log
```

### Updating MSFConsole on kali

```
1. Update metasploit framework by typing 'apt update; apt install metasploit-framework'
2. cd to '/usr/share/metasploit-frame'
3. update your gems by running 'bundle install'
```

### piping commands to an output of data (Thanks to @Dee-see for providing this!)

```
cat file.txt | awk '{print $3}' | while read i; do <command> $i; done
```

### Get disks

```
fdisk -l
```

### Get Mountpoints

```
cat /proc/mounts
```

### restart your logon session
```
switch tty using ctl+alt+F6 then login to your account (cli)

w
pkill -9 -t <TTY> (session associated with TTY7 normally)
```

### Recursively downloads files

```
wget -m http://server/path/to/directory/
```

### Remove user from sudo group
https://askubuntu.com/questions/335987/remove-sudo-privileges-from-a-user-without-deleting-the-user
```
sudo gpasswd -d <username> sudo
```

### configuring ssh
https://linuxize.com/post/how-to-enable-ssh-on-ubuntu-20-04/  
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/v2v_guide/preparation_before_the_p2v_migration-enable_root_login_over_ssh  

### Setting up apache
https://www.digitalocean.com/community/tutorials/how-to-install-the-apache-web-server-on-ubuntu-18-04-quickstart

### Creating aliases
https://www.tecmint.com/create-alias-in-linux/

```
nano ~/.bashrc
alias powershell='pwsh'
```

### Creating an HTTP/FTP Server python

```
python3 -m http.server 80
python3 -m pyftpdlib -p 21
```

### Locate and kill pts/tty by pid

```
w
ps -ft pts/#
kill -9 <PID>
w
```

### Removing lines from a file based on a keyword (thanks to @frostb1te for recommending this)

```
sed '/test/d' ./fileToRemoveStrings.txt
sed -i '/test/d' ./fileToRemoveStrings.txt
```
