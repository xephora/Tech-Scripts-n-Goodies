### [Resources for Linux Privesc]
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

https://github.com/diego-treitos/linux-smart-enumeration

https://github.com/lucyoa/kernel-exploits

### [Running your scripts]
```
chmod +x linpeas.sh
./linpeas > dump.log

chmod +x ./lse.sh
./lse.sh -l2 >> linenum.log
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

[Generating Public Keys and Xfering to your target]
```
1. ssh-keygen to create your paired keys (private + public)
2. cat your key.pub and copy and paste the public key data over to the host's authorized keys in /home/username/.ssh/authorized_keys
3. ssh into the box using your private key ssh -i privatekey username@IP
```
