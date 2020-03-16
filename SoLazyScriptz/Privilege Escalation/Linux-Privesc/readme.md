This section contains privilege escalation checking tools for linux.

https://raw.githubusercontent.com/carlospolop/linux-privilege-escalation-awsome-script/master/linpeas.sh

https://github.com/diego-treitos/linux-smart-enumeration

chmod +x linpeas.sh
./linpeas > dump.log

chmod +x ./lse.sh
./lse.sh -l2 >> linenum.log

https://github.com/lucyoa/kernel-exploits

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

Processes:
top

https://raw.githubusercontent.com/carlospolop/linux-privilege-escalation-awsome-script/master/linpeas.sh
https://github.com/1N3/PrivEsc/tree/master/linux/scripts

Enumeration of plaintext password
grep -rnw '/' -ie 'pass' --color=always
grep -rnw '/' -ie 'DB_PASS' --color=always
grep -rnw '/' -ie 'DB_PASSWORD' --color=always
grep -rnw '/' -ie 'DB_USER' --color=always
