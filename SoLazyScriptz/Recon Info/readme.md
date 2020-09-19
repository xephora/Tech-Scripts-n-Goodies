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

### [SMB Enumeration p445]
SMBClient
```
Smbclient //ipaddress/share

Retrieving data from share
smbclient //10.1.1.1/share
RECURSE ON
PROMPT OFF
mget *
```
Null Session
```
smbclient -N //IP/Sub
```
SMBv2 Mode
```
smbclient -m SMB2 '//ipaddress/c$/path/to/share' -W <WORKSTATION> -U <username>
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
enum4linux -a IP
```

smbcacls
```
smbcacls -N '//IP/Sub' /Users
```

### [Kerberos Enumeration p88]
```
GetNPUsers.py WORKSTATION/ -dc-ip IP -usersfile /path/to/userslist
GetNPUsers.py NAME.LOCAL/ -dc-ip IP -usersfile /path/to/userslist
```
resources:

https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
### [Windows Remote Management WinRM p5985]
```
ruby evil-winrm.rb -i IP -u username -p 'password' -s '/path/to/scripts/' -e '/path/to/exes/'
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

```
unmount NFS
```
umount -f /tmp/subdirectory
```

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
