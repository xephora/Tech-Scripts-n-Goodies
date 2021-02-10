### Resources:
https://docs.microsoft.com/en-us/powershell/module/smbshare/get-smbshareaccess?view=win10-ps  


### [search for string within files using powershell]
```
findstr /s "keyword" .\*
cat filename | findstr "keyword"
```

### [Recursive search using powershell]
```
gci -r -fi NameOfFile.exe
gci -r -fi NameOf*
gci -r -fi *.exe
```

### [Create network share using powershell]
```
$pass = convertto-securestring '<RemotePASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<RemoteUsername>', $pass)
New-PSDrive -Name drivename -PSProvider FileSystem -Credential $cred -Root \\<RemoteIP>\<RemoteShare>
```

### [Creating a new scheduled task]
```
$A = New-ScheduledTaskAction -Execute "Taskmgr.exe"
$T = New-ScheduledTaskTrigger -AtLogon
$P = New-ScheduledTaskPrincipal "Domain\Account"
$S = New-ScheduledTaskSettingsSet
$D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
Register-ScheduledTask T1 -InputObject $D
```

### [Disable a scheduled task]
```
Disable-ScheduledTask -TaskName "SystemScan"
```

### [Disable all scheduled tasks in a folder]
```
Get-ScheduledTask -TaskPath "\UpdateTasks\" | Disable-ScheduledTask
```

### [Get SMB Shares and Mappings]
```
Get-SMBShare
Get-SmbShare -Name "C$" | Format-List

Get-SmbMapping
```

### [Get SMB Share Access]
```
Get-SmbShareAccess -Name "C$"
```

### [Get Volumes]
```
Get-Volume
```

### [uninstall msi packages]
```
List All Package Names:
Get-WmiObject -Class Win32_Product

Uninstall:
$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "keyword"}
$MyApp.Uninstall()

List All Package Names:
Get-Package -Provider Programs -IncludeWindowsInstaller

List Specific Package Name: 
Get-Package -Provider Programs -IncludeWindowsInstaller -Name "Keyword"
Get-Package -Provider Programs -IncludeWindowsInstaller -Name "Keyword*"

Uninstall Package:
Get-Package -Provider Programs -IncludeWindowsInstaller -Name "Keyword" | Uninstall-Package -Force
```

### [Exporting EventLogs and using DeepBlue (Recommended by Frostb1te]

https://github.com/sans-blue-team/DeepBlueCLI/blob/master/DeepBlue.ps1

```
wevtutil epl System C:\TEMP\System_log.evtx

.\DeepBlue.ps1 -log system
.\DeepBlue.ps1 C:\TEMP\System_log.evtx
```

### [Get / Stop / Disable Service using powershell]

Get Services:
```
Get-Service | select -property name,starttype

Get a particular service name:

Get-Service | select -property name,starttype | findstr "ServiceName"
```

Stop a service:

```
Get-Service -DisplayName "ServiceName" | Stop-Service
```
Stop a service with dependencies:

```
Stop-Service -Name "ServiceName" -Force
```

Disable service:

```
Set-Service -Name "ServiceName" -Status stopped -StartupType disabled
```

Count files in directory
https://superuser.com/questions/959036/what-is-the-windows-equivalent-of-wc-l

```
(ls | Measure-Object -line).Lines
```
