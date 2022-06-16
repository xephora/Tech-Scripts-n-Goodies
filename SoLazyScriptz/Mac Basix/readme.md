### Useful commands and resources regarding MAC

### Information about Launchd

https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html  
https://medium.com/swlh/how-to-use-launchd-to-run-services-in-macos-b972ed1e352  

### Launchctl commands

https://www.macworld.com/article/221774/take-control-of-startup-and-login-items.html  
https://medium.com/swlh/how-to-use-launchd-to-run-services-in-macos-b972ed1e352  

```
launchctl list
launchctl list | grep <servicename>
launchctl unload /path/to/somefile.plist
launchctl stop <servicename>
launchctl start <servicename>
launchctl restart <servicename>
```

### Custom Logins

https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html

### Startup Paths

https://support.apple.com/en-gb/guide/terminal/apdc6c1077b-5d5d-4d35-9c19-60f2397b2369/mac

### System logs

`/var/log/system.log`

### crontabs

`/var/at/tabs
