ls -la /Library/startupItems >> StartupLocations.log 
ls -la /System/Library/StartupItems >> StartupLocations.log 
ps aux > Active_Processes.log 
lsof > Listening_Ports.log 
launchctl list > Service_list.log
