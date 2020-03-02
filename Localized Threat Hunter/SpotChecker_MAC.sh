ls -lt /Library/startupItems >> StartupLocations.log 
ls -lt /System/Library/StartupItems >> StartupLocations.log 
ls -lt /System/Library/LaunchDaemons >> ServiceLocations.log
ls -lt /Library/LaunchAgents >> ServiceLocations.log
ls -lt /Applications >> Applications.log
ps aux > Active_Processes.log 
lsof > Listening_Ports.log 
launchctl list > Service_list.log
