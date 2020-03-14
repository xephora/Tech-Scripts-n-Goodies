read -p 'Enter Username: ' user

#Checks the common locations of malware, spyware and saves logs to the current location
echo "System Files Inspected" >> InspectionLog.txt
ls -lt /var/root >> InspectionLog.txt
ls -lt "/Library/Application Support" >> InspectionLog.txt
ls -lt /Library/LaunchDaemons >> InspectionLog.txt
ls -lt /Library/LaunchAgents >> InspectionLog.txt
echo "User based Files Inspected" >> InspectionLog.txt
ls -lt /Users/$user/Library/LaunchAgents >> InspectionLog.txt
ls -lt "/Users/$user/Library/Application Support" >> InspectionLog.txt
ls -lt /Users/<username>/Library >> InspectionLog.txt
echo "Startup Locations and Applications" >> InspectionLog.txt
ls -lt /Library/startupItems >> InspectionLog.txt
ls -lt /System/Library/StartupItems >> InspectionLog.txt
ls -lt /System/Library/LaunchDaemons >> InspectionLog.txt
ls -lt /Library/LaunchAgents >> InspectionLog.txt
ls -lt /Applications >> InspectionLog.txt

#check processes, Listening Ports and Services saves logs to current location
ps aux > Active_Processes.log 
lsof > Listening_Ports.log 
launchctl list > Service_list.log
