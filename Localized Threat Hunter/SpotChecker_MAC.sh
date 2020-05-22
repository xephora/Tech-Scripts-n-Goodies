read -p 'Enter Username: ' user

#Checks the common locations of malware, spyware and saves logs to the current location
echo -e "\e[92mSystem Files Inspected\e[0m" >> InspectionLog.txt
ls -lt /var/root >> InspectionLog.txt
ls -lt "/Library/Application Support" >> InspectionLog.txt
ls -lt /Library/LaunchDaemons >> InspectionLog.txt
ls -lt /Library/LaunchAgents >> InspectionLog.txt
echo -e "\e[92mUser based Files Inspected\e[0m" >> InspectionLog.txt
ls -lt /Users/$user/Library/LaunchAgents >> InspectionLog.txt
ls -lt "/Users/$user/Library/Application Support" >> InspectionLog.txt
ls -lt /Users/<username>/Library >> InspectionLog.txt
echo -e "\e[92mStartup Locations and Applications\e[0m" >> InspectionLog.txt
ls -lt /Library/startupItems >> InspectionLog.txt
ls -lt /System/Library/StartupItems >> InspectionLog.txt
ls -lt /System/Library/LaunchDaemons >> InspectionLog.txt
ls -lt /Library/LaunchAgents >> InspectionLog.txt
ls -lt /Applications >> InspectionLog.txt
echo -e "\e[92mChecking Crontab\e[0m" >> InspectionLog.txt
ls -lt /var/at/tabs >> InspectionLog.txt

echo -e "\e[92mChecking Processes, Ports, Network Activity and Services\e[0m"
ps aux > Active_Processes.log 
lsof > Listening_Ports.log
netstat > Network_Activity.log
launchctl list > Service_list.log
