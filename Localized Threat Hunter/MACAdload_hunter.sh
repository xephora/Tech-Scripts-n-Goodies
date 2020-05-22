cat <<EOF
 __    __     ______     ______     ______     _____     __         ______     ______     _____            
/\ "-./  \   /\  __ \   /\  ___\   /\  __ \   /\  __-.  /\ \       /\  __ \   /\  __ \   /\  __-.          
\ \ \-./\ \  \ \  __ \  \ \ \____  \ \  __ \  \ \ \/\ \ \ \ \____  \ \ \/\ \  \ \  __ \  \ \ \/\ \         
 \ \_\ \ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \____-  \ \_____\  \ \_____\  \ \_\ \_\  \ \____-         
  \/_/  \/_/   \/_/\/_/   \/_____/   \/_/\/_/   \/____/   \/_____/   \/_____/   \/_/\/_/   \/____/         
                                                                                                           
                                           __  __     __  __     __   __     ______   ______     ______    
                                          /\ \_\ \   /\ \/\ \   /\ "-.\ \   /\__  _\ /\  ___\   /\  == \   
                                          \ \  __ \  \ \ \_\ \  \ \ \-.  \  \/_/\ \/ \ \  __\   \ \  __<   
                                           \ \_\ \_\  \ \_____\  \ \_\\"\_\    \ \_\  \ \_____\  \ \_\ \_\ 
                                            \/_/\/_/   \/_____/   \/_/ \/_/     \/_/   \/_____/   \/_/ /_/ 
                                                                                                           
EOF

echo "======================================================================================"
read -p 'Enter a username you want to inspect: ' user
echo -e "\n"
echo -e "==================================================================================="
echo -e "Hunting for MACAdload: \n"
echo "Checking for MACAdload Proxy"
find /var/root/*proxy* >> /tmp/MACAdload_hunt.log
echo "Checking for MAC Adload data stored in root"
find /var/root/*Search* >> /tmp/MACAdload_hunt.log
echo "Checking for MAC Adload data stored in Application Support"
find "/Library/Application Support/*Search*" >> /tmp/MACAdload_hunt.log
echo "Checking for MAC Adload data stored in LaunchDaemons"
find /Library/LaunchDaemons/*Search* >> /tmp/MACAdload_hunt.log
echo "Checking for MAC Adload data stored in LaunchAgents"
find /Library/LaunchAgents/*Search* >> /tmp/MACAdload_hunt.log
echo "Checking for MAC Adload data store in users Profile"
find /Users/$user/Library/LaunchAgents/*Search* >> /tmp/MACAdload_hunt.log
find "/Users/$user/Library/Application Support/*Search*" >> /tmp/MACAdload_hunt.log
find /Users/$user/Library/*Search* >> /tmp/MACAdload_hunt.log
echo "Checking for Cron Job"
find /var/at/tabs/$user >> /tmp/MACAdload_hunt.log
echo -e "\n"
echo -e "==================================================================================="
echo -e "A log has been generated below:"
ls /tmp/MACAdload_hunt.log
echo -e "\n"
echo -e "==================================================================================="
read -p 'Enter Python Script filename (example SearchQuest.py or com.SearchQuest.py): ' py
echo "Checking Processes for $py"
ps aux | grep $py
echo "Checking Port Activity for $py"
lsof | grep $py
echo -e "\n"
echo -e "==================================================================================="
read -p 'Press Enter to view log' opt1
cat /tmp/MACAdload_hunt.log
echo -e "==================================================================================="
read -p 'Press Enter to clean log' opt2
rm /tmp/MACAdload_hunt.log
echo "Log Removed"

#Additional but optional
#Hunting tmp directory. Enable or Disable feature by removing or adding the #
#find /tmp/*-*-*-*-*
