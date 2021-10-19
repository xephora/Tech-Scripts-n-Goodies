# HTB BattleGround tips

### Defending

### Recon for the team
```
1. Gather IP's and Root passwords and provide to teamchat.  
2. Fuzz all servers and run nmap and provide ports, services, and discovered paths to teamchat.  
3. Enumerate your own systems and assist with foothold and privesc.
```

### Simple but Basic tools
```
Content Hunting
grep -rao config

Restricting shell
chsh -s /bin/rbash <username>
chsh -s /bin/false <username>

Active Connections & who is signed into the device
netstat
who

Hunting for shells
ps aux | grep ''
ps aux | grep ssh
ps aux | grep python
ps aux | grep sh

Get process id for 
ps -ft pts/1

Kill based off pts session
pkill -t pts/#
```

### Tips to Patching the vulnerable and Foothold and Privesc defense
```
1. Identify what web applications are being served. If there's a particular valuable data stored onthe webserve such as a username or password then try to flip a few bytes of data.
2. Find out what the app does, make it harder for them to access or if possible (without breaking the operation of the web app) prevent the user from getting a foothold. An example, if there's an account creation page, you can try to find a way to redirect to the main page or set as forbidden or if a someone is attempting to abuse a pincode on a webpage. Change the pincode. 
3. If the opposing team has access to the box. you may want to kill their shell by killing ssh, python, sh, bash etc.
4. If the opposing team has user access and is trying to privesc, you may want to change permissions to the privilege escalation technique. If you discover a file that can be abused, you may want to strip the permissions of the user away to prevent privilage escalation.
5. pspy to review to audit activity.
```

### Useful resources
https://www.youtube.com/watch?v=o42dgCOBkRk&feature=emb_title
```
Some useful commands used by ippsec

ss -anp | grep <pid>
ss -lnpt
ps -eaf --forest 

apache2 logs

cat /var/log/apache2/access.log | grep 10.10.14
cd /proc/3609 | grep cwd
```
