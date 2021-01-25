# Resources on cracking

### john the ripper
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### hashcat

https://www.4armed.com/blog/hashcat-rule-based-attack/

```
hashcat -a 0 -m <MODE> -r best64.rule hash.txt pass_list.txt --force
```
