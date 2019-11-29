#!/usr/bin/env python
import os

read_file = open('/root/pwn/toolk1t/1_domainscraping/domain_cleanup/domain_ips.txt','r')
for host in read_file:
	os.system("ffuf -c -w /root/wordlist/Fuzzing/curated.txt --fc 403,404,302 -u https://" + host.rstrip() + "/FUZZ > logs/fuzzlog.txt")
read_file.close()

