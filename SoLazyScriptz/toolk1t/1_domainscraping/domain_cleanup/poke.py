#!/usr/bin/env python
import os

read_file = open('/root/pwn/toolk1t/1_domainscraping/domain_cleanup/domain_ips.txt','r')
for host in read_file:
	os.system("sniper -t " + host)
read_file.close()
