#!/usr/bin/env python
import os

website = raw_input('Enter URL')

read_file = open('/root/pwn/toolk1t/3_Content-Discovery/Fuzzxor/fuzzlist.txt','r')
for host in read_file:
	os.system("ffuf -c -w /root/SecLists/Discovery/Web-Content/SVNDigger/all.txt --fc 403,404,302 -u " + website + host.rstrip() + "/FUZZ >> logs/fuzzlog.txt")
read_file.close()

