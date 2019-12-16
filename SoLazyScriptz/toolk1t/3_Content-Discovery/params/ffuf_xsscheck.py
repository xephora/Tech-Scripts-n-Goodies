#!/usr/bin/env python
import os

website = raw_input('Enter URL Format - https://example.com/doc: ')

read_file = open('/root/pwn/toolk1t/3_Content-Discovery/params/paramlist.txt','r')
for param in read_file:
	#For Debugger use print function
	#print("ffuf -c -w /root/pwn/toolk1t/3_Content-Discovery/params/param_wordlists/XSS-Jhaddix.txt --fc 403,404,302 -u " + website + "?" + param.rstrip() + "=FUZZ >> logs/" + param)
	print('Light taps on param ' + param)
        os.system("ffuf -c -w /root/pwn/toolk1t/3_Content-Discovery/params/param_wordlists/xsstap.txt --fc 403,404,302 -u " + website + "?" + param.rstrip() + "=FUZZ >> logs/" + param)
read_file.close()
