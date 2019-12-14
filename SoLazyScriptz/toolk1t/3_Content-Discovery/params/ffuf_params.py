#!/usr/bin/env python
import os

website = raw_input('Enter URL Format - https://example.com/doc: ')

read_file = open('/root/pwn/toolk1t/3_Content-Discovery/params/paramlist.txt','r')
for param in read_file:
	#For Debugging purposes use print function
	#print("ffuf -c -w /root/pwn/toolk1t/3_Content-Discovery/params/param_wordlists/XSS-Jhaddix.txt --fc 403,404,302 -u " + website + "?" + param.rstrip() + "=FUZZ >> logs/" + param)
	print('Checking for XSS huge list against ' + param)
        os.system("ffuf -c -w /root/pwn/toolk1t/3_Content-Discovery/params/param_wordlists/XSS-Cheat-Sheet-PortSwigger.txt --fc 403,404,302 -u " + website + "?" + param.rstrip() + "=FUZZ >> logs/" + param)

	print('Checking for XSS small list against ' + param)
	os.system("ffuf -c -w /root/pwn/toolk1t/3_Content-Discovery/params/param_wordlists/XSS-Jhaddix.txt --fc 403,404,302 -u " + website + "?" + param.rstrip() + "=FUZZ >> logs/" + param)
	print('Checking for XSS Logic against param ' + param)
	os.system("ffuf -c -w /root/pwn/toolk1t/3_Content-Discovery/params/param_wordlists/XSS-BruteLogic.txt --fc 403,404,302 -u " + website + "?" + param.rstrip() + "=FUZZ >> logs/" + param)
	print('Bypassing logic')
	os.system("ffuf -c -w /root/pwn/toolk1t/3_Content-Discovery/params/param_wordlists/XSS-Bypass-Strings-BruteLogic.txt --fc 403,404,302 -u " + website + "?" + param.rstrip() + "=FUZZ >> logs/" + param)
	print('polygl0t Slap')
	os.system("ffuf -c -w /root/pwn/toolk1t/3_Content-Discovery/params/param_wordlists/xsspolygl0t.txt --fc 403,404,302 -u " + website + "?" + param.rstrip() + "=FUZZ >> logs/" + param)
read_file.close()

