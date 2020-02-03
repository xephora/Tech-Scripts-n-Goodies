#!/usr/bin/env python
import os
import array

read_file = open('hitlist.txt','r')


for domains in read_file:
	print('================http probing================')
	os.system("echo " + domains.rstrip() + " | ~/go/bin/httprobe")
	print('================nmap scanning================')
	os.system("nmap -sC -sV -p 88,554,623,664,1098,1099,1604,2048,3299,4070,6002,7002,9000,10000,16992,16993,16994,16995 " + domains.rstrip())
	print('================http linking================')
	print('https://' + domains.rstrip() + ':88')
	print('https://' + domains.rstrip() + ':554')
	print('https://' + domains.rstrip() + ':623')
	print('https://' + domains.rstrip() + ':664')
	print('https://' + domains.rstrip() + ':1098')
	print('https://' + domains.rstrip() + ':1099')
	print('https://' + domains.rstrip() + ':1604')
	print('https://' + domains.rstrip() + ':2048')
	print('https://' + domains.rstrip() + ':3299')
	print('https://' + domains.rstrip() + ':4070')
	print('https://' + domains.rstrip() + ':6002')
	print('https://' + domains.rstrip() + ':7002')
	print('https://' + domains.rstrip() + ':9000')
	print('https://' + domains.rstrip() + ':10000')
	print('https://' + domains.rstrip() + ':16992')
	print('https://' + domains.rstrip() + ':16993')
	print('https://' + domains.rstrip() + ':16994')
	print('https://' + domains.rstrip() + ':16995')
read_file.close()

