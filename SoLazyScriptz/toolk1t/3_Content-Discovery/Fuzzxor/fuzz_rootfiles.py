#!/usr/bin/env python
import os

read_file = open('hitlist.txt','r')

for mostint in read_file:
	#debugger
	#print("ffuf -c -w /root/wordlist/Fuzzing/curated.txt --fc 403,404,302 -u " + mostint.rstrip() + "/FUZZ")
	os.system("ffuf -c -w wordlist_rootfiles.txt --fc 403,404,302 -u " + mostint.rstrip() + "/FUZZ")
read_file.close()
