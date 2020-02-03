#!/usr/bin/env python
import os

read_file = open('hitlist.txt','r')

for domains in read_file:
	os.system("ffuf -c -w wordlist_weirdfiles.txt --fc 403,404,302 -u " + domains.rstrip() + "/FUZZ >> weirdfiles.log")
read_file.close()
