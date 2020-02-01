#!/usr/bin/env python
import os

read_file = open('hitlist.txt','r')

for api in read_file:
	#print("ffuf -c -w apilist.txt --fc 403,404,302 -u " + api.rstrip() + "/FUZZ")
	os.system("ffuf -c -w apilist.txt --fc 403,404,302 -u " + api.rstrip() + "/v1/FUZZ")
read_file.close()
