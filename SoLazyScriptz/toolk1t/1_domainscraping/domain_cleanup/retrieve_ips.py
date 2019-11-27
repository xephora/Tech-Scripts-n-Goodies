#!/usr/bin/env python
import sys
import socket

read_file = open('domains.txt','r')
for host in read_file:
    print socket.gethostbyname(host.rstrip("\n"))
read_file.close()
