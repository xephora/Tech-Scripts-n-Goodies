#!/usr/bin/env python
import sys
import socket

read_file = open('domains.txt','r')
for host in read_file:
    print socket.gethostbyname(host.rstrip("\n"))   #rstrip for removing new line characters
read_file.close()