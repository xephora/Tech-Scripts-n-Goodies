import os
import array

read_file = open('hitlist.txt','r')


for domains in read_file:
        print('================NMAP Scanning {domain}================')
        os.system("echo '\e[92mScanning.....\e[0m'")
        os.system("nmap --open -p 80,443,88,554,623,664,1098,1099,1604,2048,3299,4070,6002,7002,9000,10000,16992,16993,16994,16995 " + domains.rstrip() + "  -oG -")
read_file.close()
