import ipaddress
import sys

print("Enter IP Example 192.168.1.1:")
iaddr = raw_input()
print("Enter a Subnet Example 16, 20, 24 etc")
subn = raw_input()

for ip in ipaddress.IPv4Network(unicode(iaddr+'/'+subn)):
	sys.stdout.flush()
	print(ip)
