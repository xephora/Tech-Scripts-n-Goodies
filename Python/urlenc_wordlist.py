#!/url/bin/env python
from urllib.parse import quote

list = open('wordlist.txt','r')

for x in list:
	q = quote(x, safe='')
	print(q)
list.close()
