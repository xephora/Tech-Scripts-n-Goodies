#!/usr/bin/env python
#brute library 'pip install brute'
#requests library 'pip install requests'

from brute import brute
import os
import requests

print(("""\
  _____________  ___           __      __
 / ___/ ___/ _ \/ _ )______ __/ /____ / _/__  ___________
/ (_ / /__/ ___/ _  / __/ // / __/ -_) _/ _ \/ __/ __/ -_)
\___/\___/_/  /____/_/  \_,_/\__/\__/_/ \___/_/  \__/\__/
"""))


google_storage = 'https://storage.googleapis.com/'

for x in brute(length=6, letters=True, numbers=False, symbols=False):
	h = requests.head(google_storage + x)
	print('Attempting Bucket Name: ' + x)
	print(h.headers['content-length'])
