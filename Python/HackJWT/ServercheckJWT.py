#!/usr/bin/env python
#Required
#pip3 install pyjwt

import requests
import jwt

url = input('Enter http://url:port/ >')
jwt_tk = input('Enter JWT Token: ')
headers = {'Authorization': f'Bearer {jwt_tk}'}

r = requests.get(url, headers=headers)
print(r.text)