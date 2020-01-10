#!/usr/bin/env python
#Required
#pip3 install pyjwt

import jwt

uid = input('Enter username: ')
exp = input('Enter Expiration Time: ')
passwd = input('Enter Password: ')
alg = input('Enter Algorith: ')

jwt_tk = jwt.encode( {'username':uid, 'iat':exp}, key=passwd, algorith=alg )
jwt_tk = jwt_token.decode('UTF-8')

print(jwt_tk)