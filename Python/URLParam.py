import urllib
from urllib import request

print('Insert URL_ ExampleURL http://URL/PATH/query?key=')
urlinput = input()
print('\n')

resp = request.urlopen(urlinput)

print('Size of HTTP Response is')
print(resp.length)
print('\n')

print('Response Peek')
print(resp.peek())

data = resp.read()
print(type(data))
