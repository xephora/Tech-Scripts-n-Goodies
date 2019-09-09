import urllib
from urllib import request

urlinput = input('Insert URL_ ExampleURL http://URL/PATH/query?key=')

resp = request.urlopen(urlinput)

print(resp.length)