### Setup

Generating self signed SSL Certificate
openssl req -newkey rsa:2048 -new -nodes -x509 -days 365 -keyout key.pem -out cert.pem

### Secured server in python

```
httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443),
        SimpleHTTPServer.SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket (httpd.socket,
        keyfile="/path/to/key.pem",
        certfile='/path/to/cert.pem', server_side=True)

httpd.serve_forever()
```
