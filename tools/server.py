from http.server import HTTPServer, SimpleHTTPRequestHandler

class KeepAliveHandler(SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

server_address = ('', 8000)
httpd = HTTPServer(server_address, KeepAliveHandler)
httpd.serve_forever()

