"""Serve probe.html over HTTPS on 443 for lab L2. Usage: python3 serve.py <dir with probe.html and certs/>"""
import http.server
import ssl
import sys
from functools import partial

root = sys.argv[1]
handler = partial(http.server.SimpleHTTPRequestHandler, directory=root)
httpd = http.server.HTTPServer(("0.0.0.0", 443), handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{root}/certs/cert.pem", f"{root}/certs/key.pem")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
