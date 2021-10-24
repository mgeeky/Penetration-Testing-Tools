#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler,HTTPServer
import urllib
import re
import sys
import ssl
import json
import string
import random
import socket
import pymysql
import argparse
import datetime
import threading

from Database import Database
from Logger import *

VERSION = '0.1'

#
# CONFIGURE THE BELOW VARIABLES
#

# Must point to JSON file containing configuration mentioned in `config` dictionary below.
# One can either supply that configuration file, or let the below variable empty and fill the `config`
# dictionary instead.
CONFIGURATION_FILE = 'config.json'

config = {
    'debug' : '',
    'listen' : '0.0.0.0',
    'pingback-host': '',
    'server-remote-addr': '',
    'listen-on-ports' : (80, 443, 8080),

    # You can generate it using Let's Encrypt wildcard certificate.
    'server-ca-cert' : '',
    "server-key-file": '',
    
    'mysql-host': '',
    'mysql-user': '',
    'mysql-pass': '',
    'mysql-database': '',

    'exclude-pingbacks-from-clients' : [],
}

databaseInstance = None

def generateRandomId():
    randomized = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(50))
    return "xxx" + randomized + "yyy"

class PingbackServer(BaseHTTPRequestHandler):    
    method = ''

    def __init__(self, *args, **kwargs):
        self.server_version = 'nginx'
        try:
            BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
        except Exception as e:
            if config['debug']:
                Logger.dbg('Failure along __init__ of BaseHTTPRequestHandler: {}'.format(str(e)))
                raise

        #Logger.info('Previously catched pingbacks:\n--------------------------\n')
        #self.presentAtStart()

    def presentAtStart(self):
        rows = databaseInstance.query(f'SELECT * FROM calledbacks')
        if not rows:
            return
        for row in rows:
            request = databaseInstance.query(f"SELECT * FROM requests WHERE id = {row['requestid']}")
            Logger.info(row['request'])

    def log_message(self, format, *args):
        return

    def extractUuid(self):
        uuidRex = re.compile(r'(\bxxx[a-z0-9]{50}yyy\b)', re.I|re.M)
        
        if 'xxx' in self.path and 'yyy' in self.path:
            # Request path
            m = uuidRex.search(self.path)
            if m: 
                return ('URL path', m.group(1))

        # Request headers
        for h in self.headers:
            value = self.headers[h]
            if ('xxx' not in value or 'yyy' not in value): 
                continue
            m = uuidRex.search(value)
            if m: 
                return (f'Header: {h}', m.group(1))

        return ('', '')

    def presentPingbackedRequest(self, where, uuid, record):
        fmt = '%Y-%m-%d %H:%M:%S'
        now = datetime.datetime.utcnow().strftime(fmt)
        delay = str(datetime.datetime.utcnow() - datetime.datetime.strptime(record['sent'], fmt))
        req = '\r\n'.join([f'\t{x}' for x in record['request'].split('\r\n')])
        req2 = '\r\n'.join([f'\t{x}' for x in PingbackServer.requestToString(self).split('\r\n')])
        try:
            reverse = socket.gethostbyaddr(self.client_address[0])[0]
        except:
            reverse = self.client_address[0]
        message = f'''

-------------------------------------------------------------------------------------
Issue:                  Pingback {record['id']} ({self.command} {self.path} ) found in request's {where}
Where payload was put:  {record['whereput']}
Contacting host:        {reverse}
Tried to reach vhost:   {self.headers['Host']}:{self.server.server_port}

Issue detail:
    Our pingback-server was contacted by ({self.client_address[0]}:{self.client_address[1]}) after a delay of ({delay}):

    Original request where this pingback was inserted:
    ---
    {req}


    Request that was sent to us in return:
    ---
    {req2}

The payload was sent at ({record['sent']}) and received on ({now}).
-------------------------------------------------------------------------------------


'''

        Logger._out(message)
        return message


    def savePingback(self, requestid, message):
        query = 'INSERT INTO calledbacks(id, requestid, uuid, whereput) VALUES(%d, %d, "%s")' % (\
            0,  requestid, message)
        Logger.dbg(f'Saving pingback: (requestid={str(requestid)})')
        Logger.dbg(query)
        databaseInstance.insert(query)

    def checkUuid(self, where, uuid):
        if not (uuid.startswith('xxx') and uuid.endswith('yyy')):
            return 

        for a in uuid:
            if a not in string.ascii_lowercase + string.digits:
                return

        out = databaseInstance.query(f'SELECT * FROM requests WHERE uuid = "{uuid}"')
        if out:
            message = self.presentPingbackedRequest(where, uuid, out[0])
            self.savePingback(out[0]['id'], message)

    def send_header(self, name, value):
        if name == 'Server':
            return super(PingbackServer, self).send_header(name, 'nginx')
        return super(PingbackServer, self).send_header(name, value)

    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    @staticmethod
    def requestToString(request):
        headers = '\r\n'.join(['{}: {}'.format(k, v) for k, v in request.headers.items()])
        out = '{} {} {}\r\n{}'.format(request.command, request.path, request.request_version, headers)
        return out

    def do_GET(self):
        if not (self.client_address[0] in config['exclude-pingbacks-from-clients']):
            if config['debug']:
                Logger.dbg('--------------------------\nIncoming HTTP request from {}: {} {}'.format(
                    self.client_address[0],
                    self.method,
                    self.path[:25]
                ))

                Logger.dbg(PingbackServer.requestToString(self) + '\n')

            (where, uuid) = PingbackServer.extractUuid(self)
            if uuid:
                self.checkUuid(where, uuid)
        else:
            Logger.dbg('Skipping Client ({}) as it was excluded in config file.'.format(self.client_address[0]))

        self._set_response()
        self.wfile.write(b'Ok')

    do_POST = do_GET
    do_DELETE = do_GET
    do_PUT = do_GET
    do_OPTIONS = do_GET
    do_HEAD = do_GET
    do_TRACE = do_GET
    do_CONNECT = do_GET
    do_PATCH = do_GET


def parseOptions(argv):
    global config

    print('''
        :: Cracking the Lens pingback responding server
        Responds to every Out-of-band request correlating them along the way
        Mariusz Banach / mgeeky '16-18, <mb@binary-offensive.com>
''')

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options]')

    parser.add_argument('-l', '--listen', default='0.0.0.0', help = 'Specifies interface address to bind the HTTP server on / listen on. Default: 0.0.0.0 (all interfaces)')
    parser.add_argument('-p', '--port', metavar='PORT', default='80', type=int, help='Specifies the port to listen on. Default: 80')
    parser.add_argument('-r', '--rhost', metavar='HOST', default=config['server-remote-addr'], help='Specifies attackers host address where the victim\'s XML parser should refer while fetching external entities')

    parser.add_argument('--mysql-host', metavar='MYSQLHOST', default='127.0.0.1', type=str, help='Specifies the MySQL hostname. Defalut: 127.0.0.1:3306')
    parser.add_argument('--mysql-user', metavar='MYSQLUSER', default='root', type=str, help='Specifies the MySQL user, that will be able to create database, tables, select/insert records and so on. Default: root')
    parser.add_argument('--mysql-pass', metavar='MYSQLPASS', type=str, help='Specifies the MySQL password')

    parser.add_argument('-d', '--debug', action='store_true', help='Display debug output.')

    args = parser.parse_args()

    config['debug'] = args.debug
    config['listen'] = args.listen
    config['port'] = int(args.port)
    config['server-remote-addr'] = args.rhost

    port = int(args.port)
    if port < 1 or port > 65535:
        Logger.err("Invalid port number. Must be in <1, 65535>")
        sys.exit(-1)

    try:
        if not args.mysql_host or not args.mysql_port or not args.mysql_user or not args.mysql_pass:
            Logger.warn("You shall specify all needed MySQL connection data either via program options or config file.")
            #sys.exit(-1)
        else:
            config['mysql-host'] = args.mysql_host
            config['mysql-user'] = args.mysql_user
            config['mysql-pass'] = args.mysql_pass
    except:
        Logger.warn("You shall specify all needed MySQL connection data either via program options or config file.")

    return args

def connectToDatabase():
    global databaseInstance

    databaseInstance = Database()
    return databaseInstance.connection(config['mysql-host'], config['mysql-user'], config['mysql-pass'])

def initDatabase():
    initQueries = (
        f"CREATE DATABASE IF NOT EXISTS {config['mysql-database']}",
        f'''CREATE TABLE IF NOT EXISTS {config['mysql-database']}.requests (
    id integer AUTO_INCREMENT,
    sent text NOT NULL,
    uuid text NOT NULL,
    desthost text NOT NULL,
    pingback text NOT NULL,
    whereput text NOT NULL,
    request text NOT NULL,
    PRIMARY KEY (id)) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;''',
        f'''CREATE TABLE IF NOT EXISTS {config['mysql-database']}.calledbacks (
    id integer AUTO_INCREMENT,
    requestid integer NOT NULL,
    request text NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY(requestid) REFERENCES requests(id)) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;''',
    )

    for query in initQueries:
        databaseInstance.query(query)

    databaseInstance.databaseConnection.select_db(config['mysql-database'])
    Logger.ok('Database initialized.')

def fetchRhost():
    global config
    config['server-remote-addr'] = socket.gethostbyname(socket.gethostname())

def main(argv):
    global config

    fetchRhost()

    opts = parseOptions(argv)
    if not opts:
        Logger.err('Options parsing failed.')
        return False

    if CONFIGURATION_FILE:
        config.update(json.loads(open(CONFIGURATION_FILE).read()))

    if not connectToDatabase():
        Logger.err('Could not connect to database: {}'.format(config['mysql-host']))
        sys.exit(-1)

    initDatabase()

    Logger.dbg('Local host\'s IP address (RHOST) set to: {}'.format(config['server-remote-addr']))

    for port in config['listen-on-ports']:
        try:
            server = HTTPServer((config['listen'], port), PingbackServer)
            server.server_version = 'nginx'
        except OSError as e:
            Logger.err(f'Could not server on port {port}: {str(e)}')
            Logger.warn('Skipping...')
            continue
            #return

        if port == 443:
            try:
                server.socket = ssl.wrap_socket(server.socket, keyfile = config['server-key-file'], certfile = config['server-ca-cert'], server_side = True)
            except ssl.SSLError as e:
                Logger.warn(f'Could not serve HTTPS due to SSL error: {str(e)}')
                Logger.warn('Skipping...')
                continue

        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        Logger.ok('Serving HTTP server on: ("{}", {})'.format(
            config['listen'], port)
        )

    try:
        Logger.info('Entering infinite serving loop.')
        while True:
            pass
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main(sys.argv)
