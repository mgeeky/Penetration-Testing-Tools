#!/usr/bin/python3

import re
import sys
import json
import string
import random
import datetime    
import socket
import requests
import functools
from urllib.parse import urljoin, urlparse
from threading import Lock
from Database import Database
from threading import Thread
from time import sleep

from mitmproxy import http, ctx

VERSION = '0.1'

# Must point to JSON file containing configuration mentioned in `config` dictionary below.
# One can either supply that configuration file, or let the below variable empty and fill the `config`
# dictionary instead.
CONFIGURATION_FILE = 'config.json'

config = {
    'debug' : False,

    # The server hostname where affected systems shall pingback.
    'pingback-host': '',
    'server-remote-addr': '',

    'mysql-host': '',
    'mysql-user': '',
    'mysql-pass': '',
    'mysql-database': '',
}

append_headers = (
    'X-Forwarded-For',
    'Referer',
    'True-Client-IP',
    'X-Originating-IP',
    'X-Client-IP',
    'Client-IP',
    'X-Real-IP',
    'Contact',
    'Forwarded',
    'CF-Connecting_IP',
    'X-WAP-Profile'
)

visited_hosts = set()
add_host_lock = Lock()
database_lock = Lock()

CONNECTION_TIMEOUT = 4.0
CHUNK_SIZE = 512

def generateRandomId():
    randomized = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(50))
    return "xxx" + randomized + "yyy"

# note that this decorator ignores **kwargs
def memoize(obj):
    cache = obj.cache = {}

    @functools.wraps(obj)
    def memoizer(*args, **kwargs):
        if args not in cache:
            cache[args] = obj(*args, **kwargs)
        return cache[args]
    return memoizer

def dbg(x):
    if 'debug' in config.keys() and config['debug']:
        print('[dbg] ' + x)


class SendRawHttpRequest:
    def __init__(self):
        self.sock = None

    def connect(self, host, port, _ssl, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if _ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.options |= ssl.OP_ALL
                context.verify_mode = ssl.CERT_NONE

                self.sock = context.wrap_socket(sock)
            else:
                self.sock = sock

            self.sock.settimeout(timeout)                
            self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            self.sock.connect((host, port))
            dbg('Connected with {}'.format(host))
            return True

        except Exception as e:
            ctx.log.error('[!] Could not connect with {}:{}!'.format(host, port))
            if config['debug']:
                raise
            return False

    def close(self):
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()

        self.sock = None
        self.raw_socket = None
        self.ssl_socket = None

    def receiveAll(self, chunk_size=CHUNK_SIZE):
        chunks = []
        while True:
            chunk = None
            try:
                chunk = self.sock.recv(int(chunk_size))
            except:
                if chunk: 
                    chunks.append(chunk)
                break

            if chunk:
                chunks.append(chunk)
            else:
                break

        return b''.join(chunks)

    def send(self, host, port, ssl, data, timeout = CONNECTION_TIMEOUT):
        if not self.connect(host, port, ssl, timeout):
            return False

        self.sock.send(data.encode())
        resp = self.receiveAll()
        self.close()
        return resp

class PyCollaboratorMitmproxyAddon:    
    method = b''
    request = None
    requestBody = None

    def __init__(self):
        global config
        self.databaseInstance = self.connection = None

        if CONFIGURATION_FILE:
            config.update(json.loads(open(CONFIGURATION_FILE).read()))

        ctx.log.info('Initializing py-collaborator-mitmproxy-plugin.')

        self.connection = None
        self.createConnection()

    def createConnection(self):
        self.databaseInstance = Database()

        ctx.log.info("Connecting to MySQL database: {}@{} ...".format(
            config['mysql-user'], config['mysql-host']
        ))
        self.connection = self.databaseInstance.connection(  config['mysql-host'], 
                                                        config['mysql-user'], 
                                                        config['mysql-pass'],
                                                        config['mysql-database'])

        if not self.connection:
            ctx.log.error('Could not connect to the MySQL database! ' \
                'Please configure inner `MySQL` variables such as Host, User, Password.')
            sys.exit(1)

        ctx.log.info('Connected.')

    def executeSql(self, query, params = None):
        try:
            assert self.connection
            database_lock.acquire()
            if not params:
                out = self.databaseInstance.query(query)
            else:
                out = self.databaseInstance.query(query, params = params)

            database_lock.release()
            if not out:
                return []
            return out

        except Exception as e:
            ctx.log.error('SQL query ("{}", params: {}) has failed: {}'.format(
                query, str(params), str(e)
            ))
            database_lock.release()
            if config['debug']:
                raise
            return []

    @staticmethod
    @memoize
    def requestToString(request):
        headers = '\r\n'.join(['{}: {}'.format(k, v) for k, v in request.headers.items()])
        out = '{} {} {}\r\n{}'.format(request.command, request.path, request.request_version, headers)
        return out

    @staticmethod
    def getPingbackUrl(request):
        #guid = str(uuid.uuid4())
        guid = generateRandomId()
        url = "http://{}.{}/".format(guid, config['pingback-host'])
        return (url, guid)

    def saveRequestForCorrelation(self, request, pingback, uuid, where):
        query = 'INSERT INTO requests(id, sent, uuid, desthost, pingback, whereput, request) VALUES(%s, %s, %s, %s, %s, %s, %s)'
        generatedRequest = PyCollaboratorMitmproxyAddon.requestToString(self.request)
        desthost = self.request.headers['Host']
        values = ('0', datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), uuid, desthost, pingback, where, generatedRequest)
        self.executeSql(query, values)

    @staticmethod
    def sendRawRequest(request, requestData):
        raw = SendRawHttpRequest()
        port = 80 if request.scheme == 'http' else 443
        return raw.send(request.headers['Host'], port, request.scheme == 'https', requestData)

    def hostOverriding(self):
        (pingback, uuid) = PyCollaboratorMitmproxyAddon.getPingbackUrl(self.request)
        requestData = 'GET {} HTTP/1.1\r\n'.format(pingback)
        requestData+= 'Host: {}\r\n'.format(self.request.headers['Host'])
        requestData+= 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n'
        requestData+= 'Accept: */*\r\n'
        requestData+= 'Connection: close\r\n'

        self.saveRequestForCorrelation(self.request, pingback, uuid, 'Overridden Host header ({} -> GET {} )'.format(self.request.headers['Host'], pingback))
        PyCollaboratorMitmproxyAddon.sendRawRequest(self.request, requestData)
        ctx.log.info('(2) Re-sent host overriding request ({} -> {})'.format(self.request.path, pingback))

    def hostAtManipulation(self):
        (pingback, uuid) = PyCollaboratorMitmproxyAddon.getPingbackUrl(self.request)
        url = urljoin(self.request.scheme + '://', self.request.headers['Host'], self.request.path)
        parsed = urlparse(pingback)

        requestData = 'GET {} HTTP/1.1\r\n'.format(pingback)
        requestData+= 'Host: {}@{}\r\n'.format(self.request.headers['Host'], parsed.netloc)
        requestData+= 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n'
        requestData+= 'Accept: */*\r\n'
        requestData+= 'Connection: close\r\n'

        self.saveRequestForCorrelation(self.request, pingback, uuid, 'Host header manipulation ({} -> {}@{})'.format(self.request.headers['Host'], self.request.headers['Host'], parsed.netloc))
        PyCollaboratorMitmproxyAddon.sendRawRequest(self.request, requestData)
        ctx.log.info('(3) Re-sent host header @ manipulated request ({} -> {}@{})'.format(self.request.headers['Host'], self.request.headers['Host'], parsed.netloc))

    def sendMisroutedRequests(self):
        (pingback, uuid) = PyCollaboratorMitmproxyAddon.getPingbackUrl(self.request)
        url = self.request.url
        parsed = urlparse(pingback)

        self.saveRequestForCorrelation(self.request, pingback, uuid, 'Hijacked Host header ({} -> {})'.format(self.request.headers['Host'], parsed.netloc))

        try:
            dbg('GET {}'.format(url))
            requests.get(url, headers = {'Host' : parsed.netloc})
            ctx.log.info('(1) Re-sent misrouted request with hijacked Host header ({} -> {})'.format(self.request.headers['Host'], parsed.netloc))
        except (Exception, requests.exceptions.TooManyRedirects) as e:
            ctx.log.error('Could not issue request to ({}): {}'.format(url, str(e)))
            if config['debug']:
                raise

        self.hostOverriding()
        self.hostAtManipulation()

    @memoize
    def checkIfAlreadyManipulated(self, host):
        query = 'SELECT desthost FROM {}.requests WHERE desthost = "{}"'.format(config['mysql-database'], host)

        rows = self.executeSql(query)
        if rows == False: return rows
        for row in rows:
            if self.request.headers['Host'] in row['desthost']:
                dbg('Host ({}) already was lured for pingback.'.format(row['desthost']))
                return True
        
        dbg('Host ({}) was not yet lured for pingback.'.format(self.request.headers['Host']))
        return False

    def request_handler(self, req, req_body):
        global visited_hosts
        self.request = req
        self.requestBody = req_body

        self.request.scheme = self.request.path.split(':')[0].upper()

        allowed_letters = string.ascii_lowercase + string.digits + '-_.'
        host = ''.join(list(filter(lambda x: x in allowed_letters, self.request.headers['Host'])))

        if (host not in visited_hosts) and (not self.checkIfAlreadyManipulated(host)):
            add_host_lock.acquire()
            visited_hosts.add(host)
            add_host_lock.release()

            for header in append_headers:   
                (pingback, uuid) = PyCollaboratorMitmproxyAddon.getPingbackUrl(self.request)
                self.request.headers[header] = pingback
                if 'IP' in header:
                    self.request.headers[header] = '{}.{}'.format(uuid, config['pingback-host'])

                self.saveRequestForCorrelation(pingback, header, uuid, 'Header: {}'.format(header))

            self.sendMisroutedRequests()
            ctx.log.info('Injected pingbacks for host ({}).'.format(host))

        return self.requestBody

    def requestForMitmproxy(self, flow):
        class Request:
            def __init__(self, flow):
                self.scheme = flow.request.scheme
                self.path = flow.request.path
                self.method = flow.request.method
                self.command = flow.request.method
                self.host = str(flow.request.host)
                self.port = int(flow.request.port)
                self.http_version = flow.request.http_version
                self.request_version = flow.request.http_version
                self.headers = {}
                self.req_body = flow.request.content
                self.url = flow.request.url

                self.headers['Host'] = self.host

                for k,v in flow.request.headers.items():
                    self.headers[k] = v

            def __str__(self):
                out = '{} {} {}\r\n'.format(self.method, self.path, self.http_version)
                for k, v in self.headers.items():
                    out += '{}: {}\r\n'.format(k, v)

                if self.req_body:
                    out += '\r\n{}'.format(self.req_body)

                return out + '\r\n'

        req = Request(flow)
        req_body = req.req_body
        # ctx.log.info('DEBUG2: req.path = {}'.format(req.path))
        # ctx.log.info('DEBUG2: req.url = {}'.format(req.url))
        # ctx.log.info('DEBUG5: req.request_version = {}'.format(req.request_version))
        # ctx.log.info('DEBUG5: req.headers = {}'.format(str(req.headers)))
        # ctx.log.info('DEBUG5: req.req_body = ({})'.format(req.req_body))
        # ctx.log.info('DEBUG6: REQUEST BODY:\n{}'.format(str(req)))
        return self.request_handler(req, req_body)


def request(flow: http.HTTPFlow) -> None:
    globalPyCollaborator.requestForMitmproxy(flow)

globalPyCollaborator = PyCollaboratorMitmproxyAddon()
addons = [request]
