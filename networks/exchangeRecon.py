#!/usr/bin/python3

#
# This tool connects to the given Exchange's hostname/IP address and then
# by collects various internal information being leaked while interacting 
# with different Exchange protocols. Exchange may give away following helpful
# during OSINT or breach planning stages insights:
#   - Internal IP address
#   - Internal Domain Name (ActiveDirectory)
#   - Exchange Server Version
#   - support for various SMTP User Enumeration techniques
#   - Version of underlying software such as ASP.NET, IIS which
#       may point at OS version indirectly
#
# This tool will be helpful before mounting social engieering attack against
# victim's premises or to aid Password-Spraying efforts against exposed OWA 
# interface. 
#
# OPSEC:
#   All of the traffic that this script generates is not invasive and should 
# not be picked up by SOC/Blue Teams as it closely resembles random usual traffic
# directed at both OWA, or Exchange SMTP protocols/interfaces. The only potentially
# shady behaviour could be observed on one-shot attempts to perform SMTP user 
# enumeration, however it is unlikely that single commands would trigger SIEM use cases.
#
# Requirements:
#   - pyOpenSSL
#
# Author:
#   Mariusz B. / mgeeky, '19, <mb@binary-offensive.com>
#

import re
import sys
import ssl
import time
import base64
import struct
import string
import socket
import smtplib
import requests
import argparse
import threading
import collections
import urllib3
from urllib.parse import urlparse
import OpenSSL.crypto as crypto

VERSION = '0.1'

config = {
    'debug' : False,
    'verbose' : False,
    'timeout' : 6.0,
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Logger:
    @staticmethod
    def _out(x): 
        if config['verbose'] or config['debug']: 
            sys.stdout.write(x + '\n')

    @staticmethod
    def out(x): 
        Logger._out('[.] ' + x)
    
    @staticmethod
    def info(x):
        Logger._out('[.] ' + x)

    @staticmethod
    def dbg(x):
        if config['debug']:
            Logger._out('[DEBUG] ' + x)
    
    @staticmethod
    def err(x): 
        sys.stdout.write('[!] ' + x + '\n')
    
    @staticmethod
    def fail(x):
        Logger._out('[-] ' + x)
    
    @staticmethod
    def ok(x):  
        Logger._out('[+] ' + x)

def hexdump(data):
    s = ''
    n = 0
    lines = []
    tableline = '-----+' + '-' * 24 + '|' \
        + '-' * 25 + '+' + '-' * 18 + '+\n'
    if isinstance(data, str):
        data = data.encode()

    if len(data) == 0:
        return '<empty>'

    for i in range(0, len(data), 16):
        line = ''
        line += '%04x | ' % (i)
        n += 16

        for j in range(n-16, n):
            if j >= len(data): break
            line += '%02x' % (data[j] & 0xff)
            if j % 8 == 7 and j % 16 != 15:
                line += '-'
            else:
                line += ' '

        line += ' ' * (3 * 16 + 7 - len(line)) + ' | '
        for j in range(n-16, n):
            if j >= len(data): break
            c = data[j] if not (data[j] < 0x20 or data[j] > 0x7e) else '.'
            line += '%c' % c

        line = line.ljust(74, ' ') + ' |'
        lines.append(line)

    return tableline + '\n'.join(lines) + '\n' + tableline


class NtlmParser:
    #
    # Based on:
    #   https://gist.github.com/aseering/829a2270b72345a1dc42
    #

    VALID_CHRS = set(string.ascii_letters + string.digits + string.punctuation)
    flags_tbl_str = (
        (0x00000001, "Negotiate Unicode"),
        (0x00000002, "Negotiate OEM"),
        (0x00000004, "Request Target"),
        (0x00000008, "unknown"),
        (0x00000010, "Negotiate Sign"),
        (0x00000020, "Negotiate Seal"),
        (0x00000040, "Negotiate Datagram Style"),
        (0x00000080, "Negotiate Lan Manager Key"),
        (0x00000100, "Negotiate Netware"),
        (0x00000200, "Negotiate NTLM"),
        (0x00000400, "unknown"),
        (0x00000800, "Negotiate Anonymous"),
        (0x00001000, "Negotiate Domain Supplied"),
        (0x00002000, "Negotiate Workstation Supplied"),
        (0x00004000, "Negotiate Local Call"),
        (0x00008000, "Negotiate Always Sign"),
        (0x00010000, "Target Type Domain"),
        (0x00020000, "Target Type Server"),
        (0x00040000, "Target Type Share"),
        (0x00080000, "Negotiate NTLM2 Key"),
        (0x00100000, "Request Init Response"),
        (0x00200000, "Request Accept Response"),
        (0x00400000, "Request Non-NT Session Key"),
        (0x00800000, "Negotiate Target Info"),
        (0x01000000, "unknown"),
        (0x02000000, "unknown"),
        (0x04000000, "unknown"),
        (0x08000000, "unknown"),
        (0x10000000, "unknown"),
        (0x20000000, "Negotiate 128"),
        (0x40000000, "Negotiate Key Exchange"),
        (0x80000000, "Negotiate 56")
    )

    def __init__(self):
        self.output = {}
        self.flags_tbl = NtlmParser.flags_tbl_str

        self.msg_types = collections.defaultdict(lambda: "UNKNOWN")
        self.msg_types[1] = "Request"
        self.msg_types[2] = "Challenge"
        self.msg_types[3] = "Response"

        self.target_field_types = collections.defaultdict(lambda: "UNKNOWN")
        self.target_field_types[0] = ("TERMINATOR", str)
        self.target_field_types[1] = ("Server name", str)
        self.target_field_types[2] = ("AD domain name", str)
        self.target_field_types[3] = ("FQDN", str)
        self.target_field_types[4] = ("DNS domain name", str)
        self.target_field_types[5] = ("Parent DNS domain", str)
        self.target_field_types[7] = ("Server Timestamp", int)

    def flags_lst(self, flags):
        return [desc for val, desc in self.flags_tbl if val & flags]

    def flags_str(self, flags):
        return ['%s' % s for s in self.flags_lst(flags)]

    def clean_str(self, st):
        return ''.join((s if s in NtlmParser.VALID_CHRS else '?') for s in st)

    class StrStruct(object):
        def __init__(self, pos_tup, raw):
            length, alloc, offset = pos_tup
            self.length = length
            self.alloc = alloc
            self.offset = offset
            self.raw = raw[offset:offset+length]
            self.utf16 = False

            if len(self.raw) >= 2 and self.raw[1] == 0:
                try:
                    self.string = self.raw.decode('utf-16')
                except:
                    self.string = ''.join(filter(lambda x: str(x) != '\0', self.raw))
                self.utf16 = True
            else:
                self.string = self.raw
            
        def __str__(self):
            return ''.join((s if s in NtlmParser.VALID_CHRS else '?') for s in self.string)

    def parse(self, data):
        st = base64.b64decode(data)
        if st[:len('NTLMSSP')].decode() == "NTLMSSP":
            pass
        else:
            raise Exception("NTLMSSP header not found at start of input string")

        ver = struct.unpack("<i", st[8:12])[0]

        if ver == 1:
            self.request(st)
        elif ver == 2:
            self.challenge(st)
        elif ver == 3:
            self.response(st)
        else:
            o = "Unknown message structure.  Have a raw (hex-encoded) message:"
            o += st.encode("hex")
            raise Exception(o)

        return self.output

    def opt_str_struct(self, name, st, offset):
        nxt = st[offset:offset+8]
        if len(nxt) == 8:
            hdr_tup = struct.unpack("<hhi", nxt)
            self.output[name] = str(NtlmParser.StrStruct(hdr_tup, st))
        else:
            self.output[name] = ""

    def opt_inline_str(self, name, st, offset, sz):
        nxt = st[offset:offset+sz]
        if len(nxt) == sz:
            self.output[name] = self.clean_str(nxt)
        else:
            self.output[name] = ""

    def request(self, st):
        hdr_tup = struct.unpack("<i", st[12:16])
        flags = hdr_tup[0]

        self.opt_str_struct("Domain", st, 16)
        self.opt_str_struct("Workstation", st, 24)
        self.opt_inline_str("OS Ver", st, 32, 8)

        self.output['Flags'] = self.flags_str(flags)

    @staticmethod
    def win_file_time_to_datetime(ft):
        from datetime import datetime

        EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
        utc = datetime.utcfromtimestamp((ft - EPOCH_AS_FILETIME) / 10000000)
        return utc.strftime('%y-%m-%d %a %H:%M:%S UTC')


    def challenge(self, st):
        hdr_tup = struct.unpack("<hhiiQ", st[12:32])

        self.output['Target Name'] = str(NtlmParser.StrStruct(hdr_tup[0:3], st))
        self.output['Challenge'] = hdr_tup[4]

        flags = hdr_tup[3]

        self.opt_str_struct("Context", st, 32)

        nxt = st[40:48]
        if len(nxt) == 8:
            hdr_tup = struct.unpack("<hhi", nxt)
            tgt = NtlmParser.StrStruct(hdr_tup, st)

            self.output['Target'] = {}

            raw = tgt.raw
            pos = 0

            while pos+4 < len(raw):
                rec_hdr = struct.unpack("<hh", raw[pos : pos+4])
                rec_type_id = rec_hdr[0]
                rec_type, rec_type_type = self.target_field_types[rec_type_id]
                rec_sz = rec_hdr[1]
                subst = raw[pos+4 : pos+4+rec_sz]
                if rec_type_type == int:
                    if 'Timestamp' in rec_type:
                        self.output['Target'][rec_type] = NtlmParser.win_file_time_to_datetime(
                            struct.unpack("<Q", subst)[0]
                        )
                    else:
                        self.output['Target'][rec_type] = struct.unpack("<Q", subst)[0]
                elif rec_type_type == str:
                    try:
                        self.output['Target'][rec_type] = subst.decode('utf-16')
                    except:
                        self.output['Target'][rec_type] = subst
                pos += 4 + rec_sz

        self.opt_inline_str("OS Ver", st, 48, 8)
        self.output['Flags'] = self.flags_str(flags)

    def response(self, st):
        hdr_tup = struct.unpack("<hhihhihhihhihhi", st[12:52])

        self.output['LM Resp'] = str(NtlmParser.StrStruct(hdr_tup[0:3], st))
        self.output['NTLM Resp'] = str(NtlmParser.StrStruct(hdr_tup[3:6], st))
        self.output['Target Name'] = str(NtlmParser.StrStruct(hdr_tup[6:9], st))
        self.output['User Name'] = str(NtlmParser.StrStruct(hdr_tup[9:12], st))
        self.output['Host Name'] = str(NtlmParser.StrStruct(hdr_tup[12:15], st))

        self.opt_str_struct("Session Key", st, 52)
        self.opt_inline_str("OS Ver", st, 64, 8)

        nxt = st[60:64]
        if len(nxt) == 4:
            flg_tup = struct.unpack("<i", nxt)
            flags = flg_tup[0]
            self.output['Flags'] = self.flags_str(flags)
        else:
            self.output['Flags'] = ""


class ExchangeRecon:
    COMMON_PORTS = (443, 80, 8080, 8000)
    MAX_RECONNECTS = 3
    MAX_REDIRECTS = 10
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        #'Connection': 'close',
    }

    def __init__(self, hostname):
        self.socket = None
        self.server_tls_params = None
        self.hostname = hostname
        self.port = None
        self.reconnect = 0
        self.results = {}

    def disconnect(self):
        if self.socket != None:
            self.socket.close()
            self.socket = None

    def connect(self, host, port, _ssl = True):
        try:
            Logger.dbg(f"Attempting to reach {host}:{port}...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if self.socket != None:
                    self.socket.close()
                    self.socket = None

                sock.settimeout(config['timeout'])
                if _ssl:
                    context = ssl.create_default_context()

                    # Allow unsecure ciphers like SSLv2 and SSLv3
                    context.options &= ~(ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    conn = context.wrap_socket(sock)
                    conn.connect((host, port))
                    self.socket = conn

                    self.server_tls_params = {
                        'cipher' : conn.cipher(),
                        'version': conn.version(),
                        'shared_ciphers': conn.shared_ciphers(),
                        'compression': conn.compression(),
                        'DER_peercert': conn.getpeercert(True),
                        'selected_alpn_protocol': conn.selected_alpn_protocol(),
                        'selected_npn_protocol': conn.selected_npn_protocol(),
                    }

                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,self.server_tls_params['DER_peercert'])
                    
                    out = ''
                    for elem in x509.get_subject().get_components():
                        out += f'\t{elem[0].decode()} = {elem[1].decode()}\n'

                    Logger.dbg(out)
                    self.results['SSL Certificate Subject components'] = out[1:-1]

                else:
                    sock.connect((host, port))
                    self.socket = sock

                Logger.dbg("Succeeded.")
                self.reconnect = 0
                return True

        except (socket.gaierror, 
                socket.timeout,  
                ConnectionResetError) as e:
            Logger.dbg(f"Failed.: {e}")
        return False

    @staticmethod
    def recvall(the_socket, timeout = 1.0):
        the_socket.setblocking(0)
        total_data = []
        data = ''
        begin = time.time()

        if not timeout:
            timeout = 1

        while 1:
            if total_data and time.time() - begin > timeout:
                break

            elif time.time() - begin > timeout * 2:
                break
            wait = 0
            try:
                data = the_socket.recv(4096).decode()
                if data:
                    total_data.append(data)
                    begin = time.time()
                    data = ''
                    wait = 0
                else:
                    time.sleep(0.1)
            except:
                pass
        
        result = ''.join(total_data)
        return result

    def send(self, data, dontReconnect = False):
        Logger.dbg(f"================= [SEND] =================\n{data}\n")
        
        try:
            self.socket.send(data.encode())
        except Exception as e:
            Logger.fail(f"Could not send data: {e}")

            if not self.reconnect < ExchangeRecon.MAX_RECONNECTS and not dontReconnect:
                self.reconnect += 1
                Logger.dbg("Reconnecing...")
                if self.connect(self.hostname, self.port):
                    return self.send(data, True)
                else:
                    Logger.err("Could not reconnect with remote host. Failure.")
                    sys.exit(-1)
        
        out = ExchangeRecon.recvall(self.socket, config['timeout'])

        if not out and self.reconnect < ExchangeRecon.MAX_RECONNECTS and not dontReconnect:
            Logger.dbg("No data returned. Reconnecting...")
            self.reconnect += 1
            if self.connect(self.hostname, self.port):
                return self.send(data, True)
            else:
                Logger.err("Could not reconnect with remote host. Failure.")
                sys.exit(-1)

        Logger.dbg(f"================= [RECV] =================\n{out}\n")
        return out

    def http(self, 
        method = 'GET', url = '/', host = None, 
        httpver = 'HTTP/1.1', data = None, headers = None,
        followRedirect = False, redirect = 0
    ):
        hdrs = ExchangeRecon.HEADERS.copy()
        if headers:
            hdrs.update(headers)

        if host:
            hdrs['Host'] = host

        headersstr = ''
        for k, v in hdrs.items():
            headersstr += f'{k}: {v}\r\n'

        if data:
            data = f'\r\n{data}'
        else:
            data = ''

        packet = f'{method} {url} {httpver}\r\n{headersstr}{data}\r\n\r\n'
        raw = self.send(packet)
        resp = ExchangeRecon.response(raw)

        if resp['code'] in [301, 302, 303] and followRedirect:
            Logger.dbg(f'Following redirect. Depth: {redirect}...')

            location = urlparse(resp['headers']['location'])
            port = 80 if location.scheme == 'http' else 443
            host = location.netloc
            if not host: host = self.hostname
            if ':' in location.netloc: 
                port = int(location.netloc.split(':')[1])
                host = location.netloc.split(':')[0]

            if self.connect(host, port):
                pos = resp['headers']['location'].find(location.path)
                return self.http(
                    method = 'GET', 
                    url = resp['headers']['location'][pos:], 
                    host = host,
                    data = '',
                    headers = headers,
                    followRedirect = redirect < ExchangeRecon.MAX_REDIRECTS,
                    redirect = redirect + 1)

        return resp, raw

    @staticmethod
    def response(data):
        resp = {
            'version' : '',
            'code' : 0,
            'message' : '',
            'headers' : {},
            'data' : ''
        }
        num = 0
        parsed = 0

        for line in data.split('\r\n'):
            parsed += len(line) + 2
            line = line.strip()
            if not line:
                break

            if num == 0:
                splitted = line.split(' ')
                resp['version'] = splitted[0]
                resp['code'] = int(splitted[1])
                resp['message'] = ' '.join(splitted[2:])
                num += 1
                continue

            num += 1
            pos = line.find(':')

            name = line[:pos].lower()
            val = line[pos+1:].strip()
            
            if name in resp['headers'].keys():
                if isinstance(resp['headers'][name], str):
                    old = resp['headers'][name]
                    resp['headers'][name] = [old]

                if val not in resp['headers'][name]:
                    try:
                        resp['headers'][name].append(int(val))
                    except ValueError:
                        resp['headers'][name].append(val)
            else:
                try:
                    resp['headers'][name] = int(val)
                except ValueError:
                    resp['headers'][name] = val

        if parsed > 0 and parsed < len(data):
            resp['data'] = data[parsed:]

        if 'content-length' in resp['headers'].keys() and len(resp['data']) != resp['headers']['content-length']:
            Logger.fail(f"Received data is not of declared by server length ({len(resp['data'])} / {resp['headers']['content-length']})!")

        return resp

    def inspect(self, resp):
        if resp['code'] == 0:
            return

        leakedInternalIp = 'Leaked Internal IP address'
        leakedInternalDomainNTLM = 'Leaked Internal Domain name in NTLM challenge packet'
        iisVersion = 'IIS Version'
        aspVersion = 'ASP.Net Version'

        regexes = {
            'Outlook Web App version leaked in OWA HTML source' : r'/owa/(?:auth/)?((?:\d+\.)+\d+)/(?:themes|scripts)/'
        }

        for k, v in resp['headers'].items():
            vals = []
            if isinstance(v, str):
                vals.append(v)
            elif isinstance(v, int):
                vals.append(str(v))
            else:
                vals.extend(v)
            lowervals = [x.lower() for x in vals]

            if k == 'www-authenticate':
                realms = list(filter(lambda x: 'basic realm="' in x, lowervals))
                if len(realms):
                    Logger.dbg(f"Got basic realm.: {str(realms)}")

                    m = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', realms[0])
                    if m:
                        self.results[leakedInternalIp] = m.group(1)

                negotiates = list(filter(lambda x: 'Negotiate ' in x, vals))
                if len(negotiates):
                    val = negotiates[0][len('Negotiate '):]
                    Logger.dbg('NTLM Message hex dump:\n' + hexdump(base64.b64decode(val)))
                    parsed = NtlmParser().parse(val)
                    Logger.dbg(f"Parsed NTLM Message:\n{str(parsed)}")

                    foo = ''
                    for k, v in parsed.items():
                        if isinstance(v, str):
                            try:
                                foo += f'\t{k}:\t{v}\n'
                            except: pass
                        elif isinstance(v, dict):
                            foo += f'\t{k}:\n'
                            for k2, v2 in v.items():
                                try:
                                    foo += f"\t\t{k2: <18}:\t{v2}\n"
                                except: pass
                        elif isinstance(v, list):
                            try:
                                foo += f'\t{k}:\t- ' + '\n\t\t- '.join(v) + '\n'
                            except: pass
                    self.results[leakedInternalDomainNTLM] = foo[1:]

            if k == 'server':
                self.results[iisVersion] = vals[0]

            if k == 'x-aspnet-version':
                self.results[aspVersion] = vals[0]

        for name, rex in regexes.items():
            m = re.search(rex, resp['data'])
            if m:
                self.results[name] = m.group(1)
                if 'Outlook Web App version leaked' in name:
                    ver = ExchangeRecon.parseVersion(m.group(1))
                    if ver:
                        self.results[name] += '\n\t({})'.format('; '.join(ver))

    @staticmethod
    def parseVersion(verstring):

        # https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
        versions = (
            ('Exchange Server 4.0 SP5 ', 'May 5, 1998', '4.0.996'),
            ('Exchange Server 4.0 SP4 ', 'March 28, 1997', '4.0.995'),
            ('Exchange Server 4.0 SP3 ', 'October 29, 1996', '4.0.994'),
            ('Exchange Server 4.0 SP2 ', 'July 19, 1996', '4.0.993'),
            ('Exchange Server 4.0 SP1 ', 'May 1, 1996', '4.0.838'),
            ('Exchange Server 4.0 Standard Edition', 'June 11, 1996', '4.0.837'),
            ('Exchange Server 5.0 SP2 ', 'February 19, 1998', '5.0.1460'),
            ('Exchange Server 5.0 SP1 ', 'June 18, 1997', '5.0.1458'),
            ('Exchange Server 5.0 ', 'May 23, 1997', '5.0.1457'),
            ('Exchange Server version 5.5 SP4 ', 'November 1, 2000', '5.5.2653'),
            ('Exchange Server version 5.5 SP3 ', 'September 9, 1999', '5.5.2650'),
            ('Exchange Server version 5.5 SP2 ', 'December 23, 1998', '5.5.2448'),
            ('Exchange Server version 5.5 SP1 ', 'August 5, 1998', '5.5.2232'),
            ('Exchange Server version 5.5 ', 'February 3, 1998', '5.5.1960'),
            ('Exchange 2000 Server post-SP3', 'August 2008', '6.0.6620.7'),
            ('Exchange 2000 Server post-SP3', 'March 2008', '6.0.6620.5'),
            ('Exchange 2000 Server post-SP3', 'August 2004', '6.0.6603'),
            ('Exchange 2000 Server post-SP3', 'April 2004', '6.0.6556'),
            ('Exchange 2000 Server post-SP3', 'September 2003', '6.0.6487'),
            ('Exchange 2000 Server SP3', 'July 18, 2002', '6.0.6249'),
            ('Exchange 2000 Server SP2', 'November 29, 2001', '6.0.5762'),
            ('Exchange 2000 Server SP1', 'June 21, 2001', '6.0.4712'),
            ('Exchange 2000 Server', 'November 29, 2000', '6.0.4417'),
            ('Exchange Server 2003 post-SP2', 'August 2008', '6.5.7654.4'),
            ('Exchange Server 2003 post-SP2', 'March 2008', '6.5.7653.33'),
            ('Exchange Server 2003 SP2', 'October 19, 2005', '6.5.7683'),
            ('Exchange Server 2003 SP1', 'May25, 2004', '6.5.7226'),
            ('Exchange Server 2003', 'September 28, 2003', '6.5.6944'),
            ('Update Rollup 5 for Exchange Server 2007 SP2', 'December 7, 2010', '8.2.305.3', '8.02.0305.003'),
            ('Update Rollup 4 for Exchange Server 2007 SP2', 'April 9, 2010', '8.2.254.0', '8.02.0254.000'),
            ('Update Rollup 3 for Exchange Server 2007 SP2', 'March 17, 2010', '8.2.247.2', '8.02.0247.002'),
            ('Update Rollup 2 for Exchange Server 2007 SP2', 'January 22, 2010', '8.2.234.1', '8.02.0234.001'),
            ('Update Rollup 1 for Exchange Server 2007 SP2', 'November 19, 2009', '8.2.217.3', '8.02.0217.003'),
            ('Exchange Server 2007 SP2', 'August 24, 2009', '8.2.176.2', '8.02.0176.002'),
            ('Update Rollup 10 for Exchange Server 2007 SP1', 'April 13, 2010', '8.1.436.0', '8.01.0436.000'),
            ('Update Rollup 9 for Exchange Server 2007 SP1', 'July 16, 2009', '8.1.393.1', '8.01.0393.001'),
            ('Update Rollup 8 for Exchange Server 2007 SP1', 'May 19, 2009', '8.1.375.2', '8.01.0375.002'),
            ('Update Rollup 7 for Exchange Server 2007 SP1', 'March 18, 2009', '8.1.359.2', '8.01.0359.002'),
            ('Update Rollup 6 for Exchange Server 2007 SP1', 'February 10, 2009', '8.1.340.1', '8.01.0340.001'),
            ('Update Rollup 5 for Exchange Server 2007 SP1', 'November 20, 2008', '8.1.336.1', '8.01.0336.01'),
            ('Update Rollup 4 for Exchange Server 2007 SP1', 'October 7, 2008', '8.1.311.3', '8.01.0311.003'),
            ('Update Rollup 3 for Exchange Server 2007 SP1', 'July 8, 2008', '8.1.291.2', '8.01.0291.002'),
            ('Update Rollup 2 for Exchange Server 2007 SP1', 'May 9, 2008', '8.1.278.2', '8.01.0278.002'),
            ('Update Rollup 1 for Exchange Server 2007 SP1', 'February 28, 2008', '8.1.263.1', '8.01.0263.001'),
            ('Exchange Server 2007 SP1', 'November 29, 2007', '8.1.240.6', '8.01.0240.006'),
            ('Update Rollup 7 for Exchange Server 2007', 'July 8, 2008', '8.0.813.0', '8.00.0813.000'),
            ('Update Rollup 6 for Exchange Server 2007', 'February 21, 2008', '8.0.783.2', '8.00.0783.002'),
            ('Update Rollup 5 for Exchange Server 2007', 'October 25, 2007', '8.0.754.0', '8.00.0754.000'),
            ('Update Rollup 4 for Exchange Server 2007', 'August 23, 2007', '8.0.744.0', '8.00.0744.000'),
            ('Update Rollup 3 for Exchange Server 2007', 'June 28, 2007', '8.0.730.1', '8.00.0730.001'),
            ('Update Rollup 2 for Exchange Server 2007', 'May 8, 2007', '8.0.711.2', '8.00.0711.002'),
            ('Update Rollup 1 for Exchange Server 2007', 'April 17, 2007', '8.0.708.3', '8.00.0708.003'),
            ('Exchange Server 2007 RTM', 'March 8, 2007', '8.0.685.25  8.00.0685.025'),
            ('Update Rollup 23 for Exchange Server 2007 SP3', 'March 21, 2017', '8.3.517.0', '8.03.0517.000'),
            ('Update Rollup 22 for Exchange Server 2007 SP3', 'December 13, 2016', '8.3.502.0', '8.03.0502.000'),
            ('Update Rollup 21 for Exchange Server 2007 SP3', 'September 20, 2016', '8.3.485.1', '8.03.0485.001'),
            ('Update Rollup 20 for Exchange Server 2007 SP3', 'June 21, 2016', '8.3.468.0', '8.03.0468.000'),
            ('Update Rollup 19 forExchange Server 2007 SP3', 'March 15, 2016', '8.3.459.0', '8.03.0459.000'),
            ('Update Rollup 18 forExchange Server 2007 SP3', 'December, 2015', '8.3.445.0', '8.03.0445.000'),
            ('Update Rollup 17 forExchange Server 2007 SP3', 'June 17, 2015', '8.3.417.1', '8.03.0417.001'),
            ('Update Rollup 16 for Exchange Server 2007 SP3', 'March 17, 2015', '8.3.406.0', '8.03.0406.000'),
            ('Update Rollup 15 for Exchange Server 2007 SP3', 'December 9, 2014', '8.3.389.2', '8.03.0389.002'),
            ('Update Rollup 14 for Exchange Server 2007 SP3', 'August 26, 2014', '8.3.379.2', '8.03.0379.002'),
            ('Update Rollup 13 for Exchange Server 2007 SP3', 'February 24, 2014', '8.3.348.2', '8.03.0348.002'),
            ('Update Rollup 12 for Exchange Server 2007 SP3', 'December 9, 2013', '8.3.342.4', '8.03.0342.004'),
            ('Update Rollup 11 for Exchange Server 2007 SP3', 'August 13, 2013', '8.3.327.1', '8.03.0327.001'),
            ('Update Rollup 10 for Exchange Server 2007 SP3', 'February 11, 2013', '8.3.298.3', '8.03.0298.003'),
            ('Update Rollup 9 for Exchange Server 2007 SP3', 'December 10, 2012', '8.3.297.2', '8.03.0297.002'),
            ('Update Rollup 8-v3 for Exchange Server 2007 SP3 ', 'November 13, 2012', '8.3.279.6', '8.03.0279.006'),
            ('Update Rollup 8-v2 for Exchange Server 2007 SP3 ', 'October 9, 2012', '8.3.279.5', '8.03.0279.005'),
            ('Update Rollup 8 for Exchange Server 2007 SP3', 'August 13, 2012', '8.3.279.3', '8.03.0279.003'),
            ('Update Rollup 7 for Exchange Server 2007 SP3', 'April 16, 2012', '8.3.264.0', '8.03.0264.000'),
            ('Update Rollup 6 for Exchange Server 2007 SP3', 'January 26, 2012', '8.3.245.2', '8.03.0245.002'),
            ('Update Rollup 5 for Exchange Server 2007 SP3', 'September 21, 2011', '8.3.213.1', '8.03.0213.001'),
            ('Update Rollup 4 for Exchange Server 2007 SP3', 'May 28, 2011', '8.3.192.1', '8.03.0192.001'),
            ('Update Rollup 3-v2 for Exchange Server 2007 SP3 ', 'March 30, 2011', '8.3.159.2', '8.03.0159.002'),
            ('Update Rollup 2 for Exchange Server 2007 SP3', 'December 10, 2010', '8.3.137.3', '8.03.0137.003'),
            ('Update Rollup 1 for Exchange Server 2007 SP3', 'September 9, 2010', '8.3.106.2', '8.03.0106.002'),
            ('Exchange Server 2007 SP3', 'June 7, 2010', '8.3.83.6', '8.03.0083.006'),
            ('Update Rollup 8 for Exchange Server 2010 SP2', 'December 9, 2013', '14.2.390.3  14.02.0390.003'),
            ('Update Rollup 7 for Exchange Server 2010 SP2', 'August 3, 2013', '14.2.375.0  14.02.0375.000'),
            ('Update Rollup 6 Exchange Server 2010 SP2', 'February 12, 2013', '14.2.342.3  14.02.0342.003'),
            ('Update Rollup 5 v2 for Exchange Server 2010 SP2 ', 'December 10, 2012', '14.2.328.10 14.02.0328.010'),
            ('Update Rollup 5 for Exchange Server 2010 SP2', 'November 13, 2012', '14.3.328.5  14.03.0328.005'),
            ('Update Rollup 4 v2 for Exchange Server 2010 SP2 ', 'October 9, 2012', '14.2.318.4  14.02.0318.004'),
            ('Update Rollup 4 for Exchange Server 2010 SP2', 'August 13, 2012', '14.2.318.2  14.02.0318.002'),
            ('Update Rollup 3 for Exchange Server 2010 SP2', 'May 29, 2012', '14.2.309.2  14.02.0309.002'),
            ('Update Rollup 2 for Exchange Server 2010 SP2', 'April 16, 2012', '14.2.298.4  14.02.0298.004'),
            ('Update Rollup 1 for Exchange Server 2010 SP2', 'February 13, 2012', '14.2.283.3  14.02.0283.003'),
            ('Exchange Server 2010 SP2', 'December 4, 2011', '14.2.247.5  14.02.0247.005'),
            ('Update Rollup 8 for Exchange Server 2010 SP1', 'December 10, 2012', '14.1.438.0  14.01.0438.000'),
            ('Update Rollup 7 v3 for Exchange Server 2010 SP1 ', 'November 13, 2012', '14.1.421.3  14.01.0421.003'),
            ('Update Rollup 7 v2 for Exchange Server 2010 SP1 ', 'October 10, 2012', '14.1.421.2  14.01.0421.002'),
            ('Update Rollup 7 for Exchange Server 2010 SP1', 'August 8, 2012', '14.1.421.0  14.01.0421.000'),
            ('Update Rollup 6 for Exchange Server 2010 SP1', 'October 27, 2011', '14.1.355.2  14.01.0355.002'),
            ('Update Rollup 5 for Exchange Server 2010 SP1', 'August 23, 2011', '14.1.339.1  14.01.0339.001'),
            ('Update Rollup 4 for Exchange Server 2010 SP1', 'July 27, 2011', '14.1.323.6  14.01.0323.006'),
            ('Update Rollup 3 for Exchange Server 2010 SP1', 'April 6, 2011', '14.1.289.7  14.01.0289.007'),
            ('Update Rollup 2 for Exchange Server 2010 SP1', 'December 9, 2010', '14.1.270.1  14.01.0270.001'),
            ('Update Rollup 1 for Exchange Server 2010 SP1', 'October 4, 2010', '14.1.255.2  14.01.0255.002'),
            ('Exchange Server 2010 SP1', 'August 23, 2010', '14.1.218.15 14.01.0218.015'),
            ('Update Rollup 5 for Exchange Server 2010', 'December 13, 2010', '14.0.726.0  14.00.0726.000'),
            ('Update Rollup 4 for Exchange Server 2010', 'June 10, 2010', '14.0.702.1  14.00.0702.001'),
            ('Update Rollup 3 for Exchange Server 2010', 'April 13, 2010', '14.0.694.0  14.00.0694.000'),
            ('Update Rollup 2 for Exchange Server 2010', 'March 4, 2010', '14.0.689.0  14.00.0689.000'),
            ('Update Rollup 1 for Exchange Server 2010', 'December 9, 2009', '14.0.682.1  14.00.0682.001'),
            ('Exchange Server 2010 RTM', 'November 9, 2009', '14.0.639.21 14.00.0639.021'),
            ('Update Rollup 29 for Exchange Server 2010 SP3', 'July 9, 2019', '14.3.468.0  14.03.0468.000'),
            ('Update Rollup 28 for Exchange Server 2010 SP3', 'June 7, 2019', '14.3.461.1  14.03.0461.001'),
            ('Update Rollup 27 for Exchange Server 2010 SP3', 'April 9, 2019', '14.3.452.0  14.03.0452.000'),
            ('Update Rollup 26 for Exchange Server 2010 SP3', 'February 12, 2019', '14.3.442.0  14.03.0442.000'),
            ('Update Rollup 25 for Exchange Server 2010 SP3', 'January 8, 2019', '14.3.435.0  14.03.0435.000'),
            ('Update Rollup 24 for Exchange Server 2010 SP3', 'September 5, 2018', '14.3.419.0  14.03.0419.000'),
            ('Update Rollup 23 for Exchange Server 2010 SP3', 'August 13, 2018', '14.3.417.1  14.03.0417.001'),
            ('Update Rollup 22 for Exchange Server 2010 SP3', 'June 19, 2018', '14.3.411.0  14.03.0411.000'),
            ('Update Rollup 21 for Exchange Server 2010 SP3', 'May 7, 2018', '14.3.399.2  14.03.0399.002'),
            ('Update Rollup 20 for Exchange Server 2010 SP3', 'March 5, 2018', '14.3.389.1  14.03.0389.001'),
            ('Update Rollup 19 for Exchange Server 2010 SP3', 'December 19, 2017', '14.3.382.0  14.03.0382.000'),
            ('Update Rollup 18 for Exchange Server 2010 SP3', 'July 11, 2017', '14.3.361.1  14.03.0361.001'),
            ('Update Rollup 17 for Exchange Server 2010 SP3', 'March 21, 2017', '14.3.352.0  14.03.0352.000'),
            ('Update Rollup 16 for Exchange Server 2010 SP3', 'December 13, 2016', '14.3.336.0  14.03.0336.000'),
            ('Update Rollup 15 for Exchange Server 2010 SP3', 'September 20, 2016', '14.3.319.2  14.03.0319.002'),
            ('Update Rollup 14 for Exchange Server 2010 SP3', 'June 21, 2016', '14.3.301.0  14.03.0301.000'),
            ('Update Rollup 13 for Exchange Server 2010 SP3', 'March 15, 2016', '14.3.294.0  14.03.0294.000'),
            ('Update Rollup 12 for Exchange Server 2010 SP3', 'December 15, 2015', '14.3.279.2  14.03.0279.002'),
            ('Update Rollup 11 for Exchange Server 2010 SP3', 'September 15, 2015', '14.3.266.2  14.03.0266.002'),
            ('Update Rollup 10 for Exchange Server 2010 SP3', 'June 17, 2015', '14.3.248.2  14.03.0248.002'),
            ('Update Rollup 9 for Exchange Server 2010 SP3', 'March 17, 2015', '14.3.235.1  14.03.0235.001'),
            ('Update Rollup 8 v2 for Exchange Server 2010 SP3 ', 'December 12, 2014', '14.3.224.2  14.03.0224.002'),
            ('Update Rollup 8 v1 for Exchange Server 2010 SP3 (recalled)  ', 'December 9, 2014', '14.3.224.1  14.03.0224.001'),
            ('Update Rollup 7 for Exchange Server 2010 SP3', 'August 26, 2014', '14.3.210.2  14.03.0210.002'),
            ('Update Rollup 6 for Exchange Server 2010 SP3', 'May 27, 2014', '14.3.195.1  14.03.0195.001'),
            ('Update Rollup 5 for Exchange Server 2010 SP3', 'February 24, 2014', '14.3.181.6  14.03.0181.006'),
            ('Update Rollup 4 for Exchange Server 2010 SP3', 'December 9, 2013', '14.3.174.1  14.03.0174.001'),
            ('Update Rollup 3 for Exchange Server 2010 SP3', 'November 25, 2013', '14.3.169.1  14.03.0169.001'),
            ('Update Rollup 2 for Exchange Server 2010 SP3', 'August 8, 2013', '14.3.158.1  14.03.0158.001'),
            ('Update Rollup 1 for Exchange Server 2010 SP3', 'May 29, 2013', '14.3.146.0  14.03.0146.000'),
            ('Exchange Server 2010 SP3', 'February 12, 2013', '14.3.123.4  14.03.0123.004'),
            ('Exchange Server 2013 CU23', 'June 18, 2019', '15.0.1497.2 15.00.1497.002'),
            ('Exchange Server 2013 CU22', 'February 12, 2019', '15.0.1473.3 15.00.1473.003'),
            ('Exchange Server 2013 CU21', 'June 19, 2018', '15.0.1395.4 15.00.1395.004'),
            ('Exchange Server 2013 CU20', 'March 20, 2018', '15.0.1367.3 15.00.1367.003'),
            ('Exchange Server 2013 CU19', 'December 19, 2017', '15.0.1365.1 15.00.1365.001'),
            ('Exchange Server 2013 CU18', 'September 19, 2017', '15.0.1347.2 15.00.1347.002'),
            ('Exchange Server 2013 CU17', 'June 27, 2017', '15.0.1320.4 15.00.1320.004'),
            ('Exchange Server 2013 CU16', 'March 21, 2017', '15.0.1293.2 15.00.1293.002'),
            ('Exchange Server 2013 CU15', 'December 13, 2016', '15.0.1263.5 15.00.1263.005'),
            ('Exchange Server 2013 CU14', 'September 20, 2016', '15.0.1236.3 15.00.1236.003'),
            ('Exchange Server 2013 CU13', 'June 21, 2016', '15.0.1210.3 15.00.1210.003'),
            ('Exchange Server 2013 CU12', 'March 15, 2016', '15.0.1178.4 15.00.1178.004'),
            ('Exchange Server 2013 CU11', 'December 15, 2015', '15.0.1156.6 15.00.1156.006'),
            ('Exchange Server 2013 CU10', 'September 15, 2015', '15.0.1130.7 15.00.1130.007'),
            ('Exchange Server 2013 CU9', 'June 17, 2015', '15.0.1104.5 15.00.1104.005'),
            ('Exchange Server 2013 CU8', 'March 17, 2015', '15.0.1076.9 15.00.1076.009'),
            ('Exchange Server 2013 CU7', 'December 9, 2014', '15.0.1044.25', '15.00.1044.025'),
            ('Exchange Server 2013 CU6', 'August 26, 2014', '15.0.995.29 15.00.0995.029'),
            ('Exchange Server 2013 CU5', 'May 27, 2014', '15.0.913.22 15.00.0913.022'),
            ('Exchange Server 2013 SP1', 'February 25, 2014', '15.0.847.32 15.00.0847.032'),
            ('Exchange Server 2013 CU3', 'November 25, 2013', '15.0.775.38 15.00.0775.038'),
            ('Exchange Server 2013 CU2', 'July 9, 2013', '15.0.712.24 15.00.0712.024'),
            ('Exchange Server 2013 CU1', 'April 2, 2013', '15.0.620.29 15.00.0620.029'),
            ('Exchange Server 2013 RTM', 'December 3, 2012', '15.0.516.32 15.00.0516.03'),
            ('Exchange Server 2016 CU14', 'September 17, 2019', '15.1.1847.3 15.01.1847.003'),
            ('Exchange Server 2016 CU13', 'June 18, 2019', '15.1.1779.2 15.01.1779.002'),
            ('Exchange Server 2016 CU12', 'February 12, 2019', '15.1.1713.5 15.01.1713.005'),
            ('Exchange Server 2016 CU11', 'October 16, 2018', '15.1.1591.10', '15.01.1591.010'),
            ('Exchange Server 2016 CU10', 'June 19, 2018', '15.1.1531.3 15.01.1531.003'),
            ('Exchange Server 2016 CU9', 'March 20, 2018', '15.1.1466.3 15.01.1466.003'),
            ('Exchange Server 2016 CU8', 'December 19, 2017', '15.1.1415.2 15.01.1415.002'),
            ('Exchange Server 2016 CU7', 'September 19, 2017', '15.1.1261.35', '15.01.1261.035'),
            ('Exchange Server 2016 CU6', 'June 27, 2017', '15.1.1034.26', '15.01.1034.026'),
            ('Exchange Server 2016 CU5', 'March 21, 2017', '15.1.845.34 15.01.0845.034'),
            ('Exchange Server 2016 CU4', 'December 13, 2016', '15.1.669.32 15.01.0669.032'),
            ('Exchange Server 2016 CU3', 'September 20, 2016', '15.1.544.27 15.01.0544.027'),
            ('Exchange Server 2016 CU2', 'June 21, 2016', '15.1.466.34 15.01.0466.034'),
            ('Exchange Server 2016 CU1', 'March 15, 2016', '15.1.396.30 15.01.0396.030'),
            ('Exchange Server 2016 RTM', 'October 1, 2015', '15.1.225.42 15.01.0225.042'),
            ('Exchange Server 2016 Preview', 'July 22, 2015', '15.1.225.16 15.01.0225.016'),
            ('Exchange Server 2019 CU3', 'September 17, 2019', '15.2.464.5  15.02.0464.005'),
            ('Exchange Server 2019 CU2', 'June 18, 2019', '15.2.397.3  15.02.0397.003'),
            ('Exchange Server 2019 CU1', 'February 12, 2019', '15.2.330.5  15.02.0330.005'),
            ('Exchange Server 2019 RTM', 'October 22, 2018', '15.2.221.12 15.02.0221.012'),
            ('Exchange Server 2019 Preview', 'July 24, 2018', '15.2.196.0  15.02.0196.000')
        )

        for ver in versions:
            for subver in ver:
                if verstring in subver:
                    return ver

        return None


    def verifyExchange(self):
        # Fetching these paths as unauthorized must result in 401
        verificationPaths = (
            # (path, redirect, sendHostHeader /* HTTP/1.1 */)
            ('/owa', True, True),
            ('/autodiscover/autodiscover.xml', True, False),
            ('/Microsoft-Server-ActiveSync', True, False),
            ('/EWS/Exchange.asmx', True, False),
            ('/ecp/?ExchClientVer=15', False, False),
        )

        definitiveMarks = (
            '<title>Outlook Web App</title>',
            '<!-- OwaPage = ASP.auth_logon_aspx -->',
            'Set-Cookie: exchangecookie=',
            'Set-Cookie: OutlookSession=',
            '/owa/auth/logon.aspx?url=https://',
            '{57A118C6-2DA9-419d-BE9A-F92B0F9A418B}',
            'To use Outlook Web App, browser settings must allow scripts to run. For information about how to allow scripts'
        )

        otherMarks = (
            'Location: /owa/',
            'Microsoft-IIS/',
            'Negotiate TlRM',
            'WWW-Authenticate: Negotiate',
            'ASP.NET'
        )

        score = 0
        definitive = False

        for path, redirect, sendHostHeader in verificationPaths:
            if not sendHostHeader:
                resp, raw = self.http(url = path, httpver = 'HTTP/1.0', followRedirect = redirect)
            else:
                r = requests.get(f'https://{self.hostname}{path}', verify = False, allow_redirects = True)
                resp = {
                    'version' : 'HTTP/1.1',
                    'code' : r.status_code,
                    'message' : r.reason,
                    'headers' : r.headers,
                    'data' : r.text
                }
                raw = r.text

            Logger.info(f"Got HTTP Code={resp['code']} on access to ({path})")
            
            if resp['code'] in [301, 302]:
                loc = f'https://{self.hostname}/owa/auth/logon.aspx?url=https://{self.hostname}/owa/&reason=0'
                if loc in raw: 
                    definitive = True
                    score += 2

            if resp['code'] == 401: score += 1
            
            for mark in otherMarks:
                if mark in str(raw):
                    score += 1

            for mark in definitiveMarks:
                if mark in str(raw):
                    score += 2
                    definitive = True

            self.inspect(resp)

        Logger.info(f"Exchange scored with: {score}. Definitively sure it's an Exchange? {definitive}")
        return score > 15 or definitive

    def tryToTriggerNtlmAuthentication(self):
        verificationPaths = (
            '/autodiscover/autodiscover.xml',
        )

        for path in verificationPaths:
            auth = {
                'Authorization': 'Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==',
                'X-Nego-Capability': 'Negotiate, Kerberos, NTLM',
                'X-User-Identity': 'john.doe@example.com',
                'Content-Length': '0',
            }
            resp, raw = self.http(method = 'POST', host = self.hostname, url = path, headers = auth)
            self.inspect(resp)

    def process(self):
        for port in ExchangeRecon.COMMON_PORTS:
            if self.connect(self.hostname, port):
                self.port = port
                Logger.ok(f"Connected with {self.hostname}:{port}\n")
                break

        if not self.port:
            Logger.err(f"Could not contact {self.hostname}. Failure.\n")
            return False

        Logger.info("Probing for Exchange fingerprints...")
        if not self.verifyExchange():
            Logger.err("Specified target hostname is not an Exchange server.")
            return False

        Logger.info("Triggering NTLM authentication...")
        self.tryToTriggerNtlmAuthentication()

        Logger.info("Probing support for legacy mail protocols and their functions...")
        self.legacyMailFingerprint()

    def legacyMailFingerprint(self):
        self.socket.close()
        self.socket = None

        for port in (25, 465, 587):
            try:
                Logger.dbg(f"Trying smtp on port {port}...")
                if self.smtpInteract(self.hostname, port, _ssl = False):
                    break
                else:
                    Logger.dbg(f"Trying smtp SSL on port {port}...")
                    self.smtpInteract(self.hostname, port, _ssl = True)

            except Exception as e:
                Logger.dbg(f"Failed fetching SMTP replies: {e}")
                raise
                continue

    @staticmethod
    def _smtpconnect(host, port, _ssl):
        server = None
        try:
            if _ssl:
                server = smtplib.SMTP_SSL(host = host, port = port, 
                    local_hostname = 'smtp.gmail.com', timeout = config['timeout'])
            else:
                server = smtplib.SMTP(host = host, port = port, 
                    local_hostname = 'smtp.gmail.com', timeout = config['timeout'])

            if config['debug']:
                server.set_debuglevel(True)

            return server
        except Exception as e:
            Logger.dbg(f"Could not connect to SMTP server on SSL={_ssl} port={port}. Error: {e}")
            return None

    def smtpInteract(self, host, port, _ssl):
        server = ExchangeRecon._smtpconnect(host, port, _ssl)
        if not server:
            return None

        capabilities = []

        try:
            code, msg = server.ehlo()
        except Exception:
            server = ExchangeRecon._smtpconnect(host, port, _ssl)
            if not server:
                return None
            code, msg = server.ehlo()

        msg = msg.decode()
        for line in msg.split('\n'):
            capabilities.append(line.strip())

        try:
            server.starttls()
            code, msg = server.ehlo()
        except Exception:
            server = ExchangeRecon._smtpconnect(host, port, _ssl)
            if not server:
                return None
            server.ehlo()
            server.starttls()
            code, msg = server.ehlo()

        msg = msg.decode()
        Logger.info(f"SMTP server banner & capabilities:\n-------\n{msg}\n-------\n")
        for line in msg.split('\n'):
            capabilities.append(line.strip())

        try:
            msg = server.help()
        except Exception:
            server = ExchangeRecon._smtpconnect(host, port, _ssl)
            if not server:
                return None
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except:
                pass
            msg = server.help()

        msg = msg.decode()
        for line in msg.split('\n'):
            capabilities.append(line.strip())

        skipThese = (
            '8BITMIME',
            'STARTTLS',
            'PIPELINING',
            'AUTH ',
            'CHUNKING',
            'SIZE ',
            'ENHANCEDSTATUSCODES',
            'SMTPUTF8',
            'DSN',
            'BINARYMIME',
            'HELP',
            'QUIT',
            'DATA',
            'EHLO',
            'HELO',
            'GSSAPI',
            'X-EXPS',
            'X-ANONYMOUSTLS',
        )

        unfiltered = set()
        for line in capabilities:
            skip = False
            for n in skipThese:
                if n in line:
                    skip = True
                    break
            if not skip:
                unfiltered.add(line)


        if len(unfiltered):
            self.results["Exchange supports legacy SMTP and returns following unusual capabilities"] = '\n\t- '.join(unfiltered)

        try:
            server.quit()
        except:
            pass

        self.verifyEnumerationOpportunities(host, port, _ssl)

    def verifyEnumerationOpportunities(self, host, port, _ssl):

        Logger.info("Examining potential methods for SMTP user enumeration...")
        server = ExchangeRecon._smtpconnect(host, port, _ssl)
        if not server:
            return None

        ip = socket.gethostbyname(self.hostname)
        techniques = {
            f'MAIL FROM:<test@[{ip}]>' : None,
            f'RCPT TO:<test@[{ip}]>' : None,
            f'VRFY root' : None,
            f'EXPN root' : None,
        }

        likely = 0
        for data in techniques.keys():
            for i in range(3):
                try:
                    server = ExchangeRecon._smtpconnect(host, port, _ssl)
                    server.ehlo()
                    try:
                        server.starttls()
                        server.ehlo()
                    except:
                        pass
                    code, msg = server.docmd(data)
                    msg = msg.decode()
                    techniques[data] = f'({code}, "{msg}")'
                    server.quit()

                    Logger.dbg(f"Attempted user enumeration using: ({data}). Result: {techniques[data]}")

                    if code >= 200 and code <= 299:
                        Logger.ok(f"Method {data} may allow SMTP user enumeration.")
                        likely += 1
                    else:
                        Logger.fail(f"Method {data} is unlikely to allow SMTP user enumeration.")
                    break
                except Exception as e:
                    Logger.dbg(f"Exception occured during SMTP User enumeration attempt: {e}")
                    continue

        out = ''
        for k, v in techniques.items():
            code = eval(v)[0]
            c = '?'
            if code >= 200 and code <= 299: c = '+'
            if code >= 500 and code <= 599: c = '-'

            out += f'\n\t- [{c}] {k: <50} returned: {v}'

        self.results["Results for SMTP User Enumeration attempts"] = out[2:]



def parseOptions(argv):
    global config

    print('''
        :: Exchange Reconnaisance Toolkit
        Tries to obtain internal IP address, Domain name and other clues by talking to Exchange
        Mariusz B. / mgeeky '19, <mb@binary-offensive.com>
        v{}
'''.format(VERSION))

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <hostname>')
    parser.add_argument('hostname', metavar='<domain|ip>', type=str, help='Hostname of the Exchange server (or IP address).')

    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')
    parser.add_argument('-d', '--debug', action='store_true', help='Display debug output.')

    args = parser.parse_args()

    if not 'hostname' in args:
        Logger.err('You must specify a hostname to launch!')
        return False

    config['verbose'] = args.verbose
    config['debug'] = args.debug

    return args

def output(hostname, out):
    print("\n======[ Leaked clues about internal environment ]======\n")
    print(f"\nHostname: {hostname}\n")

    for k, v in out.items():
        print(f"*) {k}:\n\t{v}\n")

def main(argv):
    opts = parseOptions(argv)
    if not opts:
        Logger.err('Options parsing failed.')
        return False

    recon = ExchangeRecon(opts.hostname)

    try:
        t = threading.Thread(target = recon.process)
        t.setDaemon(True)
        t.start()

        while t.is_alive():
            t.join(3.0)

    except KeyboardInterrupt:
        Logger.fail("Interrupted by user.")

    if len(recon.results) > 1:
        output(opts.hostname, recon.results)    

if __name__ == '__main__':
    main(sys.argv)
