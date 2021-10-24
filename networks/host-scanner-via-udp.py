#!/usr/bin/python

#
# Simple UDP scanner determining whether scanned host replies with
# ICMP Desitnation Unreachable upon receiving UDP packet on some high, closed port.
#
# Based on "Black Hat Python" book by Justin Seitz.
#
# Mariusz Banach
#

import os
import sys
import time
import ctypes
import struct
import socket
import threading
from datetime import datetime

try:
    from netaddr import IPNetwork, IPAddress
except ImportError:
    print('[!] No module named "netaddr". Please type:\n\tpip install netaddr')
    sys.exit(1)

DEBUG = False

# Ports that will be used during scanning, considered as most likely closed ports.
SCAN_PORTS = range(65212, 65220)

HOSTS_UP = set()
MAGIC_MESSAGE = '\xec\xcb\x5c\x6f\x41\xbe\x2e\x71\x9e\xd1'


class ICMP(ctypes.Structure):
    _fields_ = [
        ('type',        ctypes.c_ubyte),
        ('code',        ctypes.c_ubyte),
        ('chksum',      ctypes.c_ushort),
        ('unused',      ctypes.c_ushort),
        ('nexthop',     ctypes.c_ushort)
    ]

    def __new__(self, sockBuff = None):
        return self.from_buffer_copy(sockBuff)

    def __init__(self, sockBuff = None):
        self.types_map = {
            0:'Echo Reply',1:'Unassigned',2:'Unassigned ',3:'Destination Unreachable',
            4:'Source Quench',5:'Redirect',6:'Alternate Host Address',7:'Unassigned',
            8:'Echo',9:'Router Advertisement',10:'Router Solicitation',11:'Time Exceeded',
            12:'Parameter Problem',13:'Timestamp',14:'Timestamp Reply',15:'Information Request',
            16:'Information Reply',17:'Address Mask Request',18:'Address Mask Reply',
            30:'Traceroute',31:'Datagram Conversion Error',32:'Mobile Host Redirect',
            33:'IPv6 Where-Are-You',34:'IPv6 I-Am-Here',35:'Mobile Registration Request',
            36:'Mobile Registration Reply',37:'Domain Name Request',38:'Domain Name Reply',
            39:'SKIP',40:'Photuris'
        }

        # Human readable protocol
        try:
            self.message = self.types_map[self.type]
        except:
            self.message = str('')

#
# IPv4 packet structure definition in ctypes.
#
class IP(ctypes.Structure):
    _fields_ = [
        ('ihl',             ctypes.c_ubyte, 4),
        ('version',         ctypes.c_ubyte, 4),
        ('tos',             ctypes.c_ubyte),
        ('len',             ctypes.c_ushort),
        ('id',              ctypes.c_ushort),
        ('offset',          ctypes.c_ushort),
        ('ttl',             ctypes.c_ubyte),
        ('protocol_num',    ctypes.c_ubyte),
        ('sum',             ctypes.c_ushort),
        ('src',             ctypes.c_uint),
        ('dst',             ctypes.c_uint)
    ]

    def __new__(self, socketBuffer = None):
        return self.from_buffer_copy(socketBuffer)

    def __init__(self, socketBuffer = None):
        # Map protocol constants to their names.
        self.protocol_map = {
            0:'HOPOPT',1:'ICMP',2:'IGMP',3:'GGP',4:'IPv4',5:'ST',6:'TCP',7:'CBT',8:'EGP',
            9:'IGP',10:'BBN-RCC-MON',11:'NVP-II',12:'PUP',13:'ARGUS',14:'EMCON',15:'XNET',16:'CHAOS',
            17:'UDP',18:'MUX',19:'DCN-MEAS',20:'HMP',21:'PRM',22:'XNS-IDP',23:'TRUNK-1',24:'TRUNK-2',
            25:'LEAF-1',26:'LEAF-2',27:'RDP',28:'IRTP',29:'ISO-TP4',30:'NETBLT',31:'MFE-NSP',32:'MERIT-INP',
            33:'DCCP',34:'3PC',35:'IDPR',36:'XTP',37:'DDP',38:'IDPR-CMTP',39:'TP++',40:'IL',
            41:'IPv6',42:'SDRP',43:'IPv6-Route',44:'IPv6-Frag',45:'IDRP',46:'RSVP',47:'GRE',48:'DSR',
            49:'BNA',50:'ESP',51:'AH',52:'I-NLSP',53:'SWIPE',54:'NARP',55:'MOBILE',56:'TLSP',
            57:'SKIP',58:'IPv6-ICMP',59:'IPv6-NoNxt',60:'IPv6-Opts',62:'CFTP',64:'SAT-EXPAK',
            65:'KRYPTOLAN',66:'RVD',67:'IPPC',69:'SAT-MON',70:'VISA',71:'IPCV',72:'CPNX',
            73:'CPHB',74:'WSN',75:'PVP',76:'BR-SAT-MON',77:'SUN-ND',78:'WB-MON',79:'WB-EXPAK',80:'ISO-IP',
            81:'VMTP',82:'SECURE-VMTP',83:'VINES',84:'TTP',84:'IPTM',85:'NSFNET-IGP',86:'DGP',87:'TCF',88:'EIGRP',
            89:'OSPFIGP',90:'Sprite-RPC',91:'LARP',92:'MTP',93:'AX.25',94:'IPIP',95:'MICP',96:'SCC-SP',
            97:'ETHERIP',98:'ENCAP',100:'GMTP',101:'IFMP',102:'PNNI',103:'PIM',104:'ARIS',
            105:'SCPS',106:'QNX',107:'A/N',108:'IPComp',109:'SNP',110:'Compaq-Peer',111:'IPX-in-IP',112:'VRRP',
            113:'PGM',115:'L2TP',116:'DDX',117:'IATP',118:'STP',119:'SRP',120:'UTI',
            121:'SMP',122:'SM',123:'PTP',124:'ISIS',125:'FIRE',126:'CRTP',127:'CRUDP',128:'SSCOPMCE',
            129:'IPLT',130:'SPS',131:'PIPE',132:'SCTP',133:'FC',134:'RSVP-E2E-IGNORE',135:'Mobility',136:'UDPLite',
            137:'MPLS-in-IP',138:'manet',139:'HIP',140:'Shim6',141:'WESP',142:'ROHC'
        }

        # Human readable IP addresses.
        try:
            self.src_address = socket.inet_ntoa(struct.pack('<L', self.src))
        except:
            print('[!] Could not represent incoming packet\'s source address: {}'.format(self.src))
            self.src_address = '127.0.0.1'

        try:
            self.dst_address = socket.inet_ntoa(struct.pack('<L', self.dst))
        except:
            print('[!] Could not represent incoming packet\'s destination address: {}'.format(self.dst))
            self.dst_address = '127.0.0.1'

        # Human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


def udpSend(subnet, message):
    time.sleep(5)
    if DEBUG: 
        print('[.] Started spraying UDP packets across {}'.format(str(subnet)))

    packets = 0
    ports = [x for x in SCAN_PORTS]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            for port in ports:
                sender.sendto(message, (str(ip), port))
                packets += 1
        except Exception, e:
            pass

    print('[.] Spraying thread finished. Sent: {} packets on {} hosts.'.format(
        packets, len(IPNetwork(subnet))
    ))

def processPackets(sniffer, subnet):
    global HOSTS_UP

    # Read in single packet
    try:
        packetNum = 0

        while True:
            packetPrint = ''
            packetNum += 1

            packet = sniffer.recvfrom((1 << 16) - 1)[0]

            # Create an IP header from the first 20 bytes of the buffer.
            ipHeader = IP(packet[0 : ctypes.sizeof(IP)])

            timeNow = datetime.now().strftime('%H:%M:%S.%f')[:-3]

            # Print out the protocol that was detected and the hosts.
            packetPrint += '[{:05} | {}] {} {} > {}'.format(
                packetNum, timeNow, ipHeader.protocol, ipHeader.src_address, ipHeader.dst_address,
            )

            if ipHeader.protocol == 'ICMP':
                offset = ipHeader.ihl * 4
                icmpBuf = packet[offset : offset + ctypes.sizeof(ICMP)]
                icmpHeader = ICMP(icmpBuf)

                packetPrint += ': ICMP Type: {} ({}), Code: {}\n'.format(
                    icmpHeader.type, icmpHeader.message, icmpHeader.code
                )

                if DEBUG: 
                    packetPrint += hexdump(packet)

                # Destination unreachable
                if icmpHeader.code == 3 and icmpHeader.type == 3:
                    if IPAddress(ipHeader.src_address) in IPNetwork(subnet):

                        # Make sure it contains our message
                        if packet[- len(MAGIC_MESSAGE):] == MAGIC_MESSAGE:
                            host = ipHeader.src_address
                            if host not in HOSTS_UP:
                                print('[+] HOST IS UP: {}'.format(host))
                                HOSTS_UP.add(host)
                
                if DEBUG:
                    print(packetPrint)

    except KeyboardInterrupt:
        return

def hexdump(src, length = 16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    num = len(src)
    
    for i in range(0, num, length):
        s = src[i:i+length]
        hexa = b' '.join(['%0*X' % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7f else b'.' for x in s])
        
        result.append(b'%04x  |  %-*s  |  %s' % (i, length * (digits + 1), hexa, text)) 

    return '\n'.join(result)

def main(argv):
    global BIND

    if len(argv) < 3:
        print('Usage: ./udp-scan.py <bind-ip> <target-subnet>')
        sys.exit(1)

    bindAddr = sys.argv[1]
    subnet = sys.argv[2]

    sockProto = None
    if os.name == 'nt':
        sockProto = socket.IPPROTO_IP
    else:
        sockProto = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, sockProto)
    if DEBUG: print('[.] Binding on {}:0'.format(bindAddr))
    sniffer.bind((bindAddr, 0))

    # Include IP headers in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # In Windows, set up promiscous mode.
    if os.name == 'nt':
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except socket.error, e:
            print('[!] Could not set promiscous mode ON: "{}"'.format(str(e)))

    # Sending thread
    threading.Thread(target=udpSend, args=(subnet, MAGIC_MESSAGE)).start()

    # Receiving thread
    recvThread = threading.Thread(target=processPackets, args=(sniffer, subnet))
    recvThread.daemon = True
    recvThread.start()

    time.sleep(15)
    if DEBUG: print('[.] Breaking response wait loop.')

    # Turn off promiscous mode
    if os.name == 'nt':
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except socket.error, e:
            pass

if __name__ == '__main__':
    main(sys.argv)
