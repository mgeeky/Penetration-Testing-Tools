#!/usr/bin/python

import sys
import netaddr
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr1, IP, ICMP

PING_TIMEOUT = 3
IFACE='eth0'

if __name__ == '__main__':
    print '\tQuick Ping Sweep\n'

    if len(sys.argv) != 2:
        print '[?] Usage: pingsweep <network>'
        sys.exit(0)
    
    net = sys.argv[1]
    print 'Input network:', net

    responding = []
    network = netaddr.IPNetwork(net)

    for ip in network:
        if ip == network.network or ip == network.broadcast:
            continue

        # Send & wait for response for the ICMP Echo Request packet
        reply = sr1( IP(dst=str(ip)) / ICMP(), timeout=PING_TIMEOUT, iface=IFACE, verbose=0 )

        if not reply:
            continue

        if int(reply.getlayer(ICMP).type) == 0 and int(reply.getlayer(ICMP).code) == 0:
            print ip, ': Host is responding to ICMP Echo Requests.'
            responding.append(ip)

    print '[+] Spotted {} ICMP Echo Requests.'.format(len(responding))