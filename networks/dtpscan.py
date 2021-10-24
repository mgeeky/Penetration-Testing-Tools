#!/usr/bin/python

#
# Simple script showing configuration of the DTP protocol on 
# the switch's port. This reconessaince will be helpful for performing
# VLAN Hopping attacks.
#
# Mariusz Banach / mgeeky, '18
#

import os
import sys
from scapy.all import *

config = {
    'count' : 10,
    'timeout' : 90
}

ciscoConfigMaps = {
    2: '''
        ACCESS/OFF/ACCESS
        Administrative Mode: static access
        Operational Mode: static access
        Administrative Trunking Encapsulation: dot1q
        Operational Trunking Encapsulation: native
        Negotiation of Trunking: Off''',

    3: '''
        ACCESS/DESIRABLE/ACCESS
        Administrative Mode: dynamic desirable
        Operational Mode: static access
        Administrative Trunking Encapsulation: dot1q
        Operational Trunking Encapsulation: native
        Negotiation of Trunking: On''',
    4: '''
        ACCESS/AUTO/ACCESS
        Administrative Mode: dynamic auto
        Operational Mode: static access
        Administrative Trunking Encapsulation: dot1q
        Operational Trunking Encapsulation: native
        Negotiation of Trunking: On''',

    0x81: '''
        TRUNK/ON/TRUNK
        Administrative Mode: trunk
        Operational Mode: trunk
        Administrative Trunking Encapsulation: dot1q
        Operational Trunking Encapsulation: dot1q
        Negotiation of Trunking: On''',
}

def showConfig(stat):
    if stat in ciscoConfigMaps.keys():
        print(ciscoConfigMaps[stat])

def inspectPacket(dtp):
    tlvs = dtp['DTP'].tlvlist

    stat = -1
    for tlv in tlvs:
        if tlv.type == 2:
            # TLV: DTPStatus
            stat = ord(tlv.status)
            break

    print('    ' + '=' * 60)
    if stat == -1:
        print('[!] Something went wrong: Got invalid DTP packet.')
        print('    ' + '=' * 60)
        return False

    elif stat == 2:
        print('[-] DTP disabled, Switchport in Access mode configuration')
        print('[-] VLAN Hopping via Switch Spoofing/trunking IS NOT possible.')
        print('\n\tSWITCH(config-if)# switchport mode access')

    elif stat == 3:
        print('[+] DTP enabled, Switchport in default configuration')
        print('[+] VLAN Hopping via Switch Spoofing/trunking IS POSSIBLE.')
        print('\n\tSWITCH(config-if)# switchport dynamic desirable (or none)')

    elif stat == 4 or stat == 0x84:
        print('[+] DTP enabled, Switchport in Dynamic Auto configuration')
        print('[+] VLAN Hopping via Switch Spoofing/trunking IS POSSIBLE.')
        print('\n\tSWITCH(config-if)# switchport mode dynamic auto')

    elif stat == 0x81:
        print('[+] DTP enabled, Switchport in Trunk configuration')
        print('[+] VLAN Hopping via Switch Spoofing/trunking IS POSSIBLE.')
        print('\n\tSWITCH(config-if)# switchport mode trunk')

    elif stat == 0xa5:
        print('[?] DTP enabled, Switchport in Trunk with 802.1Q encapsulation forced configuration')
        print('[?] VLAN Hopping via Switch Spoofing/trunking may be possible.')
        print('\n\tSWITCH(config-if)# switchport mode trunk 802.1Q')

    elif stat == 0x42:
        print('[?] DTP enabled, Switchport in Trunk with ISL encapsulation forced configuration')
        print('[?] VLAN Hopping via Switch Spoofing/trunking may be possible.')
        print('\n\tSWITCH(config-if)# switchport mode trunk ISL')

    showConfig(stat)
    print('    ' + '=' * 60)

    return True

def packetCallback(pkt):
    print('[>] Packet: ' + pkt.summary())

def main(argv):
    if os.getuid() != 0:
        print('[!] This program must be run as root.')
        return False

    load_contrib('dtp')

    print('[*] Sniffing for DTP frames (Max count: {}, Max timeout: {} seconds)...'.format(
        config['count'], config['timeout']
    ))

    dtps = sniff(
        count = config['count'], 
        filter = 'ether[20:2] == 0x2004',
        timeout = config['timeout'],
        prn = packetCallback,
        stop_filter = lambda x: x.haslayer(DTP)
    )

    if len(dtps) == 0:
        print('[-] It seems like there was no DTP frames transmitted.')
        print('[-] VLAN Hopping may not be possible (unless Switch is in Non-negotiate state):')
        print('\n\tSWITCH(config-if)# switchport nonnegotiate\t/ or / ')
        print('\tSWITCH(config-if)# switchport mode access')
        return False

    print('[*] Got {} DTP frames.\n'.format(
        len(dtps)
    ))
    
    success = False
    for dtp in dtps:
        if dtp.haslayer(DTP):
            if inspectPacket(dtp):
                success = True
                break

    if not success:
        print('[-] Received possibly corrupted DTP frames! General failure.')

    print('')
    return success

if __name__ == '__main__':
    main(sys.argv)
