#!/usr/bin/python

import sys
import socket
import argparse
import threading

config = {
    'debug': False,
    'verbose': False,
    'timeout' : 5.0,
}

# =========================================================
# CUSTOM ANALYSIS, FUZZING, INTERCEPTION ROUTINES.

def requestHandler(buff):
    '''
    Modify any requests destined for the REMOTE host service.
    '''    
    return buff


def responseHandler(buff):
    '''
    Modify any responses destined for the LOCAL host service.
    '''
    return buff

# =========================================================

class Logger:
    @staticmethod
    def _out(x): 
        if config['debug'] or config['verbose']: 
            sys.stderr.write(x + '\n')

    @staticmethod
    def dbg(x):
        if config['debug']: 
            sys.stderr.write('[dbg] ' + x + '\n')

    @staticmethod
    def out(x): 
        Logger._out('[.] ' + x)

    @staticmethod
    def info(x):
        Logger._out('[?] ' + x)

    @staticmethod
    def err(x, fatal = False): 
        Logger._out('[!] ' + x)
        if fatal: sys.exit(-1)

    @staticmethod
    def fail(x, fatal = False):
        Logger._out('[-] ' + x)
        if fatal: sys.exit(-1)

    @staticmethod
    def ok(x):  
        Logger._out('[+] ' + x)

def hexdump(src, length = 16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    num = len(src)
    
    for i in range(0, num, length):
        s = src[i:i+length]
        hexa = b' '.join(['%0*X' % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7f else b'.' for x in s])
        
        result.append(b'%04x  |  %-*s  |  %s' % (i, length * (digits + 1), hexa, text))
        
    return str(b'\n'.join(result))

def recvFrom(sock):
    '''
    Simple recvAll based on timeout exception.
    '''
    buff = ''
    sock.settimeout(config['timeout'])
    
    try:
        while True:
            data = sock.recv(4096)
            if not data: break
            
            buff += data
    except:
        pass
    
    return buff

def proxyHandler(clientSock, remoteHost, remotePort, recvFirst):
    Logger.dbg('Connecting to REMOTE service: {}:{}'.format(remoteHost, remotePort))
    
    try:
        remoteSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remoteSock.settimeout(config['timeout'])
        remoteSock.connect((remoteHost, remotePort))
        
        Logger.dbg('Connected.')
        
    except Exception as e:
        Logger.err('TCP Proxy was unable to connect to REMOTE service: {}:{}'.format(
            remoteHost, remotePort), fatal = True
        )
        
    if recvFirst:
        remoteBuff = recvFrom(remoteSock)
        Logger.info('[<==] Received {} bytes from REMOTE service.'.format(len(remoteBuff)))
        Logger.dbg('Remote service Recv buff BEFORE responseHandler:\n' + hexdump(remoteBuff))

        remoteBuffOrig = remoteBuff
        remoteBuff = responseHandler(remoteBuff)
        
        if remoteBuff != remoteBuffOrig:
            Logger.dbg('Buffer to be sent to LOCAL service modified. Lengths: {} -> {}'.format(
                len(remoteBuffOrig, remoteBuff)))
            Logger.dbg('Remote service Recv buff AFTER responseHandler:\n' + hexdump(remoteBuff))
        
        if len(remoteBuff):
            Logger.info('[<==] Sending {} bytes to LOCAL service.'.format(len(remoteBuff)))
            clientSock.send(remoteBuff)
            
    # Send & Receive / Proxy loop
    while True:
        
        # LOCAL part
        localBuff = recvFrom(clientSock)
        if len(localBuff):
            Logger.info('[==>] Received {} bytes from LOCAL service.'.format(len(localBuff)))
            Logger.dbg('Local service Recv buff:\n' + hexdump(localBuff))
            
            localBuffOrig = localBuff
            localBuff = requestHandler(localBuff)
            
            if localBuff != localBuffOrig:
                Logger.dbg('Buffer to be sent to REMOTE service modified. Lengths: {} -> {}'.format(
                    len(localBuffOrig, localBuff)))
                Logger.dbg('Local service Recv buff AFTER requestHandler:\n' + hexdump(localBuff))            
            
            remoteSock.send(localBuff)
            Logger.info('[==>] Sent to REMOTE service.')
        
        # REMOTE part
        remoteBuff = recvFrom(remoteSock)
        if len(remoteBuff):
            Logger.info('[<==] Received {} bytes from REMOTE service.'.format(len(remoteBuff)))
            Logger.dbg('Remote service Recv buff:\n' + hexdump(remoteBuff))
        
            remoteBuffOrig = remoteBuff
            remoteBuff = responseHandler(remoteBuff)
            
            if remoteBuff != remoteBuffOrig:
                Logger.dbg('Buffer to be sent to LOCAL service modified. Lengths: {} -> {}'.format(
                    len(remoteBuffOrig, remoteBuff)))
                Logger.dbg('Remote service Recv buff AFTER responseHandler:\n' + hexdump(remoteBuff))
                
            clientSock.send(remoteBuff)
            Logger.info('[<==] Sent to LOCAL service.')  
            
        if not len(localBuff) or not len(remoteBuff):
            clientSock.close()
            remoteSock.close()
            
            Logger.info('No more data. Closing connections.')
            break

def serverLoop(localHost, localPort, remoteHost, remotePort, receiveFirst):
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        serv.bind((localHost, localPort))
        Logger.ok('TCP Proxy listening on: {}:{}'.format(localHost, localPort))
        
        serv.listen(5)
    
    except Exception as e:
        Logger.err('TCP Proxy server was unable to bound to {}:{}'.format(localHost, localPort), fatal = True)
       
    while True:
        clientSock, addr = serv.accept()
        Logger.info('[==>] Received incoming connection from: {}:{}'.format(addr[0], addr[1]))
        proxyThread = threading.Thread(
            target = proxyHandler, 
            args = (
                clientSock, 
                remoteHost, 
                remotePort, 
                receiveFirst
            )
        )
        
        proxyThread.start()

def processOpts(argv):   
    global config
    
    usageStr = '''
    tcpproxy.py [options] <LOCAL> <REMOTE>
    
Example:
    tcpproxy.py 127.0.0.1:9000 192.168.56.102:9000
    '''
    
    parser = argparse.ArgumentParser(prog = argv[0], usage = usageStr)
    parser.add_argument('localhost', metavar='LOCAL', type=str, 
                        help = 'Local service to proxy (host:port)')
    parser.add_argument('remotehost', metavar='REMOTE', type=str, 
                        help = 'Remote service to proxy to (host:port)') 
    parser.add_argument('-r', '--recvfirst', dest='recvfirst', action='store_true', default = False,
                        help='Make the proxy first receive something, than respond.') 
    parser.add_argument('-t', '--timeout', metavar='timeout', dest='timeout', default = config['timeout'],
                        help='Specifies service connect & I/O timeout. Default: {}.'.format(config['timeout']))    
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='Show verbose output.')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        help='Show more verbose, debugging output.')    
    
    if len(sys.argv[1:]) < 2:
        parser.print_help()
        sys.exit(0)
        
    args = parser.parse_args()
    if args.debug: 
        config['debug'] = args.debug
    if args.verbose: 
        config['verbose'] = args.verbose
    config['timeout'] = float(args.timeout)
    Logger.dbg('Timeout set to: {} seconds.'.format(args.timeout))
        
    return (args.localhost, args.remotehost, args.recvfirst)
    
def main():
    local, remote, recvfirst = processOpts(sys.argv)
    localHost, localPort = local.split(':')
    remoteHost, remotePort = remote.split(':')
    
    try:
        localPort = int(localPort)
        if localPort < 0 or localPort > 65535:
            raise ValueError
    except ValueError:
        Logger.err('Invalid LOCAL port specified.', fatal = True)
        
    try:
        remotePort = int(remotePort)
        if remotePort < 0 or remotePort > 65535:
            raise ValueError
    except ValueError:
        Logger.err('Invalid LOCAL port specified.', fatal = True)    
    
    Logger.info('Proxying: {}:{} => {}:{}'.format(
        localHost, localPort, remoteHost, remotePort
    ))
    
    serverLoop(localHost, localPort, remoteHost, remotePort, recvfirst)

if __name__ == '__main__':
    main()
