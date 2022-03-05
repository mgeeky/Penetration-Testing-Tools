#!/usr/bin/python3
#
# This script polls various online proxy list providers to build a list of currently active
# proxies meeting this script's user input search criterias.
#
# Results of this script could be used to quickly generate Proxy Chains configuration
# to be used by proxychains-ng or Proxifier software.
#
# Author:
#   Mariusz Banach, "22, <mb [at] binary-offensive.com>
#

import time
import os, sys
import re
import string
import requests
import json
import argparse
import urllib
import random
import socket

VERSION = '0.1'

default_proxychains_opts = [
    'remote_dns_subnet 224',
    'tcp_read_time_out 15000',
    'tcp_connect_time_out 8000',
]

config = {
    'quiet' : False,
    'protocol' : ['socks5', 'socks4'],
    'country' : [],
    'last_checked' : 3600,
    'timeout' : 8,
    'chain_len' : 2,
    'verbose' : False,
    'debug' : False,
    'proxychains' : False,
    'proxychains_file' : '',
    'dont_proxy_dns' : False,
    'chain_pick' : 'random',
    'no_quiet' : False,
    'proxychains_args' : default_proxychains_opts,
    'chain_type' : 'strict',
}

headers = {
    'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
}

gimmeProxyURL = 'https://gimmeproxy.com/api/getProxy'
proxydbURL = 'http://proxydb.net/?anonlvl=2&anonlvl=3&anonlvl=4'

def verbose(x):
    if config['quiet']: return
    if config['verbose'] or config['debug']:
        print('[verbose] ' + x)

def dbg(x):
    if config['quiet']: return
    if config['debug']:
        print('[ debug ] ' + x)

def info(x):
    if config['quiet']: return
    print(x)

def gimmeProxy():
    try:
        params = {}

        if len(config['country']) > 0:
            params['country'] = ','.join([x.upper() for x in config['country']])

        if len(config['protocol']) > 0:
            params['protocol'] = ','.join(config['protocol'])

        if config['last_checked'] > 0:
            params['maxCheckPeriod'] = int(config['last_checked'])

        req = requests.get(gimmeProxyURL, params=params, headers=headers)

        out = req.json()

        if 'protocol' in out.keys() and 'ip' in out.keys() and 'port' in out.keys() and 'country' in out.keys():
            verbose(f"Got proxy: {out['protocol']} {out['ip']}:{out['port']}")

            notes = f'country: {out["country"]}'
            return out['protocol'], out['ip'], int(out['port']), notes
        else:
            raise Exception('Non conformant response.')

    except Exception as e:
        if 'Rate limited' in str(e):
            verbose('Cooling down, we got throttled.')
            time.sleep(15)
        
        else:
            info(f'[!] Exception occured while retrieving GimmeProxy result: {e}')

        return '', '', '', ''

def checkProxy(host, port):
    try:
        dbg(f'Checking proxy: {host}:{port}')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(config['timeout'])
        s.connect((host, port))
        s.close()

        dbg(f'Proxy validated.')
        return True
    
    except Exception as e:
        dbg(f'Could not validate proxy {host}:{port} - exception: {e}')
        return False

def generateProxychains(proxies):
    data = '''
#
# proxychains.conf - options
#

'''
    if not config['no_quiet']:
        data += 'quiet_mode\n'
    else:
        data += '#quiet_mode\n'

    if not config['dont_proxy_dns']:
        data += 'proxy_dns\n'
    else:
        data += '#proxy_dns\n'

    data += '\n'

    data += f'{config["chain_pick"]}_chain\n'

    for a in config['proxychains_args']:
        data += a + '\n' 

    data += f'{config["chain_type"]}_chain\n'
    data += f'chain_len = {config["chain_len"]}\n'

    data += '''
#
# Proxies
#
[ProxyList]
'''
    for p in proxies:
        c = ''
        if len(p[3]) > 0:
            c = '# ' + p[3]

        data += f'{p[0]:10} {p[1]:>20} {p[2]:<10} {c}\n'

    return data

def getopts(argv):
    global config
    
    out = '''
        :: RandMyProxy.py
        Acquires random, alive proxies based on input criterias
        Mariusz Banach / mgeeky '22, <mb@binary-offensive.com>
        v{}

'''.format(VERSION)

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options]')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')
    parser.add_argument('-d', '--debug', action='store_true', help='Display debug output.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not display any output.')
    parser.add_argument('-l', '--last-checked', default=600, type=int, help='Number of seconds when that proxy was last checked (if supported). Default: 600.')
    parser.add_argument('-n', '--proxies-num', default=3, type=int, help='Number of proxy servers to find and add to proxy list. Default: 3')
    parser.add_argument('-N', '--chain-len', default=2, type=int, help='Number of proxy servers in chain. Default: 2')
    parser.add_argument('-c', '--country', default=[], action='append', help='Expected proxy server country. Can be multipled.')
    parser.add_argument('-p', '--protocol', default=['socks5'], action='append', help='Expected proxy server protocol. Default: socks5,socks4 . Can be multipled.')

    pc = parser.add_argument_group('Proxychains config')
    pc.add_argument('-P', '--proxychains', action='store_true', help='Generate /etc/proxychains4.conf config file.')
    pc.add_argument('-F', '--proxychains-file', default='/etc/proxychains4.conf', help='Path to proxychains config file. Default: /etc/proxychains4.conf . Use "-" for stdout.')
    pc.add_argument('-D', '--dont-proxy-dns', action='store_true', help='Do not perform DNS lookups over proxy. By default all DNS lookups are made via Proxy.')
    pc.add_argument('-Q', '--no-quiet', action='store_true', help='Do not use quiet mode in Proxychains. By default will make Proxychains quiet.')
    pc.add_argument('-a', '--proxychains-args', default=default_proxychains_opts, action='append', help='Additional proxychains arguments. Can be multipled.')
    pc.add_argument('-r', '--chain-pick', choices=['random', 'round_robin'], default='random', help='How to pick proxies - at random or in round-robin fashion.')
    pc.add_argument('-t', '--chain-type', choices=['strict', 'dynamic'], default='dynamic', help='Proxychains chain type. Available: strict, dynamic. Default: dynamic.')

    args = parser.parse_args()
    config.update(vars(args))

    if not args.quiet:
        sys.stderr.write(out)

    return args

def main(argv):
    args = getopts(argv)

    proxies = []
    hosts = set()
    maxerr = 3
    checkedHosts = {}

    j = 1
    err = 0
    for i in range(config['proxies_num']):
        verbose(f'Looking up proxy #{j}...')

        while True:
            ptype, host, port, notes = gimmeProxy()

            if host == '':
                err += 1

            if host in checkedHosts.keys():
                verbose('That proxy was already checked. Skipping it.')
                checkedHosts[host] += 1

            if len(host) > 0 and host not in hosts:
                checkedHosts[host] = 1
                if checkProxy(host, port):
                    proxies.append((ptype, host, port, notes))
                    hosts.add(host)
                    dbg(f'Added proxy #{j} to chain.')
                    break

            if host in checkedHosts.keys():
                if checkedHosts[host] > maxerr:
                    break
            elif len(host) > 0:
                checkedHosts[host] = 1

        j += 1
        if err > maxerr:
            sys.stderr.write('Could not acquire proxies list. Fatal.')
            return False

    if config['proxychains']:
        data = generateProxychains(proxies)

        if config['proxychains_file'] == '-':
            if not config['quiet']: sys.stderr.write('''
Proxychains configuration:
---------------------------------------------------------------
''')
            print(data)

            if not config['quiet']: sys.stderr.write('---------------------------------------------------------------')

        else:
            with open(config['proxychains_file'], 'w') as f:
                f.write(data)

            info(f"[+] Proxychains file updated: {config['proxychains_file']}")
    else:
        if not config['quiet']: sys.stderr.write('''
Resulting proxy chain:
---------------------------------------------------------------
''')
        for p in proxies:
            c = ''
            if len(p[3]) > 0:
                c = '# ' + p[3]
                
            print(f'{p[0]:10} {p[1]:>20} {p[2]:<10} {c}')

        if not config['quiet']: sys.stderr.write('---------------------------------------------------------------')

    return True

if __name__ == '__main__':
    main(sys.argv)
