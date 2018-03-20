#!/usr/bin/python

#
# Script intendend to sweep Cisco, Huawei and possibly other network devices 
# configuration files in order to extract plain and cipher passwords out of them.
#
# Mariusz B., mgeeky '18
#

import re
import os
import sys
import argparse

#
# In order to extend capabilities of this script, one can add custom entries
# to the below dictionary. Contents are:
#   regexes = {
#       'Technology' : {
#           'Pattern Name' : r'pattern',
#       }
#   }
#
regexes = {
    'Cisco' : {
        'Enable secret'                     : r'enable secret \d+ \bcrypt',
        'Privileged command level password' : r'password \password',
        'Enable password'                   : r'enable password \password',
        'Enable password(2)'                : r'enable password level \d+ \password',
        'Username/password'                 : r'username \name .*(?:password|secret \d) \password',
        'HSRP Authentication string'        : r'standby \d+ authentication \password',
        'HSRP Authentication Text'          : r'authentication text \password',
        'HSRP Authentication MD5 key-string': r'standby \d+ authentication md5 key-string \keystring',
        'OSPF Authentication string'        : r'ip ospf authentication-key \password',
        'OSPF Authentication MD5 string'    : r'ip ospf message-digest-key \d+ md5 \password',
        'EIGRP Key-string'                  : r'key-string \password',
        'BGP Neighbor Authentication'       : r'neighbor (\ip) password 7 \hash',
        'AAA RADIUS Server Auth-Key'        : r'server-private \ip auth-port \d+ acct-port \d+ key \d+ \hash',
        'NTP Authentication MD5 Key'        : r'ntp authentication-key \d+ md5 \password \d',
        'TACACS-Server'                     : r'tacacs-server host \ip key \d \hash',
        'RADIUS Server Key'                 : r'key 7 \hash',
        'SNMP-Server User/Password'         : r'snmp-server user \name [\w-]+ auth md5 0x\hash priv 0x\hash localizedkey',
        'FTP Server Username'               : r'ip ftp username \name',
        'FTP Server Password'               : r'ip ftp password \password',
        'ISAKMP Pre-Shared Key'             : r'crypto isakmp key \password(?: address \ip)?',
        'SNMP-Server User Auth & Encr keys' : r'snmp-server user \name .* encrypted auth md5 ([0-9a-f\:]+) priv aes \d+ ([0-9a-f\:]+)',
        'PPP PAP Sent Username & Password'  : r'ppp pap sent-username \name password \password',
    },

    'Cisco ASA' : {
        'Username and Password'             : r'username \name .*password \password',
        'LDAP Login password'               : r'ldap-login-password \password',
        'SNMP-Server authentication'        : r'snmp-server user \name snmp-read-only-group v\d engineID \hash encrypted auth md5 ([0-9a-fA-F\:]+) priv aes 256 ([0-9a-fA-F\:]+)',
    },

    'Huawei' : {
        'VTY User interface'                : r'set authentication password cipher \password',
        'Local User'                        : r'local-user \name password (?:cipher|irreversible-cipher) \password',
        'NTP Authentication'                : r'ntp-service authentication-keyid \d+ authentication-mode (md5|hmac-sha256) (?:cipher)?\s*\password',
        'RADIUS Server Shared-Key'          : r'radius-server shared-key cipher \password',
        'RADIUS Server Authorization'       : r'radius-server authorization \ip shared-key cipher \password',
        'TACACS-Server Shared-Key Cipher'   : r'hwtacacs-server shared-key cipher \password',
        'SNMP-Agent Authentication MD5'     : r'snmp-agent [\w-]+ v\d \name authentication-mode md5 \password',
        'SNMP-Agent Authentication AES'     : r'snmp-agent [\w-]+ v\d \name privacy-mode aes128 \password',
    },

    'Checkpoint gateway' : {
        'SNMP User'                         : r'add snmp usm user \name security-level \w+ auth-pass-phrase-hashed \hash privacy-pass-phrase-hashed \hash privacy-protocol DES',
        'Expert Password Hash'              : r'set expert-password-hash \bcrypt',
        'TACACS Authentication Key'         : r'add aaa tacacs-servers priority \d+ server \ip key \password',
        'User password-hash'                : r'set user \name password-hash \bcrypt',
    },

    'F5 BIG-IP' : {
        'Username and password'             : r'manage user table create \name -pw \password',
        'Configuration Sync Password'       : r'redundancy config-sync sync-session-password set \password',
    },

    'PaloAlto Proxy' : {
        'Active Directory Auth password'    : r'<bind-password>([^<]+)</bind-password>',
        'NTLM Password'                     : r'<ntlm-password>([^<]+)</ntlm-password>',
        'Agent User key'                    : r'<agent-user-override-key>([^<]+)</agent-user-override-key>',
        'User Password Hash'                : r'<phash>([^<]+)</phash>',
    },

    'Others' : {
        'Other uncategorized password'      : r'.* password \password.*',
        'Other uncategorized XML password'  : r'password>([^<]+)<',
        'Other uncategorized authentication string' : r'.* authentication \password.*',
        'Other hash-key related'            : r'.* key \hash',
    },
}

config = {
    'verbose' : False,  
    'debug' : False,
    'lines' : 0,
    'output' : 'normal',
    'csv_delimiter' : ';',
    'no_others' : False,
}

markers = {
    'name' : r'([\w-]+|\"[\w-]+\")',
    'ip' : r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    'domain' : r'(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})',
    'hash' : r'([a-fA-F0-9]{20,})',
    'bcrypt' : r'([\$\w\.\/]+)',
    'password': r'(?:\d\s+)?([^\s]+)',
    'keystring': r'([a-f0-9]+)',
}

foundCreds = set()

maxTechnologyWidth = 0
maxRegexpWidth = 0

results = set()

class Logger:
    @staticmethod
    def _out(x): 
        if config['debug'] or config['verbose']: 
            sys.stdout.write(x + '\n')

    @staticmethod
    def dbg(x):
        if config['debug']: 
            sys.stdout.write('[dbg] ' + x + '\n')

    @staticmethod
    def out(x): 
        Logger._out('[.] ' + x)
    
    @staticmethod
    def info(x):
        Logger._out('[?] ' + x)
    
    @staticmethod
    def err(x): 
        Logger._out('[!] ' + x)
    
    @staticmethod
    def fail(x):
        Logger._out('[-] ' + x)
    
    @staticmethod
    def ok(x):  
        Logger._out('[+] ' + x)

def processRegex(inputRegex):
    for marker in markers:
        if '\\' + marker in inputRegex:
            inputRegex = inputRegex.replace('\\' + marker, markers[marker])

    inputRegex = '^\\s*{}\\s*.*$'.format(inputRegex)
    return inputRegex

def matchLines(lines, technology):
    global foundCreds
    global results

    num = 0

    for rex in regexes[technology]:
        for idx in range(len(lines)):   
            line = lines[idx].strip()

            if line in foundCreds: 
                continue

            processedRex = processRegex(regexes[technology][rex])
            matched = re.match(processedRex, line, re.I)
            if matched:
                num += 1

                foundCreds.add(line)
                creds = '", "'.join(matched.groups(1))
                
                results.add((
                    technology, rex, creds
                ))

                Logger._out('[+] {}: {}: {}'.format(
                    technology, rex, creds
                ))

                if idx - config['lines'] >= 0:
                    for i in range(idx - config['lines'], idx):
                        Logger._out('[{:04}]\t\t{}'.format(i, lines[i]))
                        
                if config['lines'] != 0:
                    Logger._out('[{:04}]==>\t{}'.format(idx, line))
                else:
                    Logger._out('[{:04}]\t\t{}'.format(idx, line))

                if idx + 1 + config['lines'] < len(lines):
                    for i in range(idx + 1, idx + config['lines'] + 1):
                        Logger._out('[{:04}]\t\t{}'.format(i, lines[i]))

                Logger.dbg('\tRegex used: [ {} ]'.format(processedRex))
    return num

def processFile(file):
    lines = []

    Logger.info('Processing file: "{}"'.format(file))
    with open(file, 'r') as f:
        lines = [ line.strip() for line in f.readlines()]

    num = 0
    for technology in regexes:
        if technology == 'Others':
            continue

        num0 = matchLines(lines, technology)
        num += num0

    if not config['no_others']:
        num0 = matchLines(lines, 'Others')
        if num0 == 0:
            print('<none>')
        num += num0

    return num

def processDir(dirname):
    num = 0
    for filename in os.listdir(dirname):
        newfilename = os.path.join(dirname, filename)
        if os.path.isdir(newfilename):
            num += processDir(newfilename)
        elif os.path.isfile(newfilename):
            num += processFile(newfilename)
    return num

def parseOptions(argv):
    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <file>')
    parser.add_argument('file', metavar='<file>', type=str, help='Config file or directory to process.')
    parser.add_argument('-C', '--lines', metavar='N', type=int, default=0, help='Display N lines around matched credential if verbose output is enabled.')
    parser.add_argument('-f', '--format', choices=['raw', 'normal', 'tabular', 'csv'], default='normal', help="Specifies output format: 'raw' (only hashes), 'tabular', 'normal', 'csv'. Default: 'normal'")
    parser.add_argument('-N', '--no-others', dest='no_others', action='store_true', help='Don\'t match "Others" category which is false-positives prone.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')
    parser.add_argument('-d', '--debug', action='store_true', help='Display debug output.')

    if len(argv) < 2:
        parser.print_help()
        return False

    args = parser.parse_args()

    config['verbose'] = args.verbose
    config['debug'] = args.debug
    config['lines'] = args.lines
    config['no_others'] = args.no_others

    if args.format == 'raw':
        config['output'] = 'raw'
    elif args.format == 'tabular':
        config['output'] = 'tabular'
    elif args.format == 'csv':
        config['output'] = 'csv'
    else:
        config['output'] == 'normal'

    return args

def printResults():
    global maxTechnologyWidth
    global maxRegexpWidth

    # CSV Columns
    cols = ['technology', 'name', 'hashes']

    def _print(technology, rex, creds):
        if config['output'] == 'tabular':
            print('[+] {0: <{width1}} {1:^{width2}}: "{2:}"'.format(
                technology, rex, creds,
                width1 = maxTechnologyWidth, width2 = maxRegexpWidth
            ))
        elif config['output'] == 'raw':
            credstab = creds.split('", "')
            longest = ''

            for passwd in credstab:
                if len(passwd) > len(longest):
                    longest = passwd

            print('{}'.format(
                passwd
            ))
        elif config['output'] == 'csv':
            creds = '"{}"'.format(creds)
            rex = rex.replace(config['csv_delimiter'], ' ')
            #creds = creds.replace(config['csv_delimiter'], ' ')
            print(config['csv_delimiter'].join([technology, rex, creds]))
        else:
            print('[+] {}: {}: "{}"'.format(
                technology, rex, creds
            ))

    maxTechnologyWidth = 0
    maxRegexpWidth = 0

    for result in results:
        technology, rex, creds = result
        if len(technology) > maxTechnologyWidth:
            maxTechnologyWidth = len(technology)

        if len(regexes[technology][rex]) > maxRegexpWidth:
            maxRegexpWidth = len(regexes[technology][rex])

    maxTechnologyWidth = maxTechnologyWidth + 3
    maxRegexpWidth = maxRegexpWidth + 3

    if config['output'] == 'normal' or config['output'] == 'tabular':
        print('\n=== CREDENTIALS FOUND:')
    elif config['output'] == 'csv':
        print(config['csv_delimiter'].join(cols))

    for result in results:
        technology, rex, creds = result
        if technology == 'Others': continue
        _print(technology, rex, creds)

    if not config['no_others'] and (config['output'] == 'normal' or config['output'] == 'tabular'):
        print('\n=== BELOW LINES MAY BE FALSE POSITIVES:')

    for result in results:
        technology, rex, creds = result
        if technology != 'Others': continue
        _print(technology, rex, creds)

def main(argv):
    Logger._out('''
    :: Network-configuration Credentials extraction script
    Mariusz B. / mgeeky, '18
''')
    opts = parseOptions(argv)
    if not opts:
        Logger.err('Options parsing failed.')
        return False

    count = 0
    for technology in regexes:
        count += len(regexes[technology])

    Logger.info('Capable of matching: {} patterns containing credentials.'.format(count))

    num = 0
    if os.path.isfile(opts.file):
        num = processFile(opts.file)
    elif os.path.isdir(opts.file):
        num = processDir(opts.file)
    else:
        Logger.err('Please provide either file or directory on input.')
        return False

    printResults()

    if config['output'] == 'normal' or config['output'] == 'tabular':
        print('\n[>] Found: {} credentials.'.format(num))

if __name__ == '__main__':
    main(sys.argv)
