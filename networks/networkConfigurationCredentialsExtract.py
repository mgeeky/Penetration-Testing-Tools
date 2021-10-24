#!/usr/bin/python

#
# Script intendend to sweep Cisco, Huawei and possibly other network devices 
# configuration files in order to extract plain and cipher passwords out of them.
# Equipped with functionality to decrypt Cisco Type 7 passwords.
#
# Mariusz Banach, mgeeky '18-20
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
        'AAA TACACS+/RADIUS Server Private' : r'server-private \ip key \password',
        'AAA TACACS+ Server Private'        : r'tacacs-server key \password',
        'SNMP Server Community string'      : r'snmp-server community \password',
        'IPSec VPN ISAKMP Pre-Shared Key'   : r'pre-shared-key address \ip key \password'
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
        'Cisco 7 Password'                  : r'\cisco7',
    },
}

config = {
    'verbose' : False,  
    'debug' : False,
    'lines' : 0,
    'format' : 'normal',
    'csv_delimiter' : ';',
    'no_others' : False,
    'filename' : False,
    'nonunique' : False,
    'output' : ''
}

markers = {
    'name' : r'([\w-]+|\"[\w-]+\")',
    'ip' : r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    'domain' : r'(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})',
    'hash' : r'([a-fA-F0-9]{20,})',
    'bcrypt' : r'([\$\w\.\/]+)',
    'password': r'(?:(?:\d\s+)?([^\s]+))',
    'cisco7' : r'\b(?:7 ([0-9a-f]{4,}))|(?:([0-9a-f]{4,}) 7)\b',
    'keystring': r'([a-f0-9]+)',
}

foundCreds = set()

maxTechnologyWidth = 0
maxRegexpWidth = 0

results = []

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

def cisco7Decrypt(data):
    # source: https://github.com/theevilbit/ciscot7
    xlat = [
        0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 
        0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 
        0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 
        0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 
        0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37
    ]

    dp = ''
    regex = re.compile(r'(^[0-9A-Fa-f]{2})([0-9A-Fa-f]+)')
    result = regex.search(data)
    try:
        if result:
            s, e = int(result.group(1)), result.group(2)
            for pos in range(0, len(e), 2):
                magic = int(e[pos] + e[pos+1], 16)
                newchar = ''
                if s <= 50:
                    # xlat length is 51
                    newchar = '%c' % (magic ^ xlat[s])
                    s += 1
                if s == 51: s = 0
                dp += newchar
            return dp
        return ''
    except:
        return ''

def tryToCisco7Decrypt(creds):
    if not len(creds):
        return ''

    decrypted = []
    for m in re.finditer(markers['cisco7'], creds, re.I):
        f = m.group(2) if m.group(2) != None else m.group(1)
        out = cisco7Decrypt(f)
        if out:
            decrypted.append(out)
    
    if len(decrypted):
        return " (decrypted cisco 7: '" + "', '".join(decrypted) + "')"

    return ''

def matchLines(file, lines, technology):
    global foundCreds
    global results

    num = 0

    for rex in regexes[technology]:
        for idx in range(len(lines)):   
            line = lines[idx].strip()

            if not config['nonunique'] and line in foundCreds: 
                continue

            processedRex = processRegex(regexes[technology][rex])
            matched = re.match(processedRex, line, re.I)
            if matched:
                num += 1

                foundCreds.add(line)
                f = [x for x in matched.groups(1) if type(x) == str]
                creds = '", "'.join(f)
                creds += tryToCisco7Decrypt(line)
                
                results.append((
                    file, technology, rex, creds
                ))

                if config['lines'] != 0:
                    Logger._out('\n[+] {}: {}: {}'.format(
                        technology, rex, creds
                    ))

                    if idx - config['lines'] >= 0:
                        for i in range(idx - config['lines'], idx):
                            Logger._out('[{:04}]\t\t{}'.format(i, lines[i]))
                            
                    Logger._out('[{:04}]==>\t{}'.format(idx, line))

                    if idx + 1 + config['lines'] < len(lines):
                        for i in range(idx + 1, idx + config['lines'] + 1):
                            Logger._out('[{:04}]\t\t{}'.format(i, lines[i]))

                Logger.dbg('\tRegex used: [ {} ]'.format(processedRex))
    return num

def processFile(file):
    lines = []

    Logger.info('Processing file: "{}"'.format(file))
    try:
        with open(file, 'r') as f:
            lines = [ line.strip() for line in f.readlines()]
    except Exception as e:
        Logger.err("Parsing file '{}' failed: {}.".format(file, str(e)))
        return 0

    num = 0
    for technology in regexes:
        if technology == 'Others':
            continue

        num0 = matchLines(file, lines, technology)
        num += num0

    if not config['no_others']:
        num0 = matchLines(file, lines, 'Others')
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
    parser.add_argument('-o', '--output', help = 'Output file.')
    parser.add_argument('-H', '--with-filename', action='store_true', help = 'Print file name next to the results')
    parser.add_argument('-R', '--show-nonunique', action='store_true', help = 'Print repeated, non unique credentials found. By default only unique references are returned.')
    parser.add_argument('-C', '--lines', metavar='N', type=int, default=0, help='Display N lines around matched credential if verbose output is enabled.')
    parser.add_argument('-f', '--format', choices=['raw', 'normal', 'tabular', 'csv'], default='normal', help="Specifies output format: 'raw' (only hashes), 'tabular', 'normal', 'csv'. Default: 'normal'")
    parser.add_argument('-N', '--no-others', dest='no_others', action='store_true', help='Don\'t match "Others" category which is false-positives prone.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Display verbose output.')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='Display debug output.')

    if len(argv) < 2:
        parser.print_help()
        return False

    args = parser.parse_args()

    config['verbose'] = args.verbose
    config['debug'] = args.debug
    config['lines'] = args.lines
    config['no_others'] = args.no_others
    config['filename'] = args.with_filename
    config['nonunique'] = args.show_nonunique
    config['output'] = args.output

    if args.format == 'raw':
        config['format'] = 'raw'
    elif args.format == 'tabular':
        config['format'] = 'tabular'
    elif args.format == 'csv':
        config['format'] = 'csv'
    else:
        config['format'] == 'normal'

    return args

def printResults():
    global maxTechnologyWidth
    global maxRegexpWidth
    global results

    # CSV Columns
    cols = ['file', 'technology', 'name', 'hashes']

    if not config['nonunique']:
        results = set(results)

    def _print(file, technology, rex, creds):
        out = ''
        if config['format'] == 'tabular':
            out += '[+] {0: <{width1}} {1:^{width2}}: "{2:}"\n'.format(
                technology, rex, creds,
                width1 = maxTechnologyWidth, width2 = maxRegexpWidth
            )
        elif config['format'] == 'raw':
            credstab = creds.split('", "')
            longest = ''

            for passwd in credstab:
                if len(passwd) > len(longest):
                    longest = passwd

            out += '{}\n'.format(
                passwd
            )
        elif config['format'] == 'csv':
            creds = '"{}"'.format(creds)
            rex = rex.replace(config['csv_delimiter'], ' ')
            out += config['csv_delimiter'].join([file, technology, rex, creds])
            out += '\n'
        else:
            out += '[+] {}: {}: "{}"\n'.format(
                technology, rex, creds
            )
        
        return out

    maxTechnologyWidth = 0
    maxRegexpWidth = 0

    for result in results:
        file, technology, rex, creds = result
        if len(technology) > maxTechnologyWidth:
            maxTechnologyWidth = len(technology)

        if len(regexes[technology][rex]) > maxRegexpWidth:
            maxRegexpWidth = len(regexes[technology][rex])

    maxTechnologyWidth = maxTechnologyWidth + 3
    maxRegexpWidth = maxRegexpWidth + 3

    outputToPrint = ''

    if config['format'] == 'normal' or config['format'] == 'tabular':
        outputToPrint += '\n=== CREDENTIALS FOUND:\n'
    elif config['format'] == 'csv':
        outputToPrint += config['csv_delimiter'].join(cols)
        outputToPrint += '\n'

    resultsPerFile = {}
    otherResultsPerFile = {}
    for result in results:
        file, technology, rex, creds = result
        if technology == 'Others':
            if file not in otherResultsPerFile.keys():
                otherResultsPerFile[file] = []
            otherResultsPerFile[file].append((technology, rex, creds))
        else:
            if file not in resultsPerFile.keys():
                resultsPerFile[file] = []
            resultsPerFile[file].append((technology, rex, creds))

    for file, _results in resultsPerFile.items():
        if config['filename'] and config['format'] in ['raw', 'normal', 'tabular']: 
            outputToPrint += '\nResults from file: "{}"\n'.format(file)
        for result in _results:
            technology, rex, creds = result
            outputToPrint += _print(file, technology, rex, creds)

    if not config['no_others'] and (config['format'] == 'normal' or config['format'] == 'tabular'):
        outputToPrint += '\n\n=== BELOW LINES MAY BE FALSE POSITIVES:\n'

    for file, _results in otherResultsPerFile.items():
        if config['filename'] and config['format'] in ['raw', 'normal', 'tabular']: 
            outputToPrint += '\nResults from file: "{}"\n'.format(file)
        for result in _results:
            technology, rex, creds = result
            outputToPrint += _print(file, technology, rex, creds)

    return outputToPrint

def main(argv):
    Logger._out('''
    :: Network-configuration Credentials extraction script
    Mariusz Banach / mgeeky, '18
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

    out = printResults()

    if config['output']:
        Logger.info("Dumping credentials to the output file: '{}'".format(config['output']))
        with open(config['output'], 'w') as f:
            f.write(out)
    else:
        print(out)

    if config['format'] == 'normal' or config['format'] == 'tabular':
        print('\n[>] Found: {} credentials.'.format(num))

if __name__ == '__main__':
    main(sys.argv)
