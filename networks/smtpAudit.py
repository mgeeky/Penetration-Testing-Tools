#!/usr/bin/python3
#
#   SMTP Server configuration black-box testing/audit tool, capable of auditing
# SPF/Accepted Domains, DKIM, DMARC, SSL/TLS, SMTP services, banner, Authentication (AUTH, X-EXPS)
# user enumerations (VRFY, EXPN, RCPT TO), and others.
#
# Currently supported tests:
#   01) 'spf'                           - SPF DNS record test
#           - 'spf-version'             - Checks whether SPF record version is valid
#           - 'all-mechanism-usage'     - Checks whether 'all' mechanism is used correctly
#           - 'allowed-hosts-list'      - Checks whether there are not too many allowed hosts
#   02) 'dkim'                          - DKIM DNS record test
#           - 'public-key-length'       - Tests whether DKIM Public Key is at least 1024 bits long
#   03) 'dmarc'                         - DMARC DNS record test
#           - 'dmarc-version'           - Checks whether DMARC record version is valid
#           - 'policy-rejects-by-default' - Checks whether DMARC uses reject policy
#           - 'number-of-messages-filtered' - Checks whether there are at least 20% messages filtered.
#   04) 'banner-contents'               - SMTP Banner sensitive informations leak test
#           - 'not-contains-version'    - Contains version information
#           - 'not-contains-prohibited-words'- Contains software/OS/or other prohibited name
#           - 'is-not-long-or-complex'  - Seems to be long and/or complex
#           - 'contains-hostname'       - Checks whether SMTP banner contains valid hostname
#   05) 'open-relay'                    - Open-Relay misconfiguration test
#           - 'internal-internal'
#           - 'internal-external'
#           - 'external-internal'
#           - 'external-external'
#           - And about 19 other variants
#                                       - (the above is very effective against Postfix)
#   06) 'vrfy'                          - VRFY user enumeration vulnerability test
#   07) 'expn'                          - EXPN user enumeration vulnerability test
#   08) 'rcpt-to'                       - RCPT TO user enumeration vulnerability test
#   09) 'secure-ciphers'                - SSL/TLS ciphers security weak configuration
#   10) 'starttls-offering'             - STARTTLS offering (opportunistic) weak configuration
#   11) 'auth-over-ssl'                 - STARTTLS before AUTH/X-EXPS enforcement weak configuration
#   12) 'auth-methods-offered'          - Test against unsecure AUTH/X-EXPS PLAIN/LOGIN methods.
#   13) 'tls-key-len'                   - Checks private key length of negotiated or offered SSL/TLS cipher suites.
#   14) 'spf-validation'                - Checks whether SMTP Server has been configured to validate sender's SPF 
#                                         or if it's Microsoft Exchange - that is uses Accepted Domains
#
# Tests obtain results in tri-state boolean, acordingly:
#   - 'secure'  - The test has succeeded and proved GOOD and SECURE configuration.
#   - 'unsecure'- The test has succeeded and proved BAD and UNSECURE configuration.
#   - 'unknown' - The test has failed and did not prove anything.
#
# ATTACKS offered (--attack option):
#   Currently the tool offers functionality to lift up user emails enumeration, by the use of 
#   RCPT TO, MAIL FROM and VRFY methods. 
#
# Requirements:
#   - Python 3.5+
#   - dnspython
#
# TODO:
#   - refactor all the code cause it's a mess at the moment
#   - modularize the code
#   - add support for Outlook's OWA, AutoDiscover, MAPI-over-HTTP, Exchange ActiveSync (EAC)
#   - add support for NTLM/Kerberos (GSSAPI) authentication when used from Domain-joined Windows box
#   - BUG: if smtpAudit.py connects with SMTP over non-encrypted channel (ssl: False) it should be alerted as 'unsecure', it is not atm
#   - test it more thoroughly against various SMTP setups and configurations
#   - fix the issue with hanged jobs doing DKIM lookup when they reach 99%
#   - introduce general program timeout
#   - improve output informations/messages, explanations
#   - implement options parsing, files passing, verbosity levels, etc
#   - add more options specifying various parameters, thresholds
#   - research other potential tests to implement
#   - add test for 'reject_multi_recipient_bounce' a.k.a. multi RCPT TO commands
#   - add more options and improve code for penetration-testing oriented usage (active attacks)
#
# Tested against:
#   - postfix 3.x
#   - Microsoft Exchange Server 2013
#
# Author:
#   Mariusz Banach / mgeeky, '17-19, 
#   <mb@binary-offensive.com>
#

import re
import sys
import ssl
import time
import json
import math
import base64
import string
import socket
import pprint
import random
import inspect
import smtplib
import argparse
import datetime
import threading
import multiprocessing
from collections import Counter

try:
    from dns import name, resolver, exception
except ImportError:
    print('[!] Module "dnspython" not installed. Try: python3 -m pip install dnspython')
    sys.exit(-1)

if float(sys.version[:3]) < 3.5:
    print('[!] This program must be run with Python 3.5+')
    sys.exit(-1)


#
# ===================================================
# GLOBAL PROGRAM CONFIGURATION
#

VERSION = '0.7.7'

config = {
    # Enable script's output other than tests results.
    'verbose'   : False,

    # Turn on severe debugging facilities
    'debug'     : False,
    'smtp_debug': False,

    # Connection timeout threshold
    'timeout'   : 5.0,

    # Delay between consequent requests and connections.
    'delay'     : 2.0,

    # During the work of the program - the SMTP server will receive many of our incoming
    # connections. In such situation, the server may block our new connections due to 
    # exceeding conns limit/rate (like it does Postfix/anvil=count). Therefore it is crucial
    # to set up long enough interconnection-delay that will take of as soon as server 
    # responds with: "421 Too many connections". For most situations - 60 seconds will do fine.
    'too_many_connections_delay' : 60,

    # Perform full-blown, long-time taking DNS records enumeration (for SPF, DKIM, DMARC)
    #   Accepted values:
    #       - 'always'
    #       - 'on-ip' - do full enumeration only when given with server's IP address
    #       - 'never'
    'dns_full' : 'on-ip',

    # Specifies whether to do full, long-time taking DKIM selectors review.
    'dkim_full_enumeration' : True,

    # External domain used in Open-Relay and other tests
    'smtp_external_domain': 'gmail.com',

    # Pretend to be the following client host:
    'pretend_client_hostname': 'smtp.gmail.com',

    # Specifies whether to show results JSON unfolded (nested) or only when needed
    'always_unfolded_results': False,

    # Num of enumeration tries until test is considered completed (whether it succeeds or not).
    # Value -1 denotes to go with full spectrum of the test.
    'max_enumerations' : -1,

    # Use threading - may cause some issues with responsiveness, or cause program to hang.
    'threads' : True,

    # Uncommon words to have in DKIM selectors permutations list
    'uncommon_words' : (),

    # DO NOT CHANGE THIS ONE.
    'tests_to_carry' : 'all',
    'tests_to_skip' : '',

    # Maximum number of parallel process in DKIM enumeration test
    'parallel_processes' : 10,

    # When DNS resolver becomes busy handling thousands of DKIM queries, 
    # we can delay asking for more selectors iteratively.
    'delay_dkim_queries' : True,

    # Output format. Possible values: json, text
    'format' : 'text',

    # Colorize output
    'colors': True,

    # Attack mode 
    'attack': False,

    # Minimal key length to consider it secure
    'key_len' : 2048,

    # Maximum hosts in SPF considered secure:
    'spf_maximum_hosts' : 32,
}


#
# ===================================================
# PROGRAM IMPLEMENTATION
#

class colors:
    '''Colors class:
    reset all colors with colors.reset
    two subclasses fg for foreground and bg for background.
    use as colors.subclass.colorname.
    i.e. colors.fg.red or colors.bg.green
    also, the generic bold, disable, underline, reverse, strikethrough,
    and invisible work with the main class
    i.e. colors.bold
    '''
    reset = '\033[0m'
    bold = '\033[01m'
    disable = '\033[02m'
    underline = '\033[04m'
    reverse = '\033[07m'
    strikethrough = '\033[09m'
    invisible = '\033[08m'

    class fg:
        black = '\033[30m'
        red = '\033[31m'
        green = '\033[32m'
        orange = '\033[33m'
        blue = '\033[34m'
        purple = '\033[35m'
        cyan = '\033[36m'
        lightgrey = '\033[37m'
        darkgrey = '\033[90m'
        lightred = '\033[91m'
        lightgreen = '\033[92m'
        yellow = '\033[93m'
        lightblue = '\033[94m'
        pink = '\033[95m'
        lightcyan = '\033[96m'

    class bg:
        black = '\033[40m'
        red = '\033[41m'
        green = '\033[42m'
        orange = '\033[43m'
        blue = '\033[44m'
        purple = '\033[45m'
        cyan = '\033[46m'
        lightgrey = '\033[47m'

#
# Output routines.
#
def _out(x, toOutLine = False, col = colors.reset): 
    if config['colors']:
        text = '{}{}{}\n'.format(
            col, x, colors.reset
        )
    else:
        text = x + '\n'

    if config['debug'] or config['verbose']: 
        if config['debug']:
            caller = (inspect.getouterframes(inspect.currentframe(), 2))[2][3]
            if x.startswith('['):
                x = x[:4] + '  ' + caller + '(): ' + x[4:]
        sys.stderr.write(text)

    elif config['format'] == 'text' and \
        (toOutLine or 'SECURE: ' in x or 'UNKNOWN: ' in x): 
        if config['attack']:
            sys.stderr.write(text)
        else:
            sys.stdout.write(text)

def dbg(x):
    if config['debug']: 
        caller2 = (inspect.getouterframes(inspect.currentframe(), 2))[1][3]
        caller1 = (inspect.getouterframes(inspect.currentframe(), 2))[2][3]
        caller = '{}() -> {}'.format(caller1, caller2)
        text = x
        if config['colors']: text = '{}{}{}'.format(colors.fg.lightblue, x, colors.reset)
        sys.stderr.write('[dbg] ' + caller + '(): ' + text + '\n')

def out(x, toOutLine = False): _out('[.] ' + x, toOutLine)
def info(x, toOutLine = False):_out('[?] ' + x, toOutLine, colors.fg.yellow)
def err(x, toOutLine = False): _out('[!] ' + x, toOutLine, colors.bg.red + colors.fg.black)
def fail(x, toOutLine = False):_out('[-] ' + x, toOutLine, colors.fg.red + colors.bold)
def ok(x, toOutLine = False):  _out('[+] ' + x, toOutLine, colors.fg.green + colors.bold)


class BannerParser:
    softwareWeight = 3
    osWeight = 2

    # MTAs
    prohibitedSoftwareWords = (
        'Exim',
        'Postfix',
        'Maildrop',
        'Cyrus',
        'Sendmail',
        'Exchange',
        'Lotus Domino',
    )

    prohibitedOSWords = (
        'Windows',
        'Linux',
        'Debian',
        'Fedora',
        'Unix',
        '/GNU)',
        'SuSE',
        'Mandriva',
        'Centos',
        'Gentoo',
        'Red Hat',
        'Microsoft(R) Windows(R)',
    )

    # Certain words will have greater weight since they are more important to hide in banner.
    # Every word must be in it's own list.
    prohibitedWords = prohibitedSoftwareWords + prohibitedOSWords + (
        'Microsoft ESMTP',
        'MAIL service ready at ',
        'Version:',
        'qmail',
        'Ver.',
        '(v.',
        'build:',
    )

    wellKnownDefaultBanners = {
        'Microsoft Exchange' : 'Microsoft ESMTP MAIL service ready at ',
        'IBM Lotus Domino' : 'ESMTP Service (Lotus Domino ',
    }

    # Statistical banner's length characteristics
    lengthCharacteristics = {
        'mean': 66.08,
        'median': 58.5,
        'std.dev': 27.27
    }

    # Reduced entropy statistical characteristics after removing potential timestamp
    # (as being added by e.g. Exim and Exchange)
    reducedEntropyCharacteristics = {
        'mean': 3.171583046,
        'median': 3.203097614,
        'std.dev': 0.191227689
    }

    weights = {
        'prohibitedWord': 1,
        'versionFound': 2,
        'versionNearProhibitedWord': 3,
    }

    # Max penalty score to consider banner unsecure.
    maxPenaltyScore = 4.0

    localHostnameRegex = r'(?:[0-9]{3}\s)?([\w\-\.]+).*'

    def __init__(self):
        self.results = {
            'not-contains-version' : True,
            'not-contains-prohibited-words' : True,
            'is-not-long-or-complex' : True,
            'contains-hostname' : False,
        }

    @staticmethod
    def entropy(data, unit='natural'):
        '''
        Source: https://stackoverflow.com/a/37890790
        '''
        base = {
            'shannon' : 2.,
            'natural' : math.exp(1),
            'hartley' : 10.
        }

        if len(data) <= 1:
            return 0

        counts = Counter()
        for d in data:
            counts[d] += 1

        probs = [float(c) / len(data) for c in counts.values()]
        probs = [p for p in probs if p > 0.]

        ent = 0
        for p in probs:
            if p > 0.:
                ent -= p * math.log(p, base[unit])

        return ent

    @staticmethod
    def removeTimestamp(banner):
        rex = r'\w{3}, \d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2}(?: .\d{4})?'
        return re.sub(rex, '', banner)

    def parseBanner(self, banner):
        if not banner:
            if config['always_unfolded_results']:
                return dict.fromkeys(self.results, None)
            else:
                return None

        penalty = 0
        versionFound = ''

        for service, wellKnownBanner in BannerParser.wellKnownDefaultBanners.items():
            if wellKnownBanner.lower() in banner.lower():
                fail('UNSECURE: Default banner found for {}: "{}"'.format(
                    service, banner
                ))
            return False

        penalty += self.analyseBannerEntropy(banner)
        penalty += self.checkForProhibitedWordsAndVersion(banner)
        penalty += self.checkHostnameInBanner(banner)

        ret = (penalty < BannerParser.maxPenaltyScore)
        if not ret:
            fail('UNSECURE: Banner considered revealing sensitive informations (penalty: {}/{})!'.format(
                penalty, BannerParser.maxPenaltyScore
            ))
            _out('\tBanner: ("{}")'.format(banner), toOutLine = True)
            
            return self.results
        else:
            ok('SECURE: Banner was not found leaking anything. (penalty: {}/{})'.format(
                penalty, BannerParser.maxPenaltyScore
            ))
            _out('\tBanner: ("{}")'.format(banner), toOutLine = True)
            
            if all(self.results.values()) and not config['always_unfolded_results']:
                return True
            else:
                return self.results

    def analyseBannerEntropy(self, banner):
        penalty = 0
        reducedBanner = BannerParser.removeTimestamp(banner)
        bannerEntropy = BannerParser.entropy(reducedBanner)

        dbg('Analysing banner: "{}"'.format(banner))
        dbg('Length: {}, reduced banner Entropy: {:.6f}'.format(len(banner), bannerEntropy))

        if len(reducedBanner) > (BannerParser.lengthCharacteristics['mean'] \
            + 1 * BannerParser.lengthCharacteristics['std.dev']):
            info('Warning: Banner seems to be very long. Consider shortening it.', toOutLine = True)
            self.results['is-not-long-or-complex'] = False
            penalty += 1

        if bannerEntropy > (BannerParser.reducedEntropyCharacteristics['mean'] \
            + 1 * BannerParser.reducedEntropyCharacteristics['std.dev']):
            info('Warning: Banner seems to be complex in terms of entropy.'
                    ' Consider generalising it.', toOutLine = True)
            self.results['is-not-long-or-complex'] = False
            penalty += 1

        return penalty

    def checkForProhibitedWordsAndVersion(self, banner):
        penalty = 0
        versionFound = ''
        regexVersionNumber = r'(?:(\d+)\.)?(?:(\d+)\.)?(?:(\d+)\.\d+)'
        
        match = re.search(regexVersionNumber, banner)
        if match:
            versionFound = match.group(0)
            fail('Sensitive software version number found in banner: "{}"'.format(
                versionFound
            ), toOutLine = True)
            self.results['not-contains-version'] = False
            penalty += BannerParser.weights['versionFound']
        
        alreadyFound = set()
        for word in BannerParser.prohibitedWords:
            if word.lower() in banner.lower():
                if not word.lower() in alreadyFound:
                    info('Prohibited word found in banner: "{}"'.format(
                        word
                    ), toOutLine = True)
                    self.results['not-contains-prohibited-words'] = True
                    alreadyFound.add(word.lower())

                mult = 1
                if word.lower() in BannerParser.prohibitedSoftwareWords:
                    mult = BannerParser.softwareWeight
                elif word.lower() in BannerParser.prohibitedOSWords:
                    mult = BannerParser.prohibitedOSWords

                penalty += (float(mult) * BannerParser.weights['prohibitedWord'])

                # Does the word immediately follow or precede version number?
                if versionFound:
                    surrounds = (
                        '{}{}'.format(word, versionFound),
                        '{}{}'.format(versionFound, word),
                        '{} {}'.format(word, versionFound),
                        '{} {}'.format(versionFound, word),
                        '{}/{}'.format(word, versionFound),
                        '{}/{}'.format(versionFound, word),
                    )
                    for surr in surrounds:
                        if surr in banner:
                            info('Word was found lying around version: "{}". '\
                                'Consider removing it.'.format(
                                surr
                            ), toOutLine = True)
                            penalty += BannerParser.weights['versionNearProhibitedWord']
                            break

        return penalty

    def checkHostnameInBanner(self, banner):
        penalty = 0
        matched = re.search(BannerParser.localHostnameRegex, banner)

        if matched:
            localHostname = matched.group(1)
            self.results['contains-hostname'] = True
            info('Extracted hostname from banner: "{}"'.format(localHostname))
        else:
            fail('SMTP Banner does not contain server\'s hostname. This may cause SPAM reports.', toOutLine = True)
            penalty = 1

        return penalty



class DmarcParser:
    def __init__(self):
        self.results = {
            'dmarc-version' : False,
            'policy-rejects-by-default': False,
            'number-of-messages-filtered': True,
        }

    def processDmarc(self, record):
        if not record:
            if config['always_unfolded_results']:
                return dict.fromkeys(self.results, None)
            else:
                return None

        for keyValue in record.split(' '):
            if not keyValue: break
            k, v = keyValue.split('=')
            k = k.strip()
            v = v.strip()

            if v.endswith(';'): 
                v = v[:-1]

            if k == 'v':
                self.results['dmarc-version'] = v.lower() == 'dmarc1'
                if not self.results['dmarc-version']:
                    fail('UNSECURE: Unknown version of DMARC stated: {}'.format(v))

            elif k == 'p':
                if v.lower() not in ('none', 'reject', 'quarantine'):
                    fail('UNSECURE: Unknown policy stated: {}'.format(v))
                    self.results['policy-rejects-by-default'] = False
                else:
                    self.results['policy-rejects-by-default'] = v.lower() == 'reject'

                    if not self.results['policy-rejects-by-default']:
                        fail('UNSECURE: DMARC policy does not reject unverified messages ({}).'.format(
                            v
                        ))
            elif k == 'pct':
                try:
                    perc = int(v)
                    self.results['number-of-messages-filtered'] = perc >= 20

                    if self.results['number-of-messages-filtered']:
                        info('Percentage of filtered messages is satisfiable ({})'.format(
                            perc
                        ))
                    else:
                        fail('UNSECURE: Unsatisfiable percentage of messages filtered: {}!'.format(
                            perc
                        ))

                except ValueError:
                    fail('Defined "pct" is not a valid percentage!')
                    self.results['number-of-messages-filtered'] = False

        if not config['always_unfolded_results'] and all(self.results.values()):
            return True
        else:
            return self.results

class DkimParser:
    minimumDkimKeyLength = 1024

    def __init__(self):
        self.results = {
            'public-key-length': True,
        }

    def process(self, record):
        self.testKeyLength(record)

        if not config['always_unfolded_results'] and all(self.results.values()):
            return True
        else:
            return self.results

    def testKeyLength(self, txt):
        tags = txt.split(';')
        dkim = {}

        for t in tags:
            k, v = t.strip().split('=')
            dkim[k] = v

        if 'p' not in dkim.keys(): return False

        pubkey = base64.b64decode(dkim['p'])
        keyLen = (len(pubkey) - 38) * 8 # 38 bytes is for key's metadata

        if keyLen < 0: 
            fail('Incorrect Public Key in DKIM!')
            keyLen = 0

        dbg('DKIM: version = {}, algorithm = {}, key length = {}'.format(
            dkim['v'], dkim['k'], keyLen
        ))

        if keyLen < DkimParser.minimumDkimKeyLength:
            fail('UNSECURE: DKIM Public Key length is insufficient: {}. ' \
                'Recommended at least {}'.format(
                keyLen, DkimParser.minimumDkimKeyLength
            ))

            self.results['public-key-length'] = False
        else:
            ok('SECURE: DKIM Public key is of sufficient length: {}'.format(keyLen))
            self.results['public-key-length'] = True

        return self.results['public-key-length']

class SpfParser:
    #maxAllowedNetworkMask = 28
    maxNumberOfDomainsAllowed = 3

    allowedHostsNumber = 0
    allowSpecifiers = 0

    mechanisms = ('all', 'ip4', 'ip6', 'a', 'mx', 'ptr', 'exists', 'include')
    qualifiers = ('+', '-', '~', '?')

    def __init__(self):
        self.results = {
            'spf-version': True,
            'all-mechanism-usage': True,
            'allowed-hosts-list': True,
        }

        self.addressBasedMechanism = 0

    def process(self, record):
        if not record:
            if config['always_unfolded_results']:
                return dict.fromkeys(self.results, None)
            else:
                return None

        record = record.lower()
        tokens = record.split(' ')

        dbg('Processing SPF record: "{}"'.format(record))

        for token in tokens:
            qualifier = ''
            if not token: continue

            dbg('SPF token: {}'.format(token))

            if token.startswith('v=spf'):
                self.results['spf-version'] = self.processVersion(token)
                continue

            if token[0] not in string.ascii_letters and token[0] not in SpfParser.qualifiers:
                fail('SPF record contains unknown qualifier: "{}". Ignoring it...'.format(
                    token[0]
                ))

                qualifier = token[0]
                token = token[1:]
            else:
                qualifier = '+'

            if 'all' in token:
                self.results['all-mechanism-correctly-used'] = \
                self.processAllMechanism(token, record, qualifier)
                continue

            if len(list(filter(lambda x: token.startswith(x), SpfParser.mechanisms))) >= 1:
                self.processMechanism(record, token, qualifier)

        if not self.results['allowed-hosts-list']:
            #maxAllowed = 2 ** (32 - SpfParser.maxAllowedNetworkMask)
            maxAllowed = config['spf_maximum_hosts']

            fail('UNSECURE: SPF record allows more than {} max allowed hosts: {} in total.'.format(
                    maxAllowed, self.allowedHostsNumber
            ))
            _out('\tRecord: ("{}")'.format(record))

        if not self.results['allowed-hosts-list']:
            fail('There are too many allowed domains/CIDR ranges specified in SPF record: {}.'.format(
                self.allowSpecifiers
            ))

        if not config['always_unfolded_results'] and all(self.results.values()):
            dbg('All tests passed.')
            return True
        else:
            if not all(self.results.values()):
                dbg('Not all tests passed.: {}'.format(self.results))
            else:
                dbg('All tests passed.')

            return self.results

    def areThereAnyOtherMechanismsThan(self, mechanism, record):
        tokens = record.split(' ')
        otherMechanisms = 0

        for token in tokens:
            if not token: continue
            if token.startswith('v='): continue
            if token[0] in SpfParser.qualifiers:
                token = token[1:]

            if token == mechanism: continue
            if ':' in token:
                for s in token.split(':'):
                    if s in SpfParser.mechanisms:
                        otherMechanisms += 1
                        break

            if '/' in token:
                for s in token.split('/'):
                    if s in SpfParser.mechanisms:
                        otherMechanisms += 1
                        break

            if token in SpfParser.mechanisms:
                otherMechanisms += 1

        dbg('Found {} other mechanisms than "{}"'.format(otherMechanisms, mechanism))
        return (otherMechanisms > 0)

    def processVersion(self, token):
        v, ver = token.split('=')
        validVersions = ('1')

        for version in validVersions:
            if 'spf{}'.format(version) == ver:
                dbg('SPF version was found valid.')
                return True

        fail('SPF version is invalid.')
        return False

    def processAllMechanism(self, token, record, qualifier):
        if not record.endswith(token):
            fail('SPF Record wrongly stated - "{}" mechanism must be placed at the end!'.format(
                token
            ))
            return False

        if token == 'all' and qualifier == '+':
            fail('UNSECURE: SPF too permissive: "The domain owner thinks that SPF is useless and/or doesn\'t care.": "{}"'.format(record))
            return False

        if not self.areThereAnyOtherMechanismsThan('all', record):
            fail('SPF "all" mechanism is too restrictive: "The domain sends no mail at all.": "{}"'.format(record), toOutLine = True)
            return False

        return True

    def getNetworkSize(self, net):
        dbg('Getting network size out of: {}'.format(net))
        m = re.match(r'[\w\.-:]+\/(\d{1,2})', net)
        if m:
            mask = int(m.group(1))
            return 2 ** (32 - mask)

        # Assuming any other value is a one host.
        return 1

    def processMechanism(self, record, token, qualifier):
        key, value = None, None
        addressBasedMechanisms = ('ip4', 'ip6', 'a', 'mx')
        numOfAddrBasedMechanisms = len(list(filter(lambda x: token.startswith(x), 
            addressBasedMechanisms)))

        # Processing address-based mechanisms.
        if numOfAddrBasedMechanisms >= 1:
            if self.addressBasedMechanism >= SpfParser.maxNumberOfDomainsAllowed:
                self.results['allowed-hosts-list'] = False
                self.allowSpecifiers += 1
            else:
                if qualifier == '+':
                    self.addressBasedMechanism += 1
                    self.checkTooManyAllowedHosts(token, record, qualifier)
                else:
                    dbg('Mechanism: "{}" not being passed.'.format(token))


    def checkTooManyAllowedHosts(self, token, record, qualifier):
        if self.results['allowed-hosts-list'] != True:
            return

        tok, val = None, None

        if ':' in token:
            tok, val = token.split(':')
        elif '/' in token and not ':' in token:
            tok, val = token.split('/')
            val = '0/{}'.format(val)
        elif token in SpfParser.mechanisms:
            tok = token
            val = '0/32'
        else:
            err('Invalid address-based mechanism: {}!'.format(token))
            return

        dbg('Processing SPF mechanism: "{}" with value: "{}"'.format(
            tok, val
        ))

        size = self.getNetworkSize(val)
        #maxAllowed = 2 ** (32 - SpfParser.maxAllowedNetworkMask)
        maxAllowed = config['spf_maximum_hosts']

        self.allowedHostsNumber += size
        if size > maxAllowed:
            self.results['minimum-allowed-hosts-list'] = False
            fail('UNSECURE: Too many hosts allowed in directive: {} - total: {}'.format(
                token, size
            ))


class SmtpTester:
    testsConducted = {
        'spf' : 'SPF DNS record test',
        'dkim' : 'DKIM DNS record test', 
        'dmarc' : 'DMARC DNS record test', 
        'banner-contents': 'SMTP Banner sensitive informations leak test', 
        'starttls-offering': 'STARTTLS offering (opportunistic) weak configuration', 
        'secure-ciphers': 'SSL/TLS ciphers security weak configuration', 
        'tls-key-len': 'Checks private key length of negotiated or offered SSL/TLS cipher suites.', 
        'auth-methods-offered': 'Test against unsecure AUTH/X-EXPS PLAIN/LOGIN methods.', 
        'auth-over-ssl': 'STARTTLS before AUTH/X-EXPS enforcement weak configuration', 
        'vrfy': 'VRFY user enumaration vulnerability test', 
        'expn': 'EXPN user enumaration vulnerability test', 
        'rcpt-to': 'RCPT TO user enumaration vulnerability test', 
        'open-relay': 'Open-Relay misconfiguration test',
        'spf-validation': 'Checks whether SMTP Server has been configured to validate sender\'s SPF or Accepted Domains in case of MS Exchange',
    }

    connectionLessTests = (
        'spf', 'dkim', 'dmarc'
    )

    # 25 - plain text SMTP
    # 465 - SMTP over SSL
    # 587 - SMTP-AUTH / Submission
    commonSmtpPorts = (25, 465, 587, )

    # Common AUTH X methods with sample Base64 authentication data.
    commonSmtpAuthMethods = {
        'PLAIN' : base64.b64encode('\0user\0password'.encode()),
        'LOGIN' : (
            (base64.b64encode('user'.encode()), base64.b64encode('password'.encode())), 
            ('user@DOMAIN.COM', base64.b64encode('password'.encode()))
        ),
        'NTLM' : (
            'TlRMTVNTUAABAAAABzIAAAYABgArAAAACwALACAAAABXT1JLU1RBVElPTkRPTUFJTg==', 
            'TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==',
        ),
        'MD5' : '', 
        'DIGEST-MD5' : '',
        'CRAM-MD5' : '',
    }

    smtpAuthServices = ('AUTH', 'X-EXPS')
    authMethodsNotNeedingStarttls = ('NTLM', 'GSSAPI')

    # Pretend you are the following host:
    pretendLocalHostname = config['pretend_client_hostname']

    maxStarttlsRetries = 5

    # Source: SSLabs research: 
    #   https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
    secureCipherSuitesList = (
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-AES128-SHA',
        'ECDHE-ECDSA-AES256-SHA',
        'ECDHE-ECDSA-AES128-SHA256',
        'ECDHE-ECDSA-AES256-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-SHA',
        'ECDHE-RSA-AES256-SHA',
        'ECDHE-RSA-AES128-SHA256',
        'ECDHE-RSA-AES256-SHA384',
        'DHE-RSA-AES128-GCM-SHA256',
        'DHE-RSA-AES256-GCM-SHA384',
        'DHE-RSA-AES128-SHA',
        'DHE-RSA-AES256-SHA',
        'DHE-RSA-AES128-SHA256',
        'DHE-RSA-AES256-SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
        'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    )

    def __init__(self, 
        hostname, 
        port = None, 
        forceSSL = False, 
        dkimSelectorsList = None, 
        userNamesList = None,
        openRelayParams = ('', ''),
        connect = True,
        mailDomain = ''
    ):
        self.originalHostname = hostname
        self.hostname = hostname
        self.remoteHostname = self.localHostname = self.domain = self.resolvedIPAddress = ''
        self.port = port
        self.mailDomain = mailDomain
        self.ssl = None if not forceSSL else True
        self.forceSSL = forceSSL
        self.server = None
        self.starttlsFailures = 0
        self.starttlsSucceeded = False
        self.dkimSelectorsList = dkimSelectorsList
        self.userNamesList = userNamesList
        self.availableServices = set()
        self.banner = ''
        self.connected = False
        self.dumpTlsOnce = False
        self.connectionErrors = 0
        self.connectionErrorCodes = {}
        self.results = {}
        self.threads = {}
        self.stopEverything = False
        self.server_tls_params = {}
        self.openRelayParams = openRelayParams
        self.spfValidated = False

        if not hostname:
            fail('No hostname specified!')
            return

        assert config['dns_full'] in ('always', 'on-ip', 'never'), \
            "config['dns_full'] wrongly stated."

        if re.match(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', hostname) and not mailDomain:
            spf = SmtpTester.checkIfTestToRun('spf')
            dkim = SmtpTester.checkIfTestToRun('dkim')
            dmarc = SmtpTester.checkIfTestToRun('dmarc')

            if spf or dkim or dmarc:
                out('Server\'s IP specified and no mail domain: SPF/DKIM/DMARC results may be inaccurate.', toOutLine = True)
                out('You may want to specify \'--domain\' and repeat those tests for greater confidence.', toOutLine = True)

            self.resolvedIPAddress = hostname
        
        needsConnection = False
        for test in SmtpTester.testsConducted.keys():
            if self.checkIfTestToRun(test) and test not in SmtpTester.connectionLessTests:
                needsConnection = True
                break

        try:
            if needsConnection and connect and not self.connect():
                sys.exit(-1)
        except KeyboardInterrupt:
            fail('Premature program interruption. Did not even obtained connection.')
            sys.exit(-1)

        self.connected = True
        if not self.resolveDomainName():
            sys.exit(-1)

    @staticmethod
    def getTests():
        return SmtpTester.testsConducted

    def stop(self):
        err('Stopping everything.')
        config['max_enumerations'] = 0
        self.stopEverything = True
        self.disconnect()

    def resolveDomainName(self):
        if self.hostname:
            resolutionFailed = False

            if re.match('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', self.hostname):
                resolved = None
                try:
                    resolved = socket.gethostbyaddr(self.hostname)
                    self.remoteHostname = repr(resolved[0]).replace("'", '')
                    info('Resolved DNS (A) name: "{}"'.format(
                        self.remoteHostname
                    ))

                except socket.herror as e:
                    dbg('IP address could not be resolved into hostname.')
                    resolutionFailed = True
            else:
                try:
                    resolved = socket.gethostbyname(self.hostname)
                    info('Resolved IP address / PTR: "{}"'.format(
                        resolved
                    ))
                    self.resolvedIPAddress = resolved
                except socket.herror as e:
                    dbg('DNS name could not be resolved into IP address.')

            matched = None
            if self.banner:
                matched = re.search(BannerParser.localHostnameRegex, self.banner)
                if matched:
                    self.localHostname = matched.group(1)
                    info('SMTP banner revealed server name: "{}".'.format(
                        self.localHostname
                    ))

            if resolutionFailed and not matched:
                fail("Could not obtain server's hostname from neither IP nor banner!")
                return False
            elif not resolutionFailed and not matched:
                info("Resolved IP but could not obtain server's hostname from the banner.")
                return True
            elif resolutionFailed and matched:
                info("It was possible to obtain server's hostname from the banner but not to resolve IP address.")
                return True

        return True

    def printDNS(getDNSValidHostname):
        def wrapper(self, noRemote = True):
            out = getDNSValidHostname(self, noRemote)
            if config['smtp_debug']:
                dbg('Using hostname: "{}" for DNS query.'.format(out))
            return out

        return wrapper

    @printDNS
    def getDNSValidHostname(self, noRemote = False):
        if self.localHostname: 
            return self.localHostname
        elif not noRemote and self.remoteHostname:
            return self.remoteHostname
        else:
            return self.hostname

    def getMailDomain(self):
        if self.mailDomain:
            return self.mailDomain

        hostname = self.getDNSValidHostname(noRemote = True)
        return '.'.join(hostname.split('.')[1:])

    def getAllPossibleDomainNames(self):
        allOfThem = [
            self.originalHostname,  # 0
            self.hostname,          # 1
            self.localHostname,     # 2
            self.getMailDomain(),   # 3
            self.remoteHostname,    # 4

            # 5. FQDN without first LLD
            '.'.join(self.originalHostname.split('.')[1:])
        ]
        uniq = set()
        ret = []

        # Workaround for having OrderedSet() alike collection w/o importing such modules
        for host in allOfThem:
            if host not in uniq:
                ret.append(host)
            uniq.add(host)

        return ret

    def getDomainsToReviewDNS(self):
        if self.mailDomain:
            return [self.mailDomain,]

        domainsToReview = [self.originalHostname]
        doFullReview = False
        ipRex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

        if config['dns_full'] == 'always' or \
            (config['dns_full'] == 'on-ip' and re.match(ipRex, self.originalHostname)):
            doFullReview = True

        if doFullReview:
            domainsToReview = list(filter(
                lambda x: not re.match(ipRex, x),
                self.getAllPossibleDomainNames()
            ))

        # Get only domains, not subdomains.
        domainsToReview = set(map(
            lambda x: '.'.join(x.split('.')[-2:]),
            domainsToReview
        ))

        out = list(filter(None, domainsToReview))
        out = [x.replace('"', '').replace("'", "") for x in out]
        return out

    def disconnect(self):
        if self.server:
            try: 
                self.server.quit()
                del self.server
                self.server = None
                time.sleep(0.5)
            except: 
                pass

    def connect(self, quiet = False, sayHello = False):
        ret = False
        noBannerPreviously = self.banner == ''

        if self.stopEverything:
            return False

        self.disconnect()

        if self.port == None:
            ret = self.tryToConnectOnDifferentPorts(quiet)
        else:
            ret = self.reconnect(quiet)
        
        if noBannerPreviously and self.banner:
            _out('SMTP banner: "{}"'.format(self.banner), True, colors.fg.pink)

        if ret and sayHello:
            dbg('Saying HELO/EHLO to the server...')
            out = self.sendcmd('EHLO ' + SmtpTester.pretendLocalHostname)
            dbg('Server responded to HELO/EHLO with: {}'.format(out))

            if out[0]:
                self.parseHelpOutputAndUpdateServicesList(out[1].decode())
            else:
                err('Could not obtain response to EHLO/HELO. Fatal error.', toOutLine = True)
                sys.exit(-1)

        return ret

    def connectSocket(self, port, ssl, sayHello = True):
        if ssl:
            self.server = smtplib.SMTP_SSL(
                local_hostname = SmtpTester.pretendLocalHostname, 
                timeout = config['timeout']
            )
        else:
            self.server = smtplib.SMTP(
                local_hostname = SmtpTester.pretendLocalHostname, 
                timeout = config['timeout']
            )

        if config['smtp_debug']: 
            self.server.set_debuglevel(9)

        if config['delay'] > 0.0: 
            time.sleep(config['delay'])
                
        out = self.server.connect(self.hostname, port)
        if out[0] in (220, 250, ):
            dbg('Connected over {} to {}:{}'.format(
                'SSL' if ssl else 'Non-SSL', self.hostname, port
            ))

            self.banner = out[1].decode()
            self.port = port
            self.ssl = ssl

            if ssl:
                self.performedStarttls = True
                self.server_tls_params = {
                    'cipher' : self.server.sock.cipher(),
                    'version': self.server.sock.version(),
                    'shared_ciphers': self.server.sock.shared_ciphers(),
                    'compression': self.server.sock.compression(),
                    'DER_peercert': self.server.sock.getpeercert(True),
                    'selected_alpn_protocol': self.server.sock.selected_alpn_protocol(),
                    'selected_npn_protocol': self.server.sock.selected_npn_protocol(),
                }

            if sayHello:
                dbg('Saying HELO/EHLO to the server...')
                out = self.sendcmd('EHLO ' + SmtpTester.pretendLocalHostname)
                dbg('Server responded to HELO/EHLO with: {}'.format(out))

                self.parseHelpOutputAndUpdateServicesList(self.banner)
        else:
            if out[0] not in self.connectionErrorCodes.keys():
                self.connectionErrorCodes[out[0]] = 0
            else:
                self.connectionErrorCodes[out[0]] += 1

            if out[0] == 421:
                # 421 - Too many connections error
                pass

            elif out[0] == 450:
                # 450 - 4.3.2 try again later
                if self.connectionErrorCodes[out[0]] > 5:
                    err("We have sent too many connection requests and were temporarily blocked.\nSorry. Try again later.", toOutLine = True)
                    sys.exit(-1)
                else:
                    fail('Waiting 30s for server to cool down after our flooding...')
                    time.sleep(30)

            elif out[0] == 554:
                # 554 - 5.7.1 no reverse DNS
                out = False if self.connectionErrors > 0 else True
                err('Our host\'s IP does not have reverse DNS records - what makes SMTP server reject us.', toOutLine = out)
                if self.connectionErrors > 5:
                    err('Could not make the SMTP server, ccept us without reverse DNS record.', toOutLine = True)
                    sys.exit(-1)
            else:
                err('Unexpected response after connection, from {}:{}:\n\tCode: {}, Message: {}.'.format(
                    self.hostname, port, out[0], out[1]
                ))
            dbg('-> Got response: {}'.format(out))

            self.connectionErrors += 1
            if self.connectionErrors > 20:
                err('Could not connect to the SMTP server!')
                sys.exit(-1)

        return out

    def tryToConnectOnSSLandNot(self, port):
        try:
            # Try connecting over Non-SSL socket
            if self.forceSSL: 
                raise Exception('forced ssl')

            dbg('Trying non-SSL over port: {}'.format(port))
            self.connectSocket(port, False)
            return True

        except Exception as e:
            # Try connecting over SSL socket
            dbg('Exception occured: "{}"'.format(str(e)))
            try:
                dbg('Trying SSL over port: {}'.format(port))
                self.connectSocket(port, True)

                self.starttlsSucceeded = True
                return True

            except Exception as e:
                dbg('Both non-SSL and SSL connections failed: "{}"'.format(str(e)))

        return False

    def tryToConnectOnDifferentPorts(self, quiet):
        #
        # No previous connection.
        # Enumerate common SMTP ports and find opened one.
        #
        succeeded = False

        for port in SmtpTester.commonSmtpPorts:
            if self.stopEverything: break
            if self.tryToConnectOnSSLandNot(port):
                succeeded = True
                break

        if not quiet:
            if not succeeded:
                err('Could not connect to the SMTP server!')
            else:
                ok('Connected to the server over port: {}, SSL: {}'.format(
                    self.port, self.ssl
                ), toOutLine = True)

        return succeeded

    def reconnect(self, quiet, sayHello = True):
        #
        # The script has previously connected or knows what port to choose.
        #
        multiplier = 0

        for i in range(4):
            try:
                out = self.connectSocket(self.port, self.ssl, sayHello = sayHello)
                if out[0] == 421:
                    multiplier += 1
                    delay = multiplier * config['too_many_connections_delay']

                    info('Awaiting {} secs for server to close some of our connections...'.format(
                        delay
                    ))
                    time.sleep(delay)
                    continue
                else:
                    dbg('Reconnection succeeded ({})'.format(out))
                    return True

            except (socket.gaierror, 
                    socket.timeout, 
                    smtplib.SMTPServerDisconnected, 
                    ConnectionResetError) as e:
                dbg('Reconnection failed ({}/3): "{}"'.format(i, str(e)))

            dbg('Server could not reconnect after it unexpectedly closed socket.')

            return False

    def setSocketTimeout(self, timeout = config['timeout']):
        try:
            self.server.sock.settimeout(timeout)

        except (AttributeError, OSError):
            dbg('Socket lost somehow. Reconnecting...')

            if self.connect(True):
                try:
                    self.server.sock.settimeout(timeout)
                except (AttributeError, OSError): pass
            else:
                dbg('FAILED: Could not reconnect to set socket timeout.')


    def processOutput(sendcmd):
        def wrapper(self, command, nowrap = False):
            out = sendcmd(self, command, nowrap)

            if nowrap:
                return out

            if out and (out[0] == 530 and b'STARTTLS' in out[1]):
                if self.starttlsFailures >= SmtpTester.maxStarttlsRetries:
                    dbg('Already tried STARTTLS and it have failed too many times.')
                    return (False, False)

                dbg('STARTTLS reconnection after wrapping command ({})...'.format(command))

                if not self.performStarttls():
                    dbg('STARTTLS wrapping failed.')
                    return (False, 'Failure')

                dbg('Wrapping succeeded. Retrying command "{}" after STARTTLS.'.format(
                    command
                ))

                return sendcmd(self, command)

            elif out and (out[0] == 421):
                # 'Exceeded bad SMTP command limit, disconnecting.'
                dbg('Reconnecting due to exceeded number of SMTP connections...')
                if self.connect(quiet = True):
                    return sendcmd(self, command)
                else:
                    dbg('Could not reconnect after exceeded number of connections!')
                    return (False, False)

            self.checkIfSpfEnforced(out)

            return out
        return wrapper

    def performStarttls(self, sendEhlo = True):
        ret = True

        if self.ssl == True:
            dbg('The connection is already carried through SSL Socket.')
            return True

        if self.starttlsFailures > SmtpTester.maxStarttlsRetries:
            fail('Giving up on STARTTLS. There were too many failures...')
            return False

        out = self.sendcmd('STARTTLS')
        if out[0] == 220:
            dbg('STARTTLS engaged. Wrapping socket around SSL layer.')

            context = ssl.create_default_context()

            # Allow unsecure ciphers like SSLv2 and SSLv3
            context.options &= ~(ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            if self.server and self.server.sock:
                self.setSocketTimeout(5 * config['timeout'])

            try:
                newsock = context.wrap_socket(
                    self.server.sock,
                    server_hostname = SmtpTester.pretendLocalHostname
                )

                # Re-initializing manually the smtplib instance
                self.server.sock = newsock
                self.server.file = None
                self.server.helo_resp = None
                self.server.ehlo_resp = None
                self.server.esmtp_features = {}
                self.server.does_esmtp = 0

                self.starttlsSucceeded = True

                self.server_tls_params = {
                    'cipher' : newsock.cipher(),
                    'version': newsock.version(),
                    'shared_ciphers': newsock.shared_ciphers(),
                    'compression': newsock.compression(),
                    'DER_peercert': newsock.getpeercert(True),
                    'selected_alpn_protocol': newsock.selected_alpn_protocol(),
                    'selected_npn_protocol': newsock.selected_npn_protocol(),
                }

                dbg('Connected to the SMTP Server via SSL/TLS.')
                if not self.dumpTlsOnce:
                    dbg('SSL Socket parameters:\n{}'.format(pprint.pformat(self.server_tls_params)))
                    self.dumpTlsOnce = True

                if sendEhlo:
                    dbg('Sending EHLO after STARTTLS...')
                    out = self.sendcmd('EHLO ' + SmtpTester.pretendLocalHostname)
                    if out[0]:
                        dbg('EHLO after STARTTLS returned: {}'.format(out))
                    else:
                        err('EHLO after STARTTLS failed: {}'.format(out))

            except (socket.timeout, ConnectionResetError) as e:
                err('SSL Handshake timed-out (Firewall filtering?). Fall back to plain channel.')
                dbg('STARTTLS exception: "{}"'.format(str(e)))
                
                self.starttlsFailures += 1
                if not self.connect(quiet = True, sayHello = False):
                    ret = False

            self.setSocketTimeout()
        elif out[0] == 500:
            info('The server is not offering STARTTLS.')
        else:
            fail('The server has not reacted for STARTTLS: ({}). Try increasing timeout.'.format(str(out)))

        return ret

    @processOutput
    def sendcmd(self, command, nowrap = False):
        out = (False, False)

        dbg('Sending command: "{}"'.format(command))
        self.setSocketTimeout(3 * config['timeout'])

        for j in range(3):
            try:
                if config['delay'] > 0.0: 
                    time.sleep(config['delay'])

                out = self.server.docmd(command)
                dbg('Command resulted with: {}.'.format(out))

                if out[0] in (503,) and b'hello first' in out[1].lower():
                        # 503: 5.5.2 Send hello first

                        dbg('Ok, ok - sending Hello first...')

                        if self.connect(quiet = True, sayHello = True):
                            dbg('Ok, reconnected and said hello. Trying again...')
                        else:
                            dbg('Failed reconnecting and saying hello.')
                            return (False, False)
                        continue
                break

            except (smtplib.SMTPServerDisconnected, socket.timeout) as e:
                if str(e) == 'Connection unexpectedly closed':
                    # smtplib.getreply() returns this error in case of reading empty line.
                    #dbg('Server returned empty line / did not return anything.')
                    #return (False, '')

                    dbg('Connection unexpectedly closed: {}'.format(str(e)))

                    if self.connect(quiet = True, sayHello = False):
                        continue
                else:
                    dbg('Server has disconnected ({}).'.format(str(e)))
                    if 'connect' in str(e).lower():
                        dbg('Attempting to reconnect and resend command...')
                        if self.connect(quiet = True, sayHello = False):
                            continue
                        else:
                            break

        if not out[0]:
            dbg('Could not reconnect after failure.')

        self.setSocketTimeout()
        return out[0], out[1]

    def parseHelpOutput(self, output):
        if len(output.split('\n')) >= 2:

            output = output.replace('\t', '\n')
            dbg('Parsing potential HELP output: "{}"'.format(
                output.replace('\n', '\\n')
            ))

            helpMultilineCommandsRegexes = (
                r'(?:\\n)([a-zA-Z- 0-9]{3,})',
                r'(?:\n)([a-zA-Z- 0-9]{3,})'
            )

            for rex in helpMultilineCommandsRegexes:
                out = re.findall(rex, output)
                if len([x for x in out if x != None]) > 0:
                    return out
        else:
            return ''

    def parseHelpOutputAndUpdateServicesList(self, out):
        outlines = self.parseHelpOutput(out)
        if outlines:
            self.availableServices.update(set(map(lambda x: x.strip(), outlines)))
            outlines = set()

            dbg('SMTP available services: {}'.format(pprint.pformat(self.availableServices)))
            return True

        return False

    def getAvailableServices(self):
        dbg('Acquiring list of available services...')
        
        out = False
        outlines = set()

        if self.banner:
            if self.parseHelpOutputAndUpdateServicesList(self.banner):
                return True

        out = self.sendcmd('EHLO ' + SmtpTester.pretendLocalHostname)
        if out[0]:
            dbg('EHLO returned: {}'.format(out))
            if self.parseHelpOutputAndUpdateServicesList(out[1].decode()):
                return True
            

        # We are about to provoke SMTP server sending us the HELP listing in result
        # of sending one of below collected list of commands.
        for cmd in ('HELP', '\r\nHELP', 'TEST'):
            try:
                out = self.sendcmd(cmd)
                if out[0] in (214, 220, 250):
                    ret = out[1].decode()

                    if self.parseHelpOutputAndUpdateServicesList(ret):
                        return True

                    outlines = self.parseHelpOutput(ret)
                    if len(outlines) < 2:
                        for line in ret.split('\\n'):
                            m = re.findall(r'([A-Z-]{3,})', line)
                            pos = ret.find(line)
                            if m and (pos > 0 and ret[pos-1] == '\n'):
                                dbg('Following line was found by 2nd method HELP parsing: "{}"'.format(
                                    line
                                ))

                                outlines = m
                                break
                if outlines:
                    break

            except Exception as e:
                continue

        if outlines:
            self.availableServices.update(set(map(lambda x: x.strip(), outlines)))

            dbg('SMTP available services: {}'.format(pprint.pformat(self.availableServices)))
            return True

        info('Could not collect available services list (HELP)')
        return False

    def getAuthMethods(self, service):
        if not self.availableServices:
            self.getAvailableServices()

        if not self.availableServices:
            fail('UNKNOWN: Could not collect available SMTP services')
            return None

        authMethods = set()
        authMethodsList = list(filter(
            lambda x: x.lower().startswith(service.lower()) and x.lower() != service.lower(), 
            self.availableServices
        ))

        # Conform following HELP format: "250-AUTH=DIGEST-MD5 CRAM-MD5 PLAIN LOGIN"
        if authMethodsList:
            dbg('List of candidates for {} methods: {}'.format(service, authMethodsList))

            for auth in authMethodsList:
                auth = auth.strip().replace('=', ' ')
                auth = auth.replace(service + ' ', '')

                if auth.count(' ') > 0:
                    s = set(['{}'.format(a) for a in auth.split(' ') \
                        if a.lower() != service.lower()])
                    authMethods.update(s)
                else:
                    authMethods.add(auth)
        else:
            dbg('The server does not offer any {} methods.'.format(service))

        if authMethods:
            dbg('List of {} methods to test: {}'.format(service, authMethods))

        return authMethods

    @staticmethod
    def ifMessageLike(out, codes = None, keywords = None, keywordsAtLeast = 0):
        codeCheck = False
        keywordCheck = False

        if not codes and not keywords:
            return False

        keywords2 = [k.lower() for k in keywords]
        msg = out[1].decode()
        found = 0
        for word in msg.split(' '):
            if word.lower() in keywords2:
                found += 1

        if codes != None and len(codes) > 0:
            codeCheck = out[0] in codes
        else:
            codeCheck = True

        if keywords != None and len(keywords) > 0:
            if keywordsAtLeast == 0:
                keywordCheck = found == len(keywords)
            else:
                keywordCheck = found >= keywordsAtLeast
        else:
            keywordCheck = True

        return codeCheck and keywordCheck

    @staticmethod
    def checkIfTestToRun(test):
        if (test in config['tests_to_skip']):
            return False

        if ('all' in config['tests_to_carry'] or test in config['tests_to_carry']):
            return True
        else:
            if config['smtp_debug']:
                dbg('Test: "{}" being skipped as it was marked as disabled.'.format(test))
            return False

    def runTests(self):
        dkimTestThread = None
        if SmtpTester.checkIfTestToRun('dkim'):
            dkimTestThread = self.dkimTestThread()
        
        results = [
            ('spf', None),
            ('dkim', None),
            ('dmarc', None),
            ('banner-contents', self.bannerSnitch),
            ('starttls-offering', self.starttlsOffer),
            ('secure-ciphers', self.testSecureCiphers),
            ('tls-key-len', self.testSSLKeyLen),
            ('auth-methods-offered', self.testSecureAuthMethods),
            ('auth-over-ssl', self.testSSLAuthEnforcement),
            ('vrfy', self.vrfyTest),
            ('expn', self.expnTest),
            ('rcpt-to', self.rcptToTests),
            ('open-relay', self.openRelayTest),
            ('spf-validation', self.spfValidationTest),
        ]

        if SmtpTester.checkIfTestToRun('spf'):
            self.results['spf'] = self.spfTest()

        once = True
        for res in results:
            test, func = res

            assert test in SmtpTester.testsConducted.keys(), \
                "The test: '{}' has not been added to SmtpTester.testsConducted!".format(test)

            if self.stopEverything: break
            if not SmtpTester.checkIfTestToRun(test):
                continue
                
            if not func: continue

            if config['delay'] > 0.0:
                time.sleep(config['delay'])

            if once:
                if not self.connected and not self.connect():
                    sys.exit(-1)
                else:
                    self.connected = True
                once = False

            dbg('Starting test: "{}"'.format(test))
            self.results[test] = func()

            if SmtpTester.checkIfTestToRun('auth-over-ssl') and \
                test == 'auth-over-ssl':
                dbg('Reconnecting after SSL AUth enforcement tests.')
                if self.stopEverything: break
                self.reconnect(quiet = True)

        testDmarc = False
        if SmtpTester.checkIfTestToRun('dkim') and \
            SmtpTester.checkIfTestToRun('spf') and \
            SmtpTester.checkIfTestToRun('dmarc'):
            testDmarc = True
            self.results['dmarc'] = None

        if SmtpTester.checkIfTestToRun('dmarc') and not testDmarc:
            err('To test DMARC following tests must be run also: SPF, DKIM.')

        if self.threads or dkimTestThread:
            if not self.stopEverything:
                info("Awaiting for threads ({}) to finish. Pressing CTRL-C will interrupt lookup process.".format(
                    ', '.join(self.threads.keys())
                ), toOutLine = True)

                try:
                    while (self.threads and all(self.threads.values())):
                        if self.stopEverything:
                            break
                        time.sleep(2)
                        if config['smtp_debug']:
                            dbg('Threads wait loop has finished iterating.')

                    if testDmarc:
                        self.results['dmarc'] = self.evaluateDmarc(
                            self.dmarcTest(), 
                            self.results['spf'], 
                            self.results['dkim']
                        )

                except KeyboardInterrupt:
                    err('User has interrupted threads wait loop. Returning results w/o DKIM and DMARC.')
        else:
            if testDmarc:
                self.results['dmarc'] = self.evaluateDmarc(
                    self.dmarcTest(), 
                    self.results['spf'], 
                    self.results['dkim']
                )
 
        # Translate those True and False to 'Secure' and 'Unsecure'
        self.results.update(SmtpTester.translateResultsDict(self.results))

        indent = 2
        return json.dumps(self.results, indent = indent)

    def runAttacks(self):
        attacksToBeLaunched = {
            'vrfy': self.vrfyTest, 
            'expn': self.expnTest, 
            'rcpt-to': self.rcptToTests,
        }

        results = []

        info('Attacks will be launched against domain: @{}'.format(self.getMailDomain()), toOutLine = True)
        info('If that\'s not correct, specify another one with \'--domain\'')

        for attack, func in attacksToBeLaunched.items():
            if not SmtpTester.checkIfTestToRun(attack):
                continue

            info('Launching attack: {} enumeration.'.format(attack), toOutLine = True)
            out = func(attackMode = True)

            if out and isinstance(out, list):
                info('Attack result: {} users found.'.format(len(out)), toOutLine = True)
                results.extend(out) 
            elif out:
                info('Attack most likely failed {}, result: {}'.format(attack, str(out)), toOutLine = True)
            else:
                fail('Attack {} failed.'.format(attack), toOutLine = True)

        return list(set(results))

    @staticmethod
    def translateResultsDict(results):
        for k, v in results.items():
                if isinstance(v, dict):
                    results[k] = SmtpTester.translateResultsDict(v)
                else:
                    if v == True:   results[k] = 'secure'
                    elif v == False:results[k] = 'unsecure'
                    else:           results[k] = 'unknown'

        return results

    #
    # ===========================
    # BANNER REVEALING SENSITIVIE INFORMATIONS TEST
    #
    def bannerSnitch(self):
        if not self.banner:
            info('Cannot process server\'s banner - as it was not possible to obtain one.')

        parser = BannerParser()
        return parser.parseBanner(self.banner)


    #
    # ===========================
    # SPF TESTS
    #
    def enumerateSpfRecords(self, domain):
        records = set()
        numberOfSpfRecords = 0
        once = True

        resv = resolver.Resolver()
        resv.timeout = config['timeout'] / 2.0

        info('Queried domain for SPF: "{}"'.format(domain))

        try:
            for txt in resv.query(domain, 'TXT'):
                txt = txt.to_text().replace('"', '')
                if txt.lower().startswith('v=spf') and txt not in records:
                    numberOfSpfRecords += 1
                    records.add(txt)

            if numberOfSpfRecords > 1 and once:
                err('Found more than one SPF record. One should stick to only one SPF record.')
                once = False

        except (resolver.NoAnswer, 
                resolver.NXDOMAIN,
                name.EmptyLabel, 
                resolver.NoNameservers) as e:
            pass

        return records

    def spfTest(self):
        records = {}
        txts = []
        for domain in self.getDomainsToReviewDNS():
            for txt in self.enumerateSpfRecords(domain):
                if txt not in records.keys():
                    txts.append(txt)
                    records[txt] = self.processSpf(txt)

        success = True
        if len(records):
            results = {}
            for txt, rec in records.items():
                origTxt, results = rec
                if isinstance(results, dict) and all(results.values()):
                    pass
                elif isinstance(results, bool) and results:
                    pass
                else:
                    fail('UNSECURE: SPF record exists, but not passed tests.')
                    _out('\tRecord: ("{}")'.format(origTxt))
                    return results

            ok('SECURE: SPF test passed.')
            _out('\tRecords: ("{}")'.format('", "'.join(txts)))
            if config['always_unfolded_results']:
                return results
        else:
            fail('UNSECURE: SPF record is missing.')
            success = False

        return success

    def processSpf(self, txt, recurse = 0):
        '''
        Code processing, parsing and evaluating SPF record's contents.
        '''
        maxRecursion = 3
        info('Found SPF record: "{}"'.format(txt))


        if recurse > maxRecursion:
            err('Too many SPF redirects, breaking recursion.')
            return None

        pos = txt.lower().find('redirect=')
        if pos > 0:
            for tok in txt.lower().split(' '):
                k, v = tok.split('=')
                if v.endswith(';'): v = v[:-1]
                if k == 'redirect':
                    info('SPF record redirects to: "{}". Following...'.format(v))
                    for txt in self.enumerateSpfRecords(v):
                        return (txt, self.processSpf(txt, recurse + 1))

        spf = SpfParser()
        return (txt, spf.process(txt))


    #
    # ===========================
    # DKIM TESTS
    #
    @staticmethod
    def _job(jid, domains, data, syncDkimThreadsStop, results, totalTested, dkimQueryDelay):
        try:
            if (results and sum([x != None for x in results]) > 0) or \
                SmtpTester.stopCondition(totalTested, syncDkimThreadsStop): 
                return
            results.append(SmtpTester.dkimTestWorker(domains, data, syncDkimThreadsStop, dkimQueryDelay, False, totalTested))
        except (ConnectionResetError, FileNotFoundError, BrokenPipeError, EOFError, KeyboardInterrupt):
            pass

    def dkimTestThread(self):
        self.results['dkim'] = None

        if not config['threads']:
            return self.dkimTest()

        poolNum = config['parallel_processes']
        t = threading.Thread(target = self._dkimTestThread, args = (poolNum, ))
        t.daemon = True
        t.start()
        return t

    def stopCondition(totalTested, syncDkimThreadsStop):
        if syncDkimThreadsStop.value:
            return True

        if config['max_enumerations'] > 0 and \
            totalTested.value >= config['max_enumerations']: 
            return True

        return False

    def _dkimTestThread(self, poolNum):
        def _chunks(l, n):
            return [l[i:i+n] for i in range(0, len(l), n)]

        self.threads['dkim'] = True
        dbg('Launched DKIM test in a new thread running with {} workers.'.format(poolNum))

        selectors = self.generateListOfCommonDKIMSelectors()
        info('Selectors to review: {}'.format(len(selectors)))

        jobs = []
        mgr = multiprocessing.Manager()
        totalTested = multiprocessing.Value('i', 0)
        syncDkimThreadsStop = multiprocessing.Value('i', 0)
        dkimQueryDelay = multiprocessing.Value('d', 0.0)

        results = mgr.list()
        slice = _chunks(selectors, len(selectors) // poolNum)
        domains = self.getDomainsToReviewDNS()

        try:
            for i, s in enumerate(slice):
                if SmtpTester.stopCondition(totalTested, syncDkimThreadsStop) or self.stopEverything: break
                proc = multiprocessing.Process(
                    target = SmtpTester._job, 
                    args = (i, domains, s, syncDkimThreadsStop, results, totalTested, dkimQueryDelay)
                )
                proc.start()
                jobs.append(proc)
            
            num = len(domains) * len(selectors)
            totals = []
            lastTotal = 0

            maxDelay = 4.0
            delayStep = 0.5
            smallStepToDelay = 50

            while totalTested.value < len(selectors) - 50:
                if SmtpTester.stopCondition(totalTested, syncDkimThreadsStop) or self.stopEverything: break

                totals.append(totalTested.value)
                js = '(jobs running: {})'.format(len(jobs))
                SmtpTester.dkimProgress(totalTested.value, selectors, num, syncDkimThreadsStop, True, js, dkimQueryDelay.value)

                if config['delay_dkim_queries']:
                    if totalTested.value - lastTotal < smallStepToDelay and dkimQueryDelay.value < maxDelay:
                        dkimQueryDelay.value += delayStep
                    elif totalTested.value - lastTotal >= smallStepToDelay and dkimQueryDelay.value > 0:
                        dkimQueryDelay.value -= delayStep

                lastTotal = totalTested.value

                # Wait 5*2 seconds for another DKIM progress message
                for i in range(15): 
                    if SmtpTester.stopCondition(totalTested, syncDkimThreadsStop) or self.stopEverything: break
                    time.sleep(2)

                if totals.count(totalTested.value) > 1:
                    syncDkimThreadsStop.value = 1
                    err('Stopping DKIM thread cause it seems to have stuck.', toOutLine = True)
                    break

            info('DKIM selectors enumerated. Stopping jobs...')
            for j in jobs:
                if SmtpTester.stopCondition(totalTested, syncDkimThreadsStop) or self.stopEverything: break
                for i in range(30):
                    if SmtpTester.stopCondition(totalTested, syncDkimThreadsStop) or self.stopEverything: break
                    j.join(2 * 60 / 30)
        except (KeyboardInterrupt, BrokenPipeError):
            pass

        try:
            if results and sum([x != None for x in results]) > 0:
                dbg('DKIM thread found valid selector.')
                self.results['dkim'] = [x for x in results if x != None][0]
            else:
                fail('UNSECURE: DKIM record is most likely missing, as proved after {} tries.'.format(
                    totalTested.value
                ))
        except FileNotFoundError:
            pass

        self.threads['dkim'] = False
        return self.results['dkim']

    def dkimTest(self, selectors = None):
        if not selectors:
            selectors = self.generateListOfCommonDKIMSelectors()
        
        ret = self.dkimTestWorker(self.getDomainsToReviewDNS(), selectors)
        self.results['dkim'] = ret
        return ret

    @staticmethod
    def dkimProgress(total, selectors, num, syncDkimThreadsStop, unconditional = False, extra = None, dkimQueryDelay = 0):
        if total < 100 or SmtpTester.stopCondition(total, syncDkimThreadsStop): 
            return

        progressStr = 'DKIM: Checked {:02.0f}% ({:05}/{:05}) selectors. Query delay: {:0.2f} sec.'.format(
            100.0 * (float(total) / float(len(selectors))),
            total,
            len(selectors),
            dkimQueryDelay
        )

        if extra: progressStr += ' ' + extra
        progressStr += '...'

        N = 10
        if (not config['debug'] and (unconditional or ((total % int(num // N)) == 0))):
            info(progressStr, toOutLine = True)

        elif (config['debug'] and (unconditional or (total % 250 == 0))):
            if config['threads']:
                dbg(progressStr)
            else:
                sys.stderr.write(progressStr + '\r')
                sys.stderr.flush()

    @staticmethod
    def dkimTestWorker(domainsToReview, selectors, syncDkimThreadsStop, dkimQueryDelay = None, reportProgress = True, totalTested = None):
        ret = False
        stopIt = False
        total = 0

        maxTimeoutsToAccept = int(0.3 * len(selectors))
        timeoutsSoFar = 0

        if SmtpTester.stopCondition(totalTested, syncDkimThreadsStop): return None

        num = len(domainsToReview) * len(selectors)
        if reportProgress:
            info('Checking around {} selectors. Please wait - this will take a while.'.format(
                num
            ))

        resv = resolver.Resolver()
        resv.timeout = 1.2

        for domain in domainsToReview:
            if stopIt or SmtpTester.stopCondition(totalTested, syncDkimThreadsStop): break
            if reportProgress:
                info('Enumerating selectors for domain: {}...'.format(domain))

            for sel in selectors:
                if stopIt or SmtpTester.stopCondition(totalTested, syncDkimThreadsStop): break
                dkimRecord = '{}._domainkey.{}'.format(sel, domain)
                total += 1
                if totalTested: totalTested.value += 1

                if reportProgress:
                    SmtpTester.dkimProgress(total, selectors, num)
                try:
                    if not dkimRecord: continue
                    if dkimQueryDelay and dkimQueryDelay.value > 0:
                        time.sleep(dkimQueryDelay.value)
                        
                    for txt in resv.query(dkimRecord, 'TXT'):
                        if stopIt or SmtpTester.stopCondition(totalTested, syncDkimThreadsStop): break

                        txt = txt.to_text().replace('"', '')
                        if config['max_enumerations'] > -1 and \
                            total >= config['max_enumerations']:
                            stopIt = True
                            break

                        if txt.lower().startswith('v=dkim'):
                            info('DKIM found at selector: "{}"'.format(sel))
                            ret = SmtpTester.processDkim(txt)

                            if ret: 
                                ok('SECURE: DKIM test passed.')
                            else: 
                                fail('UNSECURE: DKIM test not passed')

                            syncDkimThreadsStop.value = 1
                            return ret
                except (exception.Timeout) as e:
                    if timeoutsSoFar >= maxTimeoutsToAccept:
                        err('DNS enumeration failed: Maximum number of timeouts from DNS server reached.')
                        break
                    
                    timeoutsSoFar += 1

                except (AttributeError,
                        resolver.NoAnswer,
                        resolver.NXDOMAIN,
                        resolver.NoNameservers,
                        name.EmptyLabel, 
                        name.NameTooLong) as e:
                    continue

                except KeyboardInterrupt:
                    dbg('User has interrupted DKIM selectors enumeration test.')
                    return None

        if reportProgress:
            if total >= num:
                fail('UNSECURE: DKIM record is most likely missing. Exhausted list of selectors.')
            else:
                fail('UNSECURE: DKIM record is most likely missing. Process interrupted ({}/{}).'.format(
                    total, num
                ))

        return None

    @staticmethod
    def processDkim(txt):
        '''
        Code processing, parsing and evaluating DKIM record's contents.
        '''

        dkim = DkimParser()
        return dkim.process(txt)


    def generateListOfCommonDKIMSelectors(self):
        '''
        Routine responsible for generating list of DKIM selectors based on
        various permutations of the input words (like common DKIM selectors or other likely
        selector names).
        '''
        
        months = ('styczen', 'luty', 'marzec', 'kwiecien', 'maj', 'czerwiec', 'lipiec', 
            'sierpien', 'wrzesien', 'pazdziernik', 'listopad', 'grudzien', 'january', 
            'february', 'march', 'april', 'may', 'june', 'july', 'august', 'october', 
            'november', 'september', 'december', 'enero', 'febrero', 'marzo', 'abril', 
            'mayo', 'junio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre', 
            'januar', 'februar', 'marz', 'mai', 'juni', 'juli', 'oktober', 'dezember')

        domains = self.domain.split('.')
        words = ('default', 'dkim', 'dk', 'domain', 'domainkey', 'test', 'selector', 
            'mail', 'smtp', 'dns', 'key', 'sign', 'signing', 'auth', 'sel', 'google', 
            'shopify.com'
        ) + tuple(domains) + config['uncommon_words']

        selectors = []

        # Set 0: All collected domains
        selectors.extend(self.getAllPossibleDomainNames())

        # Set 1: User-defined
        try:
            if self.dkimSelectorsList:
                with open(self.dkimSelectorsList, 'r') as f:
                    for l in f.readlines():
                        selectors.append(l.strip())
        except IOError:
            err('Could not open DKIM selectors list file.')
            sys.exit(-1)

        # Set 2: Common words permutations
        for w in words:
            selectors.append('{}'.format(w))
            selectors.append('_{}'.format(w))
            selectors.append('{}_'.format(w))

            for i in range(0, 11):
                if not config['dkim_full_enumeration']:
                    break

                selectors.append('{}{}'.format(w, i))
                selectors.append('{}{:02d}'.format(w, i))


        if config['dkim_full_enumeration']:
            nowTime = datetime.datetime.now()
            currYear = nowTime.year
            yearsRange = range(currYear - 2, currYear + 1)

            # Set 3: Year-Month text permutations
            for m in months:
                for yr in yearsRange:
                    ms = (
                        m[:3],
                        m,
                        '%d' % yr,
                        '%s%d' % (m, yr),
                        '%s%d' % (m[:3], yr),
                        '%s%d' % (m, (yr - 2000)),
                        '%s%d' % (m[:3], (yr - 2000)),
                        '%d%s' % (yr, m),
                        '%d%s' % (yr, m[:3]),
                        '%d%s' % ((yr - 2000), m),
                        '%d%s' % ((yr - 2000), m[:3]),
                    )
                    selectors.extend(ms)

            currTimeFormats = (
                '%Y%m%d',
                '%Y%d%m',
                '%d%m%Y',
                '%m%d%Y',
                '%Y',
                '%m',
                '%Y%m',
                '%m%Y'
            )

            # Set 4: Year-Month-Day date permutations
            for f in currTimeFormats:
                selectors.append(nowTime.strftime(f))

                for yr in yearsRange:
                    for j in range(1,13):
                        for k in range(1, 32):
                            try:
                                t = datetime.datetime(yr, j, k)
                                selectors.append(t.strftime(f))
                                selectors.append('%d' % (time.mktime(t.timetuple())))
                            except: 
                                pass

        dbg('Generated: {} selectors to review.'.format(len(selectors)))
        return selectors
        

    #
    # ===========================
    # DMARC TESTS
    #

    def evaluateDmarc(self, dmarc, spf, dkim):
        lack = []
        if not spf: lack.append('SPF')
        if not dkim: lack.append('DKIM')
        if dmarc and lack:
            fail('UNSECURE: DMARC cannot work without {} being set.'.format(', '.join(lack)))
            # Return anyway...
            #return False

        return dmarc

    def dmarcTest(self):
        ret = False
        found = False

        records = []
        
        for domain in self.getDomainsToReviewDNS():
            domain = '_dmarc.' + domain
            try:
                for txt in resolver.query(domain, 'TXT'):
                    txt = txt.to_text().replace('"', '')
                    if txt.lower().startswith('v=dmarc'):
                        info('Found DMARC record: "{}"'.format(txt))
                        ret = self.processDmarc(txt)
                        records.append(txt)
                        found = True
                        break

            except (resolver.NXDOMAIN, 
                resolver.NoAnswer, 
                resolver.NoNameservers):
                pass

            if ret: break

        if ret: 
            ok('SECURE: DMARC test passed.')
            _out('\tRecords: "{}"'.format('", "'.join(records)))

        elif found and not ret:
            fail('UNSECURE: DMARC tets not passed.')
        else: 
            fail('UNSECURE: DMARC record is missing.')

        return ret

    def processDmarc(self, record):
        parser = DmarcParser()
        return parser.processDmarc(record)

    def generateUserNamesList(self, permute = True):
        users = []

        common_ones = ('all', 'admin', 'mail', 'test', 'guest', 'root', 'spam', 'catchall', 
                    'abuse', 'contact', 'administrator', 'email', 'help', 'post', 'postmaster',
                    'rekrutacja', 'recruitment', 'pomoc', 'ayuda', 'exchange', 'relay',
                    'hilfe', 'nobody', 'anonymous', 'security', 'press', 'media', 'user', 
                    'foo', 'robot', 'av', 'antivirus', 'gate', 'gateway', 'job', 'praca', 
                    'it', 'auto', 'account', 'hr', 'db', 'web')

        if not permute:
            return common_ones

        words = common_ones + config['uncommon_words']

        # Set 1: User-defined
        try:
            if self.userNamesList:
                with open(self.userNamesList, 'r') as f:
                    for l in f.readlines():
                        users.append(l.strip())

            info('Read {} lines from users list.'.format(len(users)), toOutLine = True)
            return users

        except IOError:
            err('Could not open user names list file.', toOutLine = True)
            sys.exit(-1)

        # Set 2: Common words permutations
        for w in words:
            users.append('{}'.format(w))

            for i in range(0, 11):
                users.append('{}{}'.format(w, i))
                users.append('{}{:02d}'.format(w, i))

        dbg('Generated list of {} user names to test.'.format(len(users)))

        return users
        
    #
    # ===========================
    # EXPN TESTS
    #
    def expnTest(self, attackMode = False):
        i = 0
        maxFailures = 64
        failures = 0

        secureConfigurationCodes = (252, 500, 502)
        unsecureConfigurationCodes = (250, 251, 550, 551, 553)

        userNamesList = set(self.generateUserNamesList(permute = attackMode))
        foundUserNames = set()

        info('Attempting EXPN test, be patient - it may take a longer while...')

        try:
            for user in userNamesList:
                if config['max_enumerations'] > -1 and i >= config['max_enumerations']: 
                    dbg('Max enumerations exceeded accepted limit.')
                    if not attackMode: return False
                    else: return list(foundUserNames )

                if not attackMode and failures >= maxFailures:
                    err('FAILED: EXPN test failed too many times.')
                    return None

                out = self.sendcmd('EXPN {}'.format(user))

                if out[0] in secureConfigurationCodes \
                    or (out[0] == 550 and 'access denied' in out[1].lower()):
                    ok('SECURE: EXPN could not be used for user enumeration.')
                    _out('\tReturned: {} ({})'.format(out[0], out[1].decode()))
                    if not attackMode: return True
                    else: return list(foundUserNames)

                elif out[0] in unsecureConfigurationCodes:
                    if not attackMode:
                        fail('UNSECURE: "EXPN {}": allows user enumeration!'.format(
                            user
                        ))
                        _out('\tReturned: {} ({})'.format(out[0], out[1].decode()))
                        return False
                    else:
                        ok('Found new user: {}@{}'.format(rcptTo, self.getMailDomain()), toOutLine = True)
                        _out('\tReturned: {} ({})'.format(out[0], out[1].decode()))
                        foundUserNames.add(rcptTo)

                elif (out[0] == False and out[1] == False) or not out[1]:
                    info('UNKNOWN: During EXPN test the server disconnected. This might be secure.')
                    if not attackMode: return None
                    else: return list(foundUserNames)

                else:
                    dbg('Other return code: {}'.format(out[0]))
                    failures += 1

                i += 1

        except KeyboardInterrupt:
            info('EXPN Attack interrupted.', toOutLine = True)

        if not attackMode:
            ok('SECURE: EXPN test succeeded, yielding secure configuration.')
            return True
        else:
            ok('EXPN Attack finished. Found: {} / {}'.format(
                len(foundUserNames), 
                len(userNamesList)
            ), toOutLine = True)
            return list(foundUserNames)
        

    #
    # ===========================
    # RCPT TO TESTS
    #
    def rcptToTests(self, attackMode = False):
        i = 0
        maxFailures = 256
        failures = 0

        unsecureConfigurationCodes = (250, )
        secureConfigurationCodes = (530, 553, 550)

        userNamesList = set(self.generateUserNamesList(permute = attackMode))
        foundUserNames = set()

        info('Attempting RCPT TO test, be patient - it takes a longer while...')

        for mailFrom in userNamesList:
            if not attackMode and failures >= maxFailures:
                err('FAILED: RCPT TO test failed too many times.')
                return None

            if config['max_enumerations'] > -1 and i >= config['max_enumerations']: 
                dbg('Max enumerations exceeded accepted limit.')
                if not attackMode: return False
                else: return list(foundUserNames )

            out = self.sendcmd('MAIL FROM: <{}@{}>'.format(
                mailFrom, self.getMailDomain()
            ))
            dbg('MAIL FROM returned: ({})'.format(out))

            if out and out[0] in (250,):
                dbg('Sender ok. Proceeding...')

            elif out[0] in (530, ):
                # 530: 5.7.1 Client was not authenticated
                ok('SECURE: SMTP server requires prior authentication when using RCPT TO.')
                _out('\tReturned: ("{}")'.format(out[1].decode()))
                if not attackMode: return True
                else: return list(foundUserNames)

            elif (out[0] == 503 and '5.5.1' in out[1] and 'sender' in out[1].lower() and 'specified' in out[1].lower()):
                # 503, 5.5.1 Sender already specified
                failures += 1
                continue
                
            elif out[0] in (503, ):
                # 503: 5.5.2 Send Hello first
                self.connect(quiet = True, sayHello = True)
                failures += 1
                continue

            elif (out[0] == False and out[1] == False) or not out[1]:
                info('UNKNOWN: During RCPT TO the server has disconnected. This might be secure.')
                if not attackMode: return None
                else: return list(foundUserNames)

            else:
                dbg('Server returned unexpected response in RCPT TO: {}'.format(out))
                failures += 1
                continue

            i = 0
            failures = 0

            try:
                for rcptTo in userNamesList:
                    if mailFrom == rcptTo: continue

                    if attackMode:
                        perc = float(i) / float(len(userNamesList)) * 100.0
                        if i % (len(userNamesList) / 10) == 0 and i > 0:
                            info('RCPT TO test progress: {:02.2f}% - {:04} / {:04}'.format(
                                perc, i, len(userNamesList)), toOutLine = True)

                    if config['max_enumerations'] > -1 and i >= config['max_enumerations']: 
                        dbg('Max enumerations exceeded accepted limit.')
                        if not attackMode: return None
                        else: return list(foundUserNames)

                    if not attackMode and failures >= maxFailures:
                        err('FAILED: RCPT TO test failed too many times.')
                        return None

                    out = self.sendcmd('RCPT TO: <{}@{}>'.format(
                        rcptTo, self.getMailDomain()
                    ))
                    dbg('RCTP TO returned: ({})'.format(out))

                    if out and out[0] in unsecureConfigurationCodes:
                        if not attackMode: 
                            fail('UNSECURE: "RCPT TO" potentially allows user enumeration: ({}, {})'.format(
                                out[0], out[1].decode()
                            ))
                            return False
                        elif rcptTo not in foundUserNames: 
                            ok('Found new user: {}@{}'.format(rcptTo, self.getMailDomain()), toOutLine = True)
                            _out('\tReturned: {} ({})'.format(out[0], out[1].decode()))
                            foundUserNames.add(rcptTo)

                    elif out and out[0] in secureConfigurationCodes:
                        if SmtpTester.ifMessageLike(out, (550, ), ('user', 'unknown', 'recipient', 'rejected'), 2):
                            if not attackMode: 
                                info('Warning: RCPT TO may be possible: {} ({})'.format(out[0], out[1].decode()))
                        
                        #
                        # Can't decided, whether error code shall be treated as RCPT TO disabled message or
                        # as an implication that wrong recipient's address was tried. Therefore, we disable the below
                        # logic making it try every user name in generated list, until something pops up.
                        #
                        #else:
                        #    ok('SECURE: Server disallows user enumeration via RCPT TO method.')
                        #    _out('\tReturned: {} ({})'.format(out[0], out[1].decode()))
                        #    if not attackMode: return False
                        #    else: return list(foundUserNames)

                    elif (out[0] == False and out[1] == False) or not out[1]:
                        info('UNKNOWN: During RCPT TO test the server has disconnected. This might be secure.')
                        if not attackMode: return None
                        else: return list(foundUserNames)

                    else:
                        dbg('Other return code: {}'.format(out[0]))
                        failures += 1

                    i += 1

                if attackMode:
                    break

            except KeyboardInterrupt:
                info('RCPT TO Attack interrupted.', toOutLine = True)
                break

            
        if not attackMode:
            ok('SECURE: RCPT TO test succeeded, yielding secure configuration.')
            return True
        else:
            ok('RCPT TO Attack finished. Found: {} / {}'.format(
                len(foundUserNames), 
                len(userNamesList)
            ), toOutLine = True)
            return list(foundUserNames)


    #
    # ===========================
    # VRFY TESTS
    #
    def vrfyTest(self, attackMode = False):
        i = 0
        maxFailures = 64
        failures = 0

        unsecureConfigurationCodes = (250, 251, 550, 551, 553)
        secureConfigurationCodes = (252, 500, 502, 535)

        userNamesList = set(self.generateUserNamesList(permute = attackMode))
        foundUserNames = set()

        info('Attempting VRFY test, be patient - it may take a longer while...')

        try:
            for user in userNamesList:
                if config['max_enumerations'] > -1 and i >= config['max_enumerations']: 
                    dbg('Max enumerations exceeded accepted limit.')
                    if not attackMode: return False
                    else: return list(foundUserNames)

                if not attackMode and failures >= maxFailures:
                    dbg('Failures exceeded maximum failures limit.')
                    return None

                out = self.sendcmd('VRFY {}'.format(user))

                if out[0] in secureConfigurationCodes \
                    or (out[0] == 550 and 'access denied' in out[1].lower()):
                    comm = ''
                    if out[0] == 535:
                        comm = 'unauthenticated '
                    ok('SECURE: VRFY disallows {}user enumeration.'.format(comm))
                    _out('\tReturned: {} ({})'.format(out[0], out[1].decode()))

                    if not attackMode: return True
                    else: return list(foundUserNames)

                elif out[0] in unsecureConfigurationCodes:
                    if not attackMode:
                        fail('UNSECURE: "VRFY {}": allows user enumeration!'.format(
                            user
                        ))
                        _out('\tReturned: {} ({})'.format(out[0], out[1].decode()))
                        return False
                    else:
                        ok('Found new user: {}@{}'.format(rcptTo, self.getMailDomain()), toOutLine = True)
                        _out('\tReturned: {} ({})'.format(out[0], out[1].decode()))
                        foundUserNames.add(rcptTo)

                elif (out[0] == False and out[1] == False) or not out[1]:
                    info('UNKNOWN: During VRFY test the server has disconnected. This might be secure.')
                    if not attackMode: return None
                    else: return list(foundUserNames)

                else:
                    dbg('Other return code: {}'.format(out[0]))
                    failures += 1

                i += 1

        except KeyboardInterrupt:
            info('Attack interrupted.', toOutLine = True)

        if not attackMode:
            ok('SECURE: VRFY test succeeded, yielding secure configuration.')
            return True
        else:
            ok('VRFY Attack finished. Found: {} / {}'.format(
                len(foundUserNames), 
                len(userNamesList)
            ), toOutLine = True)
            return list(foundUserNames)
        

    #
    # ===========================
    # OPEN-RELAY TESTS
    #
    def openRelayTest(self):
        if self.connect(quiet = True, sayHello = True):            
            results = {}

            internalDomain = self.getMailDomain()
            externalDomain = config['smtp_external_domain']

            ip = '[{}]'.format(self.resolvedIPAddress)
            if not self.resolvedIPAddress:
                ip = '[{}]'.format(self.originalHostname)

            srvname = self.localHostname
            domain = self.originalHostname

            if domain == srvname:
                domain = self.getMailDomain()

            dbg('Attempting open relay tests. Using following parameters:\n\tinternalDomain = {}\n\texternalDomain = {}\n\tdomain = {}\n\tsrvname = {}\n\tip = {}'.format(
                internalDomain, externalDomain, domain, srvname, ip
            ))

            domains = {
                'internal -> internal'  : [internalDomain, internalDomain],
                'srvname -> internal'   : [srvname, internalDomain],
                'internal -> external'  : [internalDomain, externalDomain],
                'external -> internal'  : [externalDomain, internalDomain],
                'external -> external'  : [externalDomain, externalDomain],

                'user@localhost -> external'  : ['localhost', externalDomain],

                #'empty -> empty'        : ['', ''],
                'empty -> internal'     : ['', internalDomain],
                'empty -> external'     : ['', externalDomain],
                'ip -> internal'        : [ip, internalDomain],
                'ip -> to%domain@[ip]'  : [ip, '<USER>%{}@{}'.format(domain, ip)],
                'ip -> to%domain@srvname': [ip, '<USER>%{}@{}'.format(domain, srvname)],
                'ip -> to%domain@[srvname]': [ip, '<USER>%{}@[{}]'.format(domain, srvname)],
                'ip -> "to@domain"'     : [ip, '"<USER>@{}"'.format(domain)],
                'ip -> "to%domain"'     : [ip, '"<USER>%{}"'.format(domain)],
                'ip -> to@domain@[ip]'  : [ip, '<USER>@{}@{}'.format(domain, ip)],
                'ip -> to@domain@'      : [ip, '<USER>@{}@'.format(domain)],
                'ip -> "to@domain"@[ip]': [ip, '"<USER>@{}"@{}'.format(domain, ip)],
                'ip -> to@domain@srvname': [ip, '<USER>@{}@{}'.format(domain,srvname)],
                'ip -> @[ip]:to@domain' : [ip, '@{}:<USER>@{}'.format(ip, domain)],
                'ip -> @srvname:to@domain': [ip, '@{}:<USER>@{}'.format(srvname, domain)],
                'ip -> domain!to'       : [ip, '{}!<USER>'.format(domain)],
                'ip -> domain!to@[ip]'  : [ip, '{}!<USER>@{}'.format(domain, ip)],
                'ip -> domain!to@srvname': [ip, '{}!<USER>@{}'.format(domain,srvname)],
            }

            dbg('Performing Open-Relay tests...')

            interrupted = False

            try:
                if (self.openRelayParams[0] != '' and self.openRelayParams[1] != '') and \
                    ('@' in self.openRelayParams[0] and '@' in self.openRelayParams[1]):
                        info('Running custom test: (from: <{}>) => (to: <{}>)'.format(
                            self.openRelayParams[0], self.openRelayParams[1]
                        ), toOutLine = True)
                        results['custom'] = self._openRelayTest('custom', self.openRelayParams)
                else:
                    avoidMailFrom = False
                    rollBackSenderOnce = False

                    num = 0
                    for k, v in domains.items():
                        if self.stopEverything: break
                        num += 1
                        results[k] = False

                        retry = 0
                        for i in range(2):
                            if self.stopEverything: break
                            dbg('Attempting Open-Relay test #{}: "{}"'.format(num, k))
                            results[k] = self._openRelayTest(k, v, avoidMailFrom, num)

                            if results[k] == 554 and not rollBackSenderOnce:
                                dbg('Rolling back to traditional sender\'s address: @{}'.format(internalDomain))
                                rollBackSenderOnce = True

                                for d, v in domains.items():
                                    if d.startswith('ip -> '):
                                        domains[d] = [internalDomain, v[1]]

                            #elif (results[k] == 503 or results[k] == 501) and not avoidMailFrom:
                            #    dbg('Will not send MAIL FROM anymore.')
                            #    avoidMailFrom = True

                            elif (results[k] == 501 or results[k] == 503):
                                results[k] = False
                                dbg('Reconnecting as SMTP server stuck in repeated/invalid MAIL FROM envelope.')
                                if self.stopEverything: break
                                self.reconnect(quiet = True)
                                results[k] = self._openRelayTest(k, v, avoidMailFrom, num)
                                continue
                            break
            except KeyboardInterrupt:
                interrupted = True
                info('Open-Relay tests interrupted by user!')

            if not config['always_unfolded_results'] and all(results.values()):
                ok('SECURE: Open-Relay seems not to be possible as proved after {} tests.'.format(len(results)))
                return True
            else:
                sumOfValues = 0
                for k, v in results.items():
                    dbg('Open-Relay test ({}) resulted with: {}'.format(
                        k, v
                    ))
                    if v == False: 
                        sumOfValues += 1

                appendix = ''
                if sumOfValues != len(results):
                    appendix = '\tThe rest of tests failed at some point, without any status.'

                if interrupted:
                    sumOfValues = 1 if sumOfValues < 1 else sumOfValues
                    appendix = '\tTests were interrupted thus dunno whether the server is open-relaying or not.'
                    _out('[?] UNKNOWN: Open-Relay were interrupted after {}/{} carried tests.'.format(
                        sumOfValues - 1, len(results)
                    ), True, colors.fg.pink)
                else:
                    fail('UNSECURE: Open-Relay MAY BE possible as turned out after {}/{} successful tests.'.format(
                        sumOfValues, len(results)
                    ))

                if appendix:
                    _out(appendix, True, colors.fg.pink)
                    
                return results
        else:
            fail('FAILED: Could not reconnect for Open-Relay testing purposes.')

        return None 

    @staticmethod
    def _extractMailAddress(param, baseName = ''):
        '''
        @param param    - specifies target SMTP domain
        @param baseName - specifies target mail username 
        '''

        surnames = ['John Doe', 'Mike Smith', 'William Dafoe', 'Henry Mitchell']

        if not param:
            return '', ''

        base = 'test{}'.format(random.randint(0, 9))
        if baseName:
            base = baseName

            # Format: test@test.com
            m = re.match(r"(^[a-zA-Z0-9_.+-]+)@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", baseName)
            if m:
                base = m.group(1)

        if '<USER>' in param:
            param = param.replace('<USER>', base)

        addr = '{}@{}'.format(base, param)
        if '@' in param and param.count('@') == 1:
            addr = param
            param = param.split('@')[1]

        elif '@' in param and param.count('@') > 1:
            return param, param

        mail = '"{}" <{}>'.format(random.choice(surnames), addr)

        # Format: test@test.com
        m = re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", param)
        if m:
            addr = m.group(1)
            mail = '"{}" <{}>'.format(random.choice(surnames), addr)
            return addr, mail

        # Format: "John Doe" <test@test.com>
        m = re.match(r'(^\"([^\"]+)\"[\s,]+<([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)>$)', param)
        if m:
            addr = m.group(3)
            mail = '"{}" <{}>'.format(m.group(2), addr)
            return addr, mail

        return addr, mail

    @staticmethod
    def extractMailAddress(param, baseName = ''):
        dbg('Extracting mail address from parameter: "{}", according to base: "{}"'.format(
            param, baseName
        ))

        addr, mail = SmtpTester._extractMailAddress(param, baseName)

        dbg('After extraction: addr="{}", mail="{}"'.format(
            addr, mail
        ))

        return addr, mail


    def _openRelayTest(self, testName, twoDomains, avoidMailFrom = False, num = 0, doNotSendAndTest = False):
        secureConfigurationCodes = (221, 454, 500, 501, 503, 504, 530, 550, 554, )
        now = datetime.datetime.now()

        # If True - secure configuration, could not send via open-relay
        result = None

        fromAddr, fromMail = SmtpTester.extractMailAddress(twoDomains[0], self.openRelayParams[0])
        toAddr, toMail = SmtpTester.extractMailAddress(twoDomains[1], self.openRelayParams[1])

        if testName == 'custom':
            info('Performing custom Open-Relay test from: {}, to: {}'.format(
                fromMail, toMail
            ))

        dateNow = now.strftime("%a, %d %b %Y %H:%m:%S")
        subject = 'Open-Relay test #{}: {}'.format(num, testName)

        mailFromReturn = ''
        rcptToReturn = ''
        dataReturn = ''

        mailCommands = (
            'MAIL From: ' + fromAddr,
            'RCPT To: ' + toAddr,
            'DATA',
            '<HERE-COMES-MESSAGE>'
        )

        message = '''From: {fromMail}
To: {toMail}
Subject: {subject}
Date: {dateNow}

Warning!

This is a test mail coming from 'smtpAudit.py' tool.

If you see this message it means that your SMTP server is *vulnerable* to Open-Relay spam technique (https://en.wikipedia.org/wiki/Open_mail_relay). Unauthorized users will be able to make your server send messages in a name of other mail users.

You may want to contact with your mail administrator and pass him with the following informations:

--------------------8<--------------------
Open-Relay test name: "{testName}"

MAIL From: {fromAddr}
    Server response: {mailFromReturn}
RCPT To: {toAddr}
    Server response: {rcptToReturn}
DATA
    Server response: {dataReturn}

Subject: "{subject}"
Date: {dateNow}
--------------------8<--------------------

smtpAudit.py ({VERSION}) - SMTP Server penetration testing / audit tool,
(https://gist.github.com/mgeeky/ef49e5fb6c3479dd6a24eb90b53f9baa)
by Mariusz Banach / mgeeky (<mb@binary-offensive.com>)
.
'''

        n = 0
        out = None
        for line in mailCommands:
            if self.stopEverything: break

            if avoidMailFrom and line.startswith('MAIL From:'):
                dbg('Skipping MAIL From: line.')
                continue

            n += 1

            if line.startswith('DATA') and doNotSendAndTest:
                break

            if line == '<HERE-COMES-MESSAGE>':
                line = message.format(
                    fromMail = fromMail, 
                    toMail = toMail, 
                    subject = subject, 
                    dateNow = dateNow, 
                    fromAddr = fromAddr, 
                    toAddr = toAddr, 
                    testName = testName, 
                    VERSION = VERSION,
                    mailFromReturn = mailFromReturn,
                    rcptToReturn = rcptToReturn,
                    dataReturn = dataReturn
                )

            out = self.sendcmd(line)
            msg = out[1].decode().lower()

            if line.startswith('MAIL From'): 
                mailFromReturn = '{} ({})'.format(out[0], out[1].decode())
            if line.startswith('RCPT To'): 
                rcptToReturn = '{} ({})'.format(out[0], out[1].decode())
            if line.startswith('DATA'): 
                dataReturn = '{} ({})'.format(out[0], out[1].decode())

            if 'rcpt to' in line.lower():
                _out('[>] Open-Relay test (from: <{}>) => (to: <{}>); returned: {} ({})'.format(
                    fromAddr, toAddr, out[0], out[1].decode()
                ), False, colors.fg.pink)

            elif out[0] == 221 and 'can' in msg and 'break' in msg and 'rules' in msg:
                # 221 (2.7.0 Error: I can break rules, too. Goodbye.)
                result = True

            if out[0] == 501 and 'mail from' in msg and 'already' in msg:
                # 501 (5.5.1 MAIL FROM already established)
                return 501

            elif out[0] == 503 and 'nested' in msg and 'mail' in msg:
                # 503 (5.5.1 Error: nested MAIL command)
                return 503

            elif out[0] == 503 and 'already' in msg and 'specified' in msg:
                # 503 (5.5.1 Sender already specified)
                #return 503
                continue

            elif out[0] == 554 and 'bad' in msg and 'sender' in msg and 'addr' in msg:
                # 554 (5.7.1 Bad senders system address)
                dbg('Bad sender\'s address. Rolling back.')
                return 554

            elif (out[0] == 550 or out[0] == 530) and self.processResponseForAcceptedDomainsFailure(out):
                # 530 (5.7.1 Client was not authenticated).
                # 550 (5.7.1 Client does not have permissions to send as this sender).
                info('Microsoft Exchange Accepted Domains mechanism properly rejects us from relaying. Splendid.')
                result = True

            elif out[0] == 550 and self.processResponseForSpfFailure(out):
                # 550 (5.7.1 Recipient address rejected: Message rejected due to: SPF fail - not authorized).
                info('SPF properly rejects us from relaying. Splendid.')
                result = True

            elif not out or not out[0] or not out[1] or out[0] in secureConfigurationCodes:
                if line.startswith('From: '):
                    info('Open-Relay {} MAY be possible: the server hanged up on us after invalid "From:" (step: {})'.format(
                        testName, n
                    ), toOutLine = True)
                    info('\tThis means, that upon receiving existing From/To addresses - server could allow for Open-Relay.', toOutLine = True)
                    info('\tTo further analyse this issue - increase verbosity and choose another "--from" or "--to" parameters.', toOutLine = True)
                    result = None
                else:
                    dbg('Open-Relay {} test failed at step {}: {}.'.format(
                        testName, n, line.strip()
                    ))
                    result = True
                break

            dbg('Open-Relay {} test DID NOT failed at step {}: {}. Response: {}'.format(
                testName, n, line.strip(), str(out)
            ))

        verdict = 'most likely'
        if out[0] == 250:
            verdict = 'TOTALLY'

        if doNotSendAndTest:
            return True

        if result != True and out[0] < 500:
            fail('UNSECURE: Open-Relay {} is {} possible.'.format(
                testName, verdict
            ))
            _out('\tReturned: {} ("{}")'.format(out[0], out[1].decode()))

            result = False

        elif (result == False and not out[0]) or result == None:
            fail('UNKNOWN: Server has disconnected after the Open-Relay ({}) test. Most likely secure.'.format(testName))
            result = None

        else:
            if 'relaying denied' in out[1].decode().lower():
                #  (550, b'5.7.1 Relaying denied')
                ok('SECURE: Open-Relay attempt "{}" was denied.'.format(testName))
            else:
                info('Open-Relay "{}" seems not to be possible.'.format(
                    testName
                ))
            try:
                _out('\tReturned: {} ({})'.format(out[0], out[1].decode()))
            except:
                _out('\tReturned: ({})'.format(str(out)))

            result = True

        return result


    #
    # ===========================
    # SSL AUTH ENFORCEMENT TESTS
    #
    def starttlsOffer(self):
        if not self.availableServices:
            self.getAvailableServices()
            if not self.availableServices:
                fail('UNKNOWN: Could not collect available SMTP services')
                return None

        ret = ('starttls' in map(lambda x: x.lower(), self.availableServices))

        if ret or self.ssl: 
            ok('SECURE: STARTTLS is offered by SMTP server.')
        else:
            dbg('Trying to send STARTTLS by hand')
            out = self.sendcmd('STARTTLS', nowrap = True)

            if out[0] == 220:
                ok('SECURE: STARTTLS is supported, but not offered at first sight.')
                ret = True

                self.connect(quiet = True)

            else:
                fail('UNSECURE: STARTTLS is NOT offered by SMTP server.')

        return ret

    #
    # ===========================
    # SSL AUTH ENFORCEMENT TESTS
    #

    def testSSLAuthEnforcement(self):
        for service in SmtpTester.smtpAuthServices:
            ret = self.testSSLAuthEnforcementForService(service)
            if ret == False:
                return ret

        return True

    def testSSLAuthEnforcementForService(self, service):
        authMethods = self.getAuthMethods(service)
        ret = True
        emptyMethods = False

        notSupportedCodes = (500, 502, 503, 504, 535)
        unsecureConfigurationCodes = ()

        for authMethod in authMethods:
            if authMethod.upper() == 'NTLM':
                _out('[?] This may be a Microsoft Exchange receive connector offering Integrated Windows Authentication service.', True, colors.fg.pink)

            if authMethod.upper() == 'GSSAPI':
                _out('[?] This may be a Microsoft Exchange receive connector offering Exchange Server authentication service over Generic Security Services application programming interface (GSSAPI) and Mutual GSSAPI authentication.', True, colors.fg.pink)

        if not authMethods:
            emptyMethods = True
            authMethods = SmtpTester.commonSmtpAuthMethods.keys()

        for authMethod in authMethods:
            dbg("Checking authentication method: {}".format(authMethod))

            if authMethod.upper() in SmtpTester.authMethodsNotNeedingStarttls:
                dbg('Method {} does not need to be issued after STARTTLS.'.format(
                    authMethod.upper()
                ))
                #continue

            auths = []
            _auth = '{} {}'.format(service, authMethod)

            if authMethod in SmtpTester.commonSmtpAuthMethods.keys():
                param = SmtpTester.commonSmtpAuthMethods[authMethod]

                if isinstance(param, bytes): param = param.decode()

                if isinstance(param, str):
                    _auth += ' ' + param
                    auths.append(_auth)
                elif isinstance(param, list) or isinstance(param, tuple):
                    for n in param:
                        if isinstance(param, bytes): n = n.decode()

                        if isinstance(n, str):
                            auths.append(_auth)
                            n = base64.b64encode(n.replace('DOMAIN.COM', self.originalHostname).encode())
                            auths.append(n)
                        elif isinstance(n, list) or isinstance(n, tuple):
                            auths.append(_auth)
                            for m in n:
                                if isinstance(m, bytes): m = m.decode()

                                if 'DOMAIN.COM' in m:
                                    m = base64.b64encode(m.replace('DOMAIN.COM', self.originalHostname).encode())
                                auths.append(m)

            index = 0
            for index in range(len(auths)):
                auth = auths[index]
                out = self.sendcmd(auth, nowrap = True)

                dbg('The server responded for {} command with: ({})'.format(auth, str(out)))

                if not out or out[0] == False:
                    dbg('Something gone wrong along the way.')

                elif out and out[0] in notSupportedCodes:
                    dbg('The {} {} method is either not supported or not available.'.format(
                        service, authMethod
                    ))
                    index += 1

                elif not out[0] and not out[1]:
                    info('The server disconnected during {} {}, this might be secure.'.format(
                        service, authMethod
                    ))

                elif out[0] == 454:
                    # 4.7.0 TLS not available due to local problem
                    fail('UNSECURE: STARTTLS seems to be not available on the server side.')
                    _out('\tReturned: {} ("{}")'.format(out[0], out[1].decode()))
                    return False

                elif out[0] == 334:
                    # 334 base64 encoded User then Password prompt
                    if out[1].decode() == 'VXNlcm5hbWU6':
                        dbg('During LOGIN process the server enticed to carry on')

                    elif out[1].decode() == 'UGFzc3dvcmQ6':
                        if not self.ssl:
                            fail('UNSECURE: Server allowed authentication over non-SSL channel via "{} {}"!'.format(
                                service, authMethod
                            ))
                            _out('\tReturned: {} ("{}")'.format(out[0], out[1].decode()))
                            return False

                    else:
                        dbg('The {} {} method is not understood.: ({})'.format(
                            service, authMethod, str(out)
                        ))

                elif out and not (out[0] in (530, ) and b'starttls' in out[1].lower()):
                    fail('UNSECURE: For method "{} {}" the server did not required STARTTLS!'.format(
                        service, authMethod
                    ))
                    _out('\tReturned: {} ("{}")'.format(out[0], out[1].decode()))
                    return False

                elif out and (out[0] == 530 and b'STARTTLS' in out[1]):
                    ok('SECURE: Server enforces SSL/TLS channel negotation before {}.'.format(
                        service
                    ))
                    _out('\tReturned: {} ("{}")'.format(out[0], out[1].decode()))
                    return True

        if set(authMethods) <= set(SmtpTester.authMethodsNotNeedingStarttls):
            ok('SECURE: There were no {} methods requiring STARTTLS.'.format(service))
            return True

        if emptyMethods:
            info('The server does not offer any {} methods to enforce.'.format(
                service
            ))
        else:
            info('UNKNOWN: None of tested {} methods yielded any result (among: {}).'.format(
                service, ', '.join(authMethods)
            ))

        return None


    #
    # ===========================
    # SSL/TLS UNSECURE CIPHERS TESTS
    #
    def testSecureCiphers(self):
        performedStarttls = False
        if not self.starttlsSucceeded:
            dbg('STARTTLS session has not been set yet. Setting up...')
            performedStarttls = self.performStarttls()

        if not self.ssl and not performedStarttls and not self.starttlsSucceeded:
            err('Could not initiate successful STARTTLS session. Failure')
            return None

        try:
            cipherUsed = self.server_tls_params['cipher']
            version = self.server_tls_params['version']
        except (KeyError, AttributeError):
            err('Could not initiate successful STARTTLS session. Failure')
            return None
        
        dbg('Offered cipher: {} and version: {}'.format(cipherUsed, version))

        if cipherUsed[0].upper() in SmtpTester.secureCipherSuitesList:
            ok('SECURE: Offered cipher is considered secure.')
            _out('\tCipher: {}'.format(cipherUsed[0]))
            return True


        for secureCipher in SmtpTester.secureCipherSuitesList:
            ciphers = set(secureCipher.split('-'))
            cipherUsedSet = set(cipherUsed[0].upper().split('-'))

            intersection = ciphers.intersection(cipherUsedSet)
            minWords = min(len(ciphers), len(cipherUsedSet))
            if minWords >= 3 and len(intersection) >= (minWords - 1):
                ok('SECURE: Offered cipher is having secure structure.')
                _out('\tCipher: {}'.format(cipherUsed))

                return True

        unsecureCiphers = ('RC4', '3DES', 'DES', )
        usedUnsecureCipher = ''
        
        for cipher in unsecureCiphers:
            if cipher in cipherUsed[0].upper():
                fail('SMTP Server offered unsecure cipher.')
                _out('\tCipher: {}'.format(cipher))
                return False

        usedSSL = 'ssl' in version.lower()

        unsecureSSLs = ('sslv2', 'sslv3')
        if 'shared_ciphers' in self.server_tls_params.keys():
            unsecureProtocolsOffered = set()
            for s in self.server_tls_params['shared_ciphers']:
                dbg('Offered cipher (22222): {}'.format(s[1]))
                if s[1].lower() in unsecureSSLs:
                    unsecureProtocolsOffered.add(s[1])

            if len(unsecureProtocolsOffered) > 0:
                out = ', '.join(unsecureProtocolsOffered)

                fail('SMTP Server offered unsecure SSL/TLS protocols: {}'.format(out))
                return False
        else:
            fail('No server TLS parameters obtained yet.')

        if not usedSSL and not usedUnsecureCipher:
            ok('SECURE: SMTP Server did not offered unsecure encryption suite.') 
            return True

        else:
            fail('UNSECURE: SMTP Server offered unsecure encryption suite.')
            _out('\tCipher: {}'.format(usedUnsecureCipher))
            return False


    #
    # ===========================
    # UNSECURE AUTH METHODS TESTS
    #
    def testSecureAuthMethods(self):
        success = None
        for service in SmtpTester.smtpAuthServices:
            ret = self.testSecureAuthMethodsForService(service)
            if ret == False:
                return ret
            elif ret == True:
                # ret may be also 'None'
                success = True

        return success

    def testSecureAuthMethodsForService(self, service):
        authMethods = self.getAuthMethods(service)

        unsecureAuthMethods = ('PLAIN', 'LOGIN')
        ret = True
        methods = set()

        if not authMethods:
            authMethods = SmtpTester.commonSmtpAuthMethods
            foundMethods = []

            dbg('The server is not offering any {} method. Going to try to discover ones.'.format(
                service
            ))

            for authMethod in authMethods:
                if authMethod in SmtpTester.authMethodsNotNeedingStarttls:
                    dbg('Method: {} {} is considered not needing STARTTLS.'.format(
                        service, authMethod
                    ))
                    continue

                auth = '{} {}'.format(service, authMethod)
                out = self.sendcmd(auth)

                if out[0] == (500, 503) or \
                    (out[1] and (b'not available' in out[1].lower() or \
                    b'not recognized' in out[1].lower())):
                    info('UNKNOWN: {} method not available at all.'.format(service))
                    return None

                elif out and out[0] in (334, ):
                    dbg('Authentication via {} is supported'.format(auth))
                    foundMethods.append(authMethod)

                    if authMethod.upper() in unsecureAuthMethods:
                        if not self.ssl:
                            fail('UNSECURE: SMTP offers plain-text authentication method: {}!'.format(
                                auth
                            ))
                        else:
                            ok('SECURE: SMTP offered plain-text authentication method over SSL: {}!'.format(
                                auth
                            ))

                        _out('\tOffered reply: {} ("{}")'.format(out[0], out[1].decode()))

                        ret = False
                        break

                if out[0] == False and out[1] == False:
                    info('UNKNOWN: The server has disconnected while checking'\
                        ' {}. This might be secure'.format(
                        auth
                    ))
                    return None

                methods = foundMethods
        else:
            for authMethod in authMethods:
                if authMethod.upper() in unsecureAuthMethods:
                    if not self.ssl:
                        fail('UNSECURE: SMTP server offers plain-text authentication method: {}.'.format(
                            authMethod
                        ))
                    else:
                        ok('SECURE: SMTP server offered plain-text authentication method over SSL: {}.'.format(
                            authMethod
                        ))

                    ret = False
                    break

            methods = authMethods

        if ret and methods:
            ok('SECURE: Among found {} methods ({}) none was plain-text.'.format(
                service, ', '.join(methods)
            ))
        elif not ret:
            pass
        elif not methods:
            info('UNKNOWN: The server does not offer any {} methods.'.format(
                service
            ))

            return None

        dbg('ret = {}, methods = {}'.format(ret, methods))

        return ret
    

    #
    # ===========================
    # SSL/TLS PRIVATE KEY LENGTH
    #
    def testSSLKeyLen(self):
        performedStarttls = False
        if not self.server_tls_params or not self.starttlsSucceeded:
            dbg('STARTTLS session has not been set yet. Setting up...')
            performedStarttls = self.performStarttls()

        if not performedStarttls and not self.starttlsSucceeded:
            err('Could not initiate successful STARTTLS session. Failure')
            return None

        try:
            cipherUsed = self.server_tls_params['cipher']
            version = self.server_tls_params['version']
            sharedCiphers = self.server_tls_params['shared_ciphers']
        except (KeyError, AttributeError):
            err('Could not initiate successful STARTTLS session. Failure')
            return None
        
        dbg('Offered cipher: {} and version: {}'.format(cipherUsed, version))

        keyLen = cipherUsed[2] * 8
        if keyLen < config['key_len']:
            fail('UNSECURE: SSL/TLS negotiated cipher\'s ({}) key length is insufficient: {} bits'.format(
                cipherUsed[0], keyLen
            ))
        elif sharedCiphers != None and len(sharedCiphers) > 0:
            for ciph in sharedCiphers:
                name, ver, length = ciph
                if length * 8 < 1024:
                    fail('UNSECURE: SMTP server offers SSL/TLS cipher suite ({}) which key length is insufficient: {} bits'.format(
                        name, keyLen
                    ))
                    return False

            ok('SECURE: SSL/TLS negotiated key length is sufficient ({} bits).'.format(
                keyLen
            ))
        else:
            fail('UNKNOWN: Something went wrong during SSL/TLS shared ciphers negotiation.')
            return None

        return keyLen >= config['key_len']


    #
    # ===========================
    # SPF VALIDATION CHECK
    #    
    def spfValidationTest(self):

        if not self.spfValidated:
            dbg('Sending half-mail to domain: "{}" to trigger SPF/Accepted Domains'.format(self.mailDomain))
            self._openRelayTest('spf-validation', ['test@' + self.getMailDomain(), 'admin@' + self.getMailDomain()], False, 0, True)

        if self.spfValidated:
            ok('SECURE: SMTP Server validates sender\'s SPF record')
            info('\tor is using MS Exchange\'s Accepted Domains mechanism.')
            _out('\tReturned: {}'.format(self.spfValidated))
            return True
        else:
            fail("UNKNOWN: SMTP Server has not been seen validating sender's SPF record.")
            info("\tIf it is Microsoft Exchange - it could have reject us via Accepted Domains mechanism using code 550 5.7.1")
            return None

    def processResponseForAcceptedDomainsFailure(self, out):
        try:
            msg = out[1].lower()

            #if out[0] == 530 and '5.7.1' in msg and 'was not authenticated' in msg:
            #    info('Looks like we might be dealing with Microsoft Exchange')
            #    return True

            if out[0] == 550 and '5.7.1' in msg and 'does not have permissions to send as this sender' in msg:
                info('Looks like we might be dealing with Microsoft Exchange')
                return True
        except:
            pass

        return False

    def processResponseForSpfFailure(self, out):
        spfErrorCodes = (250, 451, 550, 554, )
        spfErrorKnownSentences = (
            'Client host rejected: Access denied',
        )
        spfErrorKeywords = ('validat',  'host rejected', 'fail', 'reject', 'check', 'soft', 'not auth', 'openspf.net/Why')
        
        if out[0] in spfErrorCodes:
            msg = out[1].decode().strip()

            # Maybe this error is already known?
            for knownSentence in spfErrorKnownSentences:
                if knownSentence in msg:
                    dbg('SPF validation found when received well-known SPF failure error: {} ({})'.format(
                        out[0], msg
                    ))
                    return True

            found = 0
            for word in msg.split(' '):
                for k in spfErrorKeywords:
                    if k.lower() in word:
                        found += 1
                        break

            if 'spf' in msg.lower() and found >= 2:
                return True

            if found > 0:
                dbg('SPF validation possibly found but unsure ({} keywords related): {} ({})'.format(
                    found, out[0], msg
                ))

        return False

    def checkIfSpfEnforced(self, out):
        if self.spfValidated:
            return True

        if self.processResponseForSpfFailure(out):
            info('SPF validation found: {} ({})'.format(out[0], out[1].decode()))
            self.spfValidated = '{} ({})'.format(out[0], out[1].decode())
            return True

        if self.processResponseForAcceptedDomainsFailure(out):
            info('SPF validation not found but found enabled Microsoft Exchange Accepted Domains mechanism: {} ({})'.format(out[0], out[1].decode()))
            self.spfValidated = '{} ({})'.format(out[0], out[1].decode())
            return False

        return False


class ParseOptions:
    def __init__(self, argv):
        self.argv = argv
        self.domain = ''
        self.port = None
        self.userslist = ''
        self.selectors = ''
        self.forceSSL = False
        self.fromAddr = ''
        self.toAddr = ''

        self.parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <hostname[:port]|ip[:port]>')

        self.parser.add_argument('hostname', metavar='<domain|ip>', type=str,
            help='Domain address (server name, or IPv4) specifying SMTP server to scan (host:port).')

        self.parser.add_argument('-d', '--domain', metavar='DOMAIN', dest='maildomain', default='', help = 'This option can be used to specify proper and valid mail (MX) domain (what comes after @, like: example.com). It helps avoid script confusion when it automatically tries to find that mail domain and it fails (like in case IP was passed in first argument).')

        self.parser.add_argument('-v', '--verbose', dest='verbose', 
            action = 'count', default = 0, help='Increase verbosity level (use -vv or more for greater effect)')
        self.parser.add_argument('-T', '--list-tests', dest='testsHelp', action='store_true', help='List available tests.')
        self.parser.add_argument('-u', '--unfolded', dest='unfolded', default=False, action='store_true',
            help = 'Always display unfolded JSON results even if they were "secure".')
        self.parser.add_argument('-C', '--no-colors', dest = 'colors', default = True, action = 'store_false', help = 'Print without colors.')
        self.parser.add_argument('-f', '--format', metavar='FORMAT', dest='format',
            default = 'text', choices = ['text', 'json'],
            help = 'Specifies output format. Possible values: text, json. Default: text.')
        
        self.parser.add_argument('-m', '--tests', metavar='TEST', dest='testToCarry', 
            type=str,
            default = 'all', help = 'Select specific tests to conduct. For a list of tests'\
            ', launch the program with option: "{} -T tests". Add more tests after colon. (Default: run all tests).'.format(
                argv[0]
            ))

        self.parser.add_argument('-M', '--skip-test', metavar='TEST', dest='testToSkip', 
            type=str,
            default = '', help = 'Select specific tests to skip. For a list of tests'\
            ', launch the program with option: "{} -T tests". Add more tests after colon. (Default: run all tests).'.format(
                argv[0]
            ))
        
        self.parser.add_argument('-t', '--timeout', metavar="TIMEOUT", type=float, dest='timeout',
            default = config['timeout'], help='Socket timeout. (Default: {})'.format(
                config['timeout']
            ))

        self.parser.add_argument('--delay', metavar="DELAY", dest='delay', type=float,
            default = config['delay'], 
            help='Delay introduced between subsequent requests and connections. '\
            '(Default: {} secs)'.format(
                config['delay']
            ))

        # Attack options
        attack = self.parser.add_argument_group('Attacks')
        attack.add_argument('--attack', dest='attack', action='store_true', help = 'Switch to attack mode in which only enumeration techniques will be pulled off (vrfy, expn, rcpt to). You can use --tests option to specify which of them to launch.')

        attack.add_argument('-U', '--users', metavar="USERS", type=str, dest='userslist',
            default = '', help='Users list file used during enumeration tests.')

        # DKIM options
        dkim = self.parser.add_argument_group('DKIM Tests')
        dkim.add_argument('-w', '--wordlist', dest='words', default='', type=str,
           help = 'Uncommon words to be used in DKIM selectors dictionary generation. Comma separated.')
        dkim.add_argument('-D', '--selectors', metavar="SELECTORS", type=str, dest='selectors',
            default = '', help='DKIM selectors list file with custom selectors list to review.')
        dkim.add_argument('-y', '--tries', metavar="TRIES", type=int, dest='tries',
            default = -1, help='Maximum number of DNS tries/enumerations in DKIM test. (Default: all of them)')

        dkim.add_argument('--dkim-enumeration', metavar="TYPE", type=str,
            choices = ['never', 'on-ip', 'full'], dest = 'dnsenum',
            default = config['dns_full'], 
            help='When to do full-blown DNS records enumeration. Possible values: '\
            'always, on-ip, never. When on-ip means when DOMAIN was IP address. '\
            '(Default: "{}")'.format(
                config['dns_full']
            ))


        # Open-Relay options
        openRelay = self.parser.add_argument_group('Open-Relay Tests')
        openRelay.add_argument('-x', '--external-domain', dest='external_domain', metavar='DOMAIN',
            default = config['smtp_external_domain'], type=str,
            help = 'External domain to use in Open-Relay tests. (Default: "{}")'.format(
                config['smtp_external_domain']
            ))
        openRelay.add_argument('--from', dest='fromAddr', default='', type=str,
           help = 'Specifies "From:" address to be used in Open-Relay test. Possible formats: (\'test\', \'test@test.com\', \'"John Doe" <test@test.com>\'). If you specify here and in \'--to\' full email address, you are going to launch your own custom test. Otherwise, those values will be passed into username part <USER>@domain.')
        openRelay.add_argument('--to', dest='toAddr', default='', type=str,
           help = 'Specifies "To:" address to be used in Open-Relay test. Possible formats: (\'test\', \'test@test.com\', \'"John Doe" <test@test.com>\'). If you specify here and in \'--from\' full email address, you are going to launch your own custom test. Otherwise, those values will be passed into username part <USER>@domain.')

        if len(sys.argv) < 2:
            self.usage()
            sys.exit(-1)

        if config['verbose']:
            ParseOptions.banner()

        if not self.parse():
            sys.exit(-1)

    @staticmethod
    def banner():
        sys.stderr.write('''
    :: SMTP Black-Box Audit tool.
    v{}, Mariusz Banach / mgeeky, '17

'''.format(VERSION))

    def usage(self):
        ParseOptions.banner()
        self.parser.print_help()

    def parse(self):
        global config

        testsHelp = ''
        for k, v in SmtpTester.testsConducted.items():
            testsHelp += '\n\t{:20s} - {}'.format(k, v)

        if len(sys.argv) >= 2:
            if (sys.argv[1].lower() == '--list-tests') or \
                (sys.argv[1] == '-T' and len(sys.argv) >= 3 and sys.argv[2] == 'tests') or \
                (sys.argv[1] == '-T') or \
                (sys.argv[1] == '--list-tests' and len(sys.argv) >= 3 and sys.argv[2] == 'tests'):
                print('Available tests:{}'.format(testsHelp))
                sys.exit(0)

        args = self.parser.parse_args()

        if args.testsHelp:
            print('Available tests:{}'.format(testsHelp))
            sys.exit(0)

        self.domain = args.hostname
        self.userslist = args.userslist
        self.selectors = args.selectors
        self.maildomain = args.maildomain
        self.attack = args.attack

        if args.fromAddr: self.fromAddr = args.fromAddr
        if args.toAddr: self.toAddr = args.toAddr

        if ':' in args.hostname:
            self.domain, self.port = args.hostname.split(':')
            self.port = int(self.port)

        if args.verbose >= 1: config['verbose'] = True
        if args.verbose >= 2: config['debug'] = True
        if args.verbose >= 3: config['smtp_debug'] = True

        config['timeout'] = args.timeout
        config['delay'] = args.delay
        config['max_enumerations'] = args.tries
        config['dns_full'] = args.dnsenum
        config['always_unfolded_results'] = args.unfolded
        config['format'] = args.format
        config['colors'] = args.colors
        config['attack'] = args.attack

        if args.words:
            config['uncommon_words'] = args.words.split(',')

        if args.testToCarry:
            config['tests_to_carry'] = args.testToCarry.split(',')
            for c in config['tests_to_carry']:
                if c == 'all': continue
                if c not in SmtpTester.testsConducted.keys():
                    err('There is no such test as the one specified: "{}"'.format(
                        c
                    ))
                    print('\nAvailable tests:{}'.format(testsHelp))
                    sys.exit(-1)

            l = list(filter(lambda x: x != 'all', config['tests_to_carry']))
            if l:
                info('Running following tests: ' + ', '.join(l))

        if args.testToSkip:
            config['tests_to_skip'] = args.testToSkip.split(',')
            for c in config['tests_to_skip']:
                if c == '': break
                if c not in SmtpTester.testsConducted.keys():
                    err('There is no such test as the one specified: "{}"'.format(
                        c
                    ))
                    print('\nAvailable tests:{}'.format(testsHelp))
                    sys.exit(-1)

            l = list(filter(lambda x: x != '', config['tests_to_skip']))
            if l:
                info('Skipping following tests: ' + ', '.join(l))

        return True


def printResults(results, auditMode):
    if auditMode:
        if config['format'] == 'json':
            out = json.dumps(results, indent = 4)
            out = out[1:-1]
            out = out.replace('\\n', '\n')
            out = out.replace('\\', '')
            print(out)

        elif config['format'] == 'text':
            pass
    else:
        info('Results:')
        if config['format'] == 'json':
            out = json.dumps(results, indent = 4)
            out = out[1:-1]
            out = out.replace('\\n', '\n')
            out = out.replace('\\', '')
            print(out)

        else:
            for found in results:
                print(found)

    if not config['verbose'] and not config['debug']:
        sys.stderr.write('\n---\nFor more detailed output, consider enabling verbose mode.\n')


def main(argv):
    opts = ParseOptions(argv)
    domain = opts.domain
    port = opts.port 
    userslist = opts.userslist
    selectors = opts.selectors

    if config['format'] == 'text':
        sys.stderr.write('''
    :: SMTP configuration Audit / Penetration-testing tool
    Intended to be used as a black-box tool revealing security state of SMTP.
    Mariusz Banach / mgeeky, '17-19
    v{}

'''.format(VERSION))

    prev = datetime.datetime.now()
    info('SMTP Audit started at: [{}], on host: "{}"'.format(
        prev.strftime('%Y.%m.%d, %H:%M:%S'),
        socket.gethostname()
    ))
    info('Running against target: {}{}{}'.format(
        opts.domain, ':'+str(opts.port) if opts.port != None else '', 
        ' (...@' + opts.maildomain + ')' if opts.maildomain != '' else '',
    toOutLine = True))

    results = {}
    tester = SmtpTester(
        domain, 
        port, 
        dkimSelectorsList = selectors, 
        userNamesList = userslist,
        openRelayParams = (opts.fromAddr, opts.toAddr),
        mailDomain = opts.maildomain
    )

    try:
        if opts.attack:
            results = tester.runAttacks()
        else:
            results = tester.runTests()

    except KeyboardInterrupt:
        err('USER HAS INTERRUPTED THE PROGRAM.')
        if tester: 
            tester.stop()

    after = datetime.datetime.now()
    info('Audit finished at: [{}], took: [{}]'.format(
        after.strftime('%Y.%m.%d, %H:%M:%S'),
        str(after - prev)
    ), toOutLine = True)

    if config['verbose'] and config['format'] != 'text': 
        sys.stderr.write('\n' + '-' * 50 + '\n\n')

    printResults(results, not opts.attack)

if __name__ == '__main__':
    main(sys.argv)
