#!/usr/bin/python3

#
# This script attempts to decode SMTP headers that may contain Anti-Spam related information, clues,
# scores and other characteristics. Intention is to extract reason why the message was considered a spam,
# by combining flags and values for different headers from all around the Internet and documentation.
#
# The script might be used by System Administrators to help them understand mail deliverability obstacles,
# but also by the Offensive security consultants performing Phishing Awareness Trainings, before sending
# a campaign to analyse negative constructs in their e-mails.
#
# Usage:
#   ./decode-spam-headers [options] <smtp-headers.txt>
#
#
# Mariusz B. / mgeeky, '21
# <mb [at] binary-offensive.com>
#

import os, sys, re
import string
import argparse
import json
import textwrap
import socket
import time
import base64
import packaging.version

from dateutil import parser
from email import header as emailheader
from datetime import *
from dateutil.tz import *


try:
    import dns.resolver

except ImportError:
    print('''
[!] You need to install dnspython: 
        # pip3 install dnspython

    If problem remains, re-install dnspython:
        # pip3 uninstall dnspython
        # pip3 install dnspython
''')

    sys.exit(1)

options = {
    'debug': False,
    'verbose': False,
    'nocolor' : False,
    'log' : sys.stderr,
}

class Logger:
    colors_map = {
        'red':      31, 
        'green':    32, 
        'yellow':   33,
        'blue':     34, 
        'magenta':  35, 
        'cyan':     36,
        'white':    37, 
        'grey':     38,
    }

    colors_dict = {
        'error': colors_map['red'],
        'trace': colors_map['magenta'],
        'info ': colors_map['green'],
        'debug': colors_map['grey'],
        'other': colors_map['grey'],
    }

    options = {}

    def __init__(self, opts = None):
        self.options.update(Logger.options)
        if opts != None and len(opts) > 0:
            self.options.update(opts)

    @staticmethod
    def with_color(c, s):
        return "\x1b[%dm%s\x1b[0m" % (c, s)

    def colored(self, txt, col):
        if self.options['nocolor']:
            return txt

        return Logger.with_color(Logger.colors_map[col], txt)
        
    # Invocation:
    #   def out(txt, mode='info ', fd=None, color=None, noprefix=False, newline=True):
    @staticmethod
    def out(txt, fd, mode='info ', **kwargs):
        if txt == None or fd == 'none':
            return 
        elif fd == None:
            raise Exception('[ERROR] Logging descriptor has not been specified!')

        args = {
            'color': None, 
            'noprefix': False, 
            'newline': True,
            'nocolor' : False
        }
        args.update(kwargs)

        if type(txt) != str:
            txt = str(txt)
            
        txt = txt.replace('\t', ' ' * 4)

        if args['nocolor']:
            col = ''
        elif args['color']:
            col = args['color']
            if type(col) == str and col in Logger.colors_map.keys():
                col = Logger.colors_map[col]
        else:
            col = Logger.colors_dict.setdefault(mode, Logger.colors_map['grey'])

        prefix = ''
        if mode:
            mode = '[%s] ' % mode
            
        if not args['noprefix']:
            if args['nocolor']:
                prefix = mode.upper()
            else:
                prefix = Logger.with_color(Logger.colors_dict['other'], '%s' 
                % (mode.upper()))
        
        nl = ''
        if 'newline' in args:
            if args['newline']:
                nl = '\n'

        if 'force_stdout' in args:
            fd = sys.stdout

        if type(fd) == str:
            with open(fd, 'a') as f:
                prefix2 = ''
                if mode: 
                    prefix2 = '%s' % (mode.upper())
                f.write(prefix2 + txt + nl)
                f.flush()

        else:
            if args['nocolor']:
                fd.write(prefix + txt + nl)
            else:
                fd.write(prefix + Logger.with_color(col, txt) + nl)

    # Info shall be used as an ordinary logging facility, for every desired output.
    def info(self, txt, forced = False, **kwargs):
        kwargs['nocolor'] = self.options['nocolor']
        if forced or (self.options['verbose'] or \
            self.options['debug'] ) \
            or (type(self.options['log']) == str and self.options['log'] != 'none'):
            Logger.out(txt, self.options['log'], 'info', **kwargs)

    def text(self, txt, **kwargs):
        kwargs['noPrefix'] = True
        kwargs['nocolor'] = self.options['nocolor']
        Logger.out(txt, self.options['log'], '', **kwargs)

    def dbg(self, txt, **kwargs):
        if self.options['debug']:
            kwargs['nocolor'] = self.options['nocolor']
            Logger.out(txt, self.options['log'], 'debug', **kwargs)

    def err(self, txt, **kwargs):
        kwargs['nocolor'] = self.options['nocolor']
        Logger.out(txt, self.options['log'], 'error', **kwargs)

    def fatal(self, txt, **kwargs):
        kwargs['nocolor'] = self.options['nocolor']
        Logger.out(txt, self.options['log'], 'error', **kwargs)
        os._exit(1)

logger = Logger(options)

class Verstring(object):
    def __init__(self, name, date, *versions):
        self.name = name
        self.date = date
        self.version = versions[0].split(' ')[0]

    def __eq__(self, other):
        if isinstance(other, Verstring):
            return packaging.version.parse(self.version) == packaging.version.parse(other.version) \
            and self.name == other.name
        elif isinstance(other, str):
            return packaging.version.parse(self.version) == packaging.version.parse(other)

    def __lt__(self, other):
        return packaging.version.parse(self.version) < packaging.version.parse(other.version)

    def __str__(self):
        return f'{self.name}; {self.date}; {self.version}'


class SMTPHeadersAnalysis:
    bad_keywords = (
        'gophish', 'phishingfrenzy', 'frenzy', 'king-phisher', 'phisher', 
        'speedphishing', 
    )

    Dodgy_User_Names = (
        'action', 'postmaster', 'root', 'admin', 'administrator', 'offer',
        'test', 'it', 'account', 'hr', 'job', 'relay', 'robot', 'help', 'catchall',
        'guest', 'spam', 'abuse', 'all', 'contact', 'nobody', 'auto', 'db', 'web', 
    )

    Header_Keywords_That_May_Contain_Spam_Info = (
        'spam', 
        'phishing', 
        'bulk', 
        'attack', 
        'spm', 
        'atp', 
        'defend', 
        'assassin',
    )

    Interesting_Headers = (
        'mailgun',
        'sendgrid',
        'mailchimp',
        'x-ses',
    )

    Headers_Known_For_Breaking_Line = (
        'Received',
        'Authentication-Results',
        'Received-SPF',
        'DKIM-Signature',
        'X-Google-DKIM-Signature',
        'X-GM-Message-State',
        'Subject',
        'X-MS-Exchange-Organization-ExpirationStartTime',
        'X-MS-Exchange-Organization-Network-Message-Id',
        'X-Forefront-Antispam-Report',
        'X-MS-Exchange-CrossTenant-OriginalArrivalTime',
        'X-Microsoft-Antispam-Mailbox-Delivery',
        'X-Microsoft-Antispam-Message-Info'
    )

    Handled_Spam_Headers = (
        'X-Forefront-Antispam-Report',
        'X-Microsoft-Antispam',
        'X-Microsoft-Antispam-Mailbox-Delivery',
        'X-Microsoft-Antispam-Message-Info',
        'X-Exchange-Antispam',
        'X-Exchange-Antispam-Mailbox-Delivery',
        'X-Exchange-Antispam-Message-Info',
        'X-Exchange-Antispam-Report-CFA-Test',
        'X-Microsoft-Antispam-Report-CFA-Test',
        'X-MS-Exchange-AtpMessageProperties',
        'X-Spam-Status',
        'X-Spam-Level',
        'X-Spam-Flag',
        'X-Spam-Report',
        'ARC-Authentication-Results',
        'X-MSFBL',
        'X-Ovh-Spam-Reason',
        'X-VR-SPAMSCORE',
        'X-VR-SPAMCAUSE',
    )

    auth_result = {
        'none': 'The message was not signed.',
        'pass': logger.colored('The message was signed, the signature or signatures were acceptable to the ADMD, and the signature(s) passed verification tests.', 'green'),
        'fail': logger.colored('The message was signed and the signature or signatures were acceptable to the ADMD, but they failed the verification test(s).', 'red'),
        'policy': 'The message was signed, but some aspect of the signature or signatures was not acceptable to the ADMD.',
        'neutral': logger.colored('The message was signed, but the signature or signatures contained syntax errors or were not otherwise able to be processed.', 'magenta'),
        'temperror': logger.colored('The message could not be verified due to some error that is likely transient in nature, such as a temporary inability to retrieve a public key.', 'red'),
        'permerror': logger.colored('The message could not be verified due to some error that is unrecoverable, such as a required header field being absent.', 'red'), 
    }

    Forefront_Antispam_Report = {
        'ARC' : (
            'ARC Protocol',
            {
                'AAR': 'Records the content of the Authentication-results header from DMARC.',
                'AMS': 'Includes cryptographic signatures of the message.',
                'AS': 'Includes cryptographic signatures of the message headers'
            }
        ),

        'CAT' : (
            'The category of protection policy',
            {
                'BULK': logger.colored('Bulk', 'red'),
                'DIMP': logger.colored('Domain Impersonation', 'red'),
                'GIMP': logger.colored('Mailbox intelligence based impersonation', 'red'),
                'HPHSH': logger.colored('High confidence phishing', 'red'),
                'HPHISH': logger.colored('High confidence phishing', 'red'),
                'HSPM': logger.colored('High confidence spam', 'red'),
                'MALW': logger.colored('Malware', 'red'),
                'PHSH': logger.colored('Phishing', 'red'),
                'SPM': logger.colored('Spam', 'red'),
                'SPOOF': logger.colored('Spoofing', 'red'),
                'UIMP': logger.colored('User Impersonation', 'red'),
                'AMP': logger.colored('Anti-malware', 'red'),
                'SAP': logger.colored('Safe attachments', 'green'),
                'OSPM': logger.colored('Outbound spam', 'red'),
                'NONE': logger.colored('Clean message', 'green'),
            }
        ),

        'CTRY' : (
            'The source country as determined by the connecting IP address',
            ''
        ),

        'H' : (
            'The HELO or EHLO string of the connecting email server.',
            ''
        ),

        'IPV' : (
            'Ingress Peer Verification status',
            {
                'CAL' : logger.colored('Source IP address was Configured in Allowed List (CAL)', 'green'),
                'NLI' : 'The IP address was not found on any IP reputation list.',
            }
        ),

        'EFV' : (
            'Egress F(?) Verification status',
            {
                'CAL' : logger.colored('Source IP address was Configured in Allowed List (CAL)', 'green'),
                'NLI' : 'The IP address was not found on any IP reputation list.',
            }
        ),

        'DIR' : (
            'Direction of email verification',
            {
                'INB' : 'Inbound email verification',
                'OUT' : 'Outbound email verification',
                'OUB' : 'Outbound email verification',
                'OTB' : 'Outbound email verification',
            }
        ),

        'LANG' : (
            'The language in which the message was written',
            ''
        ),

        'PTR' : (
            'Reverse DNS of the Connecting IP peer\'s address',
            ''
        ),

        'SFTY' : (
            'The message was identified as phishing',
            {
                '9.19': logger.colored('Domain impersonation. The sending domain is attempting to impersonate a protected domain', 'red'),

                '9.20' : logger.colored('User impersonation. The sending user is attempting to impersonate a user in the recipient\'s organization', 'red'),
            }
        ),

        'SRV' : (
            'Bulk Email analysis results',
            {
                'BULK' : logger.colored('The message was identified as bulk email by spam filtering and the bulk complaint level (BCL) threshold', 'red'),
            }
        ),

        'SFV' : (
            'Message Filtering',
            {
                'BLK' : logger.colored('Filtering was skipped and the message was blocked because it was sent from an address in a user\'s Blocked Senders list.', 'red'),
                'NSPM' : logger.colored('Spam filtering marked the message as non-spam and the message was sent to the intended recipients.', 'green'),
                'SFE' : logger.colored('Filtering was skipped and the message was allowed because it was sent from an address in a user\'s Safe Senders list.', 'green'),
                'SKA' : 'The message skipped spam filtering and was delivered to the Inbox because the sender was in the allowed senders list or allowed domains list in an anti-spam policy.',
                'SKB' : logger.colored('The message was marked as spam because it matched a sender in the blocked senders list or blocked domains list in an anti-spam policy.', 'red'),
                'SKI' : 'Similar to SFV:SKN, the message skipped spam filtering for another reason (for example, an intra-organizational email within a tenant).',
                'SKN' : logger.colored('The message was marked as non-spam prior to being processed by spam filtering. For example, the message was marked as SCL -1 or Bypass spam filtering by a mail flow rule.', 'green'),
                'SKQ' : logger.colored('The message was released from the quarantine and was sent to the intended recipients.', 'cyan'),
                'SKS' : logger.colored('The message was marked as spam prior to being processed by spam filtering. For example, the message was marked as SCL 5 to 9 by a mail flow rule.', 'red'),
                'SPM' : logger.colored('The message was marked as spam by spam filtering.', 'red'),
            }
        ),
    }

    Anti_Spam_Rules_ReverseEngineered = {
        '35100500006' : logger.colored('(SPAM) Message contained embedded image. Score +4', 'red'),
    }

    ForeFront_Spam_Confidence_Levels = {
        -1 : (False, logger.colored('The message skipped spam filtering. Probably Whitelisted.', 'green')),
        0 : (False, logger.colored('Spam filtering determined the message was not spam.', 'green')),
        1 : (False, 'The message skipped spam filtering'),
        5 : (True, logger.colored('Spam filtering marked the message as Spam', 'red')),
        6 : (True, logger.colored('Spam filtering marked the message as Spam', 'red')),
        9 : (True, logger.colored('Spam filtering marked the message as High confidence spam', 'red')),
    }

    ForeFront_Phishing_Confidence_Levels = {
        1 : (False, 'The message content isn\'t likely to be phishing'),
        2 : (False, 'The message content isn\'t likely to be phishing'),
        3 : (False, 'The message content isn\'t likely to be phishing'),
        4 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
        5 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
        6 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
        7 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
        8 : (True, logger.colored('The message content is likely to be phishing.', 'red')),
    }

    ForeFront_Bulk_Confidence_Levels = {
        0 : logger.colored('The message isn\'t from a bulk sender.', 'green'),
        1 : logger.colored('The message is from a bulk sender that generates few complaints.', 'magenta'),
        2 : logger.colored('The message is from a bulk sender that generates few complaints.', 'magenta'),
        3 : logger.colored('The message is from a bulk sender that generates few complaints.', 'magenta'),
        4 : logger.colored('The message is from a bulk sender that generates a mixed number of complaints.', 'red'),
        5 : logger.colored('The message is from a bulk sender that generates a mixed number of complaints.', 'red'),
        6 : logger.colored('The message is from a bulk sender that generates a mixed number of complaints.', 'red'),
        7 : logger.colored('The message is from a bulk sender that generates a mixed number of complaints.', 'red'),
        8 : logger.colored('The message is from a bulk sender that generates a high number of complaints.', 'red'),
        9 : logger.colored('The message is from a bulk sender that generates a high number of complaints.', 'red'),
    }

    ATP_Message_Properties = {
        'SA' : 'Safe Attachments Protection',
        'SL' : 'Safe Links Protection',
    }

    TLCOOBClassifiers = {
        'OLM' : (
            '',
            {

            }
        )
    }

    SpamAssassin_Spam_Status = (
        'SpamAssassin spam evaluation status report',
        {
            '_result' : 'Whether the message is Spam',
            'score' : 'Total score for the message (negative if whitelisted)',
            'required' : 'The score that would be required to be classed as spam',
            'tests' : 'List of tests that returned non-zero value',
            'autolearn' : 'Whether autolearn learned the message as spam or ham',
            'version' : 'Version of SpamAssassin used',
            'hits' : 'Number of characteristics considering this message as Spam',
            'tagged_above' : 'Tag message with SpamAssassin report if above threshold',
        }
    )

    Forefront_Antispam_Delivery = {
        'dest' : (
            'Destination where message should be placed',
            {
                'I' : logger.colored('Inbox directory', 'green'),
                'J' : logger.colored('JUNK directory', 'red'),
            }
        ),

        'auth' : (
            'Message originating from Authenticated sender',
            {
                '0' : 'Not Authenticated',
                '1' : 'Authenticated',
            }
        ),
    }


    # https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
    Exchange_Versions = (
        Verstring('Exchange Server 4.0 SP5 ', 'May 5, 1998', '4.0.996'),
        Verstring('Exchange Server 4.0 SP4 ', 'March 28, 1997', '4.0.995'),
        Verstring('Exchange Server 4.0 SP3 ', 'October 29, 1996', '4.0.994'),
        Verstring('Exchange Server 4.0 SP2 ', 'July 19, 1996', '4.0.993'),
        Verstring('Exchange Server 4.0 SP1 ', 'May 1, 1996', '4.0.838'),
        Verstring('Exchange Server 4.0 Standard Edition', 'June 11, 1996', '4.0.837'),
        Verstring('Exchange Server 5.0 SP2 ', 'February 19, 1998', '5.0.1460'),
        Verstring('Exchange Server 5.0 SP1 ', 'June 18, 1997', '5.0.1458'),
        Verstring('Exchange Server 5.0 ', 'May 23, 1997', '5.0.1457'),
        Verstring('Exchange Server version 5.5 SP4 ', 'November 1, 2000', '5.5.2653'),
        Verstring('Exchange Server version 5.5 SP3 ', 'September 9, 1999', '5.5.2650'),
        Verstring('Exchange Server version 5.5 SP2 ', 'December 23, 1998', '5.5.2448'),
        Verstring('Exchange Server version 5.5 SP1 ', 'August 5, 1998', '5.5.2232'),
        Verstring('Exchange Server version 5.5 ', 'February 3, 1998', '5.5.1960'),
        Verstring('Exchange 2000 Server post-SP3', 'August 2008', '6.0.6620.7'),
        Verstring('Exchange 2000 Server post-SP3', 'March 2008', '6.0.6620.5'),
        Verstring('Exchange 2000 Server post-SP3', 'August 2004', '6.0.6603'),
        Verstring('Exchange 2000 Server post-SP3', 'April 2004', '6.0.6556'),
        Verstring('Exchange 2000 Server post-SP3', 'September 2003', '6.0.6487'),
        Verstring('Exchange 2000 Server SP3', 'July 18, 2002', '6.0.6249'),
        Verstring('Exchange 2000 Server SP2', 'November 29, 2001', '6.0.5762'),
        Verstring('Exchange 2000 Server SP1', 'June 21, 2001', '6.0.4712'),
        Verstring('Exchange 2000 Server', 'November 29, 2000', '6.0.4417'),
        Verstring('Exchange Server 2003 post-SP2', 'August 2008', '6.5.7654.4'),
        Verstring('Exchange Server 2003 post-SP2', 'March 2008', '6.5.7653.33'),
        Verstring('Exchange Server 2003 SP2', 'October 19, 2005', '6.5.7683'),
        Verstring('Exchange Server 2003 SP1', 'May25, 2004', '6.5.7226'),
        Verstring('Exchange Server 2003', 'September 28, 2003', '6.5.6944'),
        Verstring('Update Rollup 5 for Exchange Server 2007 SP2', 'December 7, 2010', '8.2.305.3', '8.02.0305.003'),
        Verstring('Update Rollup 4 for Exchange Server 2007 SP2', 'April 9, 2010', '8.2.254.0', '8.02.0254.000'),
        Verstring('Update Rollup 3 for Exchange Server 2007 SP2', 'March 17, 2010', '8.2.247.2', '8.02.0247.002'),
        Verstring('Update Rollup 2 for Exchange Server 2007 SP2', 'January 22, 2010', '8.2.234.1', '8.02.0234.001'),
        Verstring('Update Rollup 1 for Exchange Server 2007 SP2', 'November 19, 2009', '8.2.217.3', '8.02.0217.003'),
        Verstring('Exchange Server 2007 SP2', 'August 24, 2009', '8.2.176.2', '8.02.0176.002'),
        Verstring('Update Rollup 10 for Exchange Server 2007 SP1', 'April 13, 2010', '8.1.436.0', '8.01.0436.000'),
        Verstring('Update Rollup 9 for Exchange Server 2007 SP1', 'July 16, 2009', '8.1.393.1', '8.01.0393.001'),
        Verstring('Update Rollup 8 for Exchange Server 2007 SP1', 'May 19, 2009', '8.1.375.2', '8.01.0375.002'),
        Verstring('Update Rollup 7 for Exchange Server 2007 SP1', 'March 18, 2009', '8.1.359.2', '8.01.0359.002'),
        Verstring('Update Rollup 6 for Exchange Server 2007 SP1', 'February 10, 2009', '8.1.340.1', '8.01.0340.001'),
        Verstring('Update Rollup 5 for Exchange Server 2007 SP1', 'November 20, 2008', '8.1.336.1', '8.01.0336.01'),
        Verstring('Update Rollup 4 for Exchange Server 2007 SP1', 'October 7, 2008', '8.1.311.3', '8.01.0311.003'),
        Verstring('Update Rollup 3 for Exchange Server 2007 SP1', 'July 8, 2008', '8.1.291.2', '8.01.0291.002'),
        Verstring('Update Rollup 2 for Exchange Server 2007 SP1', 'May 9, 2008', '8.1.278.2', '8.01.0278.002'),
        Verstring('Update Rollup 1 for Exchange Server 2007 SP1', 'February 28, 2008', '8.1.263.1', '8.01.0263.001'),
        Verstring('Exchange Server 2007 SP1', 'November 29, 2007', '8.1.240.6', '8.01.0240.006'),
        Verstring('Update Rollup 7 for Exchange Server 2007', 'July 8, 2008', '8.0.813.0', '8.00.0813.000'),
        Verstring('Update Rollup 6 for Exchange Server 2007', 'February 21, 2008', '8.0.783.2', '8.00.0783.002'),
        Verstring('Update Rollup 5 for Exchange Server 2007', 'October 25, 2007', '8.0.754.0', '8.00.0754.000'),
        Verstring('Update Rollup 4 for Exchange Server 2007', 'August 23, 2007', '8.0.744.0', '8.00.0744.000'),
        Verstring('Update Rollup 3 for Exchange Server 2007', 'June 28, 2007', '8.0.730.1', '8.00.0730.001'),
        Verstring('Update Rollup 2 for Exchange Server 2007', 'May 8, 2007', '8.0.711.2', '8.00.0711.002'),
        Verstring('Update Rollup 1 for Exchange Server 2007', 'April 17, 2007', '8.0.708.3', '8.00.0708.003'),
        Verstring('Exchange Server 2007 RTM', 'March 8, 2007', '8.0.685.25  8.00.0685.025'),
        Verstring('Update Rollup 23 for Exchange Server 2007 SP3', 'March 21, 2017', '8.3.517.0', '8.03.0517.000'),
        Verstring('Update Rollup 22 for Exchange Server 2007 SP3', 'December 13, 2016', '8.3.502.0', '8.03.0502.000'),
        Verstring('Update Rollup 21 for Exchange Server 2007 SP3', 'September 20, 2016', '8.3.485.1', '8.03.0485.001'),
        Verstring('Update Rollup 20 for Exchange Server 2007 SP3', 'June 21, 2016', '8.3.468.0', '8.03.0468.000'),
        Verstring('Update Rollup 19 forExchange Server 2007 SP3', 'March 15, 2016', '8.3.459.0', '8.03.0459.000'),
        Verstring('Update Rollup 18 forExchange Server 2007 SP3', 'December, 2015', '8.3.445.0', '8.03.0445.000'),
        Verstring('Update Rollup 17 forExchange Server 2007 SP3', 'June 17, 2015', '8.3.417.1', '8.03.0417.001'),
        Verstring('Update Rollup 16 for Exchange Server 2007 SP3', 'March 17, 2015', '8.3.406.0', '8.03.0406.000'),
        Verstring('Update Rollup 15 for Exchange Server 2007 SP3', 'December 9, 2014', '8.3.389.2', '8.03.0389.002'),
        Verstring('Update Rollup 14 for Exchange Server 2007 SP3', 'August 26, 2014', '8.3.379.2', '8.03.0379.002'),
        Verstring('Update Rollup 13 for Exchange Server 2007 SP3', 'February 24, 2014', '8.3.348.2', '8.03.0348.002'),
        Verstring('Update Rollup 12 for Exchange Server 2007 SP3', 'December 9, 2013', '8.3.342.4', '8.03.0342.004'),
        Verstring('Update Rollup 11 for Exchange Server 2007 SP3', 'August 13, 2013', '8.3.327.1', '8.03.0327.001'),
        Verstring('Update Rollup 10 for Exchange Server 2007 SP3', 'February 11, 2013', '8.3.298.3', '8.03.0298.003'),
        Verstring('Update Rollup 9 for Exchange Server 2007 SP3', 'December 10, 2012', '8.3.297.2', '8.03.0297.002'),
        Verstring('Update Rollup 8-v3 for Exchange Server 2007 SP3 ', 'November 13, 2012', '8.3.279.6', '8.03.0279.006'),
        Verstring('Update Rollup 8-v2 for Exchange Server 2007 SP3 ', 'October 9, 2012', '8.3.279.5', '8.03.0279.005'),
        Verstring('Update Rollup 8 for Exchange Server 2007 SP3', 'August 13, 2012', '8.3.279.3', '8.03.0279.003'),
        Verstring('Update Rollup 7 for Exchange Server 2007 SP3', 'April 16, 2012', '8.3.264.0', '8.03.0264.000'),
        Verstring('Update Rollup 6 for Exchange Server 2007 SP3', 'January 26, 2012', '8.3.245.2', '8.03.0245.002'),
        Verstring('Update Rollup 5 for Exchange Server 2007 SP3', 'September 21, 2011', '8.3.213.1', '8.03.0213.001'),
        Verstring('Update Rollup 4 for Exchange Server 2007 SP3', 'May 28, 2011', '8.3.192.1', '8.03.0192.001'),
        Verstring('Update Rollup 3-v2 for Exchange Server 2007 SP3 ', 'March 30, 2011', '8.3.159.2', '8.03.0159.002'),
        Verstring('Update Rollup 2 for Exchange Server 2007 SP3', 'December 10, 2010', '8.3.137.3', '8.03.0137.003'),
        Verstring('Update Rollup 1 for Exchange Server 2007 SP3', 'September 9, 2010', '8.3.106.2', '8.03.0106.002'),
        Verstring('Exchange Server 2007 SP3', 'June 7, 2010', '8.3.83.6', '8.03.0083.006'),
        Verstring('Update Rollup 8 for Exchange Server 2010 SP2', 'December 9, 2013', '14.2.390.3  14.02.0390.003'),
        Verstring('Update Rollup 7 for Exchange Server 2010 SP2', 'August 3, 2013', '14.2.375.0  14.02.0375.000'),
        Verstring('Update Rollup 6 Exchange Server 2010 SP2', 'February 12, 2013', '14.2.342.3  14.02.0342.003'),
        Verstring('Update Rollup 5 v2 for Exchange Server 2010 SP2 ', 'December 10, 2012', '14.2.328.10 14.02.0328.010'),
        Verstring('Update Rollup 5 for Exchange Server 2010 SP2', 'November 13, 2012', '14.3.328.5  14.03.0328.005'),
        Verstring('Update Rollup 4 v2 for Exchange Server 2010 SP2 ', 'October 9, 2012', '14.2.318.4  14.02.0318.004'),
        Verstring('Update Rollup 4 for Exchange Server 2010 SP2', 'August 13, 2012', '14.2.318.2  14.02.0318.002'),
        Verstring('Update Rollup 3 for Exchange Server 2010 SP2', 'May 29, 2012', '14.2.309.2  14.02.0309.002'),
        Verstring('Update Rollup 2 for Exchange Server 2010 SP2', 'April 16, 2012', '14.2.298.4  14.02.0298.004'),
        Verstring('Update Rollup 1 for Exchange Server 2010 SP2', 'February 13, 2012', '14.2.283.3  14.02.0283.003'),
        Verstring('Exchange Server 2010 SP2', 'December 4, 2011', '14.2.247.5  14.02.0247.005'),
        Verstring('Update Rollup 8 for Exchange Server 2010 SP1', 'December 10, 2012', '14.1.438.0  14.01.0438.000'),
        Verstring('Update Rollup 7 v3 for Exchange Server 2010 SP1 ', 'November 13, 2012', '14.1.421.3  14.01.0421.003'),
        Verstring('Update Rollup 7 v2 for Exchange Server 2010 SP1 ', 'October 10, 2012', '14.1.421.2  14.01.0421.002'),
        Verstring('Update Rollup 7 for Exchange Server 2010 SP1', 'August 8, 2012', '14.1.421.0  14.01.0421.000'),
        Verstring('Update Rollup 6 for Exchange Server 2010 SP1', 'October 27, 2011', '14.1.355.2  14.01.0355.002'),
        Verstring('Update Rollup 5 for Exchange Server 2010 SP1', 'August 23, 2011', '14.1.339.1  14.01.0339.001'),
        Verstring('Update Rollup 4 for Exchange Server 2010 SP1', 'July 27, 2011', '14.1.323.6  14.01.0323.006'),
        Verstring('Update Rollup 3 for Exchange Server 2010 SP1', 'April 6, 2011', '14.1.289.7  14.01.0289.007'),
        Verstring('Update Rollup 2 for Exchange Server 2010 SP1', 'December 9, 2010', '14.1.270.1  14.01.0270.001'),
        Verstring('Update Rollup 1 for Exchange Server 2010 SP1', 'October 4, 2010', '14.1.255.2  14.01.0255.002'),
        Verstring('Exchange Server 2010 SP1', 'August 23, 2010', '14.1.218.15 14.01.0218.015'),
        Verstring('Update Rollup 5 for Exchange Server 2010', 'December 13, 2010', '14.0.726.0  14.00.0726.000'),
        Verstring('Update Rollup 4 for Exchange Server 2010', 'June 10, 2010', '14.0.702.1  14.00.0702.001'),
        Verstring('Update Rollup 3 for Exchange Server 2010', 'April 13, 2010', '14.0.694.0  14.00.0694.000'),
        Verstring('Update Rollup 2 for Exchange Server 2010', 'March 4, 2010', '14.0.689.0  14.00.0689.000'),
        Verstring('Update Rollup 1 for Exchange Server 2010', 'December 9, 2009', '14.0.682.1  14.00.0682.001'),
        Verstring('Exchange Server 2010 RTM', 'November 9, 2009', '14.0.639.21 14.00.0639.021'),
        Verstring('Update Rollup 29 for Exchange Server 2010 SP3', 'July 9, 2019', '14.3.468.0  14.03.0468.000'),
        Verstring('Update Rollup 28 for Exchange Server 2010 SP3', 'June 7, 2019', '14.3.461.1  14.03.0461.001'),
        Verstring('Update Rollup 27 for Exchange Server 2010 SP3', 'April 9, 2019', '14.3.452.0  14.03.0452.000'),
        Verstring('Update Rollup 26 for Exchange Server 2010 SP3', 'February 12, 2019', '14.3.442.0  14.03.0442.000'),
        Verstring('Update Rollup 25 for Exchange Server 2010 SP3', 'January 8, 2019', '14.3.435.0  14.03.0435.000'),
        Verstring('Update Rollup 24 for Exchange Server 2010 SP3', 'September 5, 2018', '14.3.419.0  14.03.0419.000'),
        Verstring('Update Rollup 23 for Exchange Server 2010 SP3', 'August 13, 2018', '14.3.417.1  14.03.0417.001'),
        Verstring('Update Rollup 22 for Exchange Server 2010 SP3', 'June 19, 2018', '14.3.411.0  14.03.0411.000'),
        Verstring('Update Rollup 21 for Exchange Server 2010 SP3', 'May 7, 2018', '14.3.399.2  14.03.0399.002'),
        Verstring('Update Rollup 20 for Exchange Server 2010 SP3', 'March 5, 2018', '14.3.389.1  14.03.0389.001'),
        Verstring('Update Rollup 19 for Exchange Server 2010 SP3', 'December 19, 2017', '14.3.382.0  14.03.0382.000'),
        Verstring('Update Rollup 18 for Exchange Server 2010 SP3', 'July 11, 2017', '14.3.361.1  14.03.0361.001'),
        Verstring('Update Rollup 17 for Exchange Server 2010 SP3', 'March 21, 2017', '14.3.352.0  14.03.0352.000'),
        Verstring('Update Rollup 16 for Exchange Server 2010 SP3', 'December 13, 2016', '14.3.336.0  14.03.0336.000'),
        Verstring('Update Rollup 15 for Exchange Server 2010 SP3', 'September 20, 2016', '14.3.319.2  14.03.0319.002'),
        Verstring('Update Rollup 14 for Exchange Server 2010 SP3', 'June 21, 2016', '14.3.301.0  14.03.0301.000'),
        Verstring('Update Rollup 13 for Exchange Server 2010 SP3', 'March 15, 2016', '14.3.294.0  14.03.0294.000'),
        Verstring('Update Rollup 12 for Exchange Server 2010 SP3', 'December 15, 2015', '14.3.279.2  14.03.0279.002'),
        Verstring('Update Rollup 11 for Exchange Server 2010 SP3', 'September 15, 2015', '14.3.266.2  14.03.0266.002'),
        Verstring('Update Rollup 10 for Exchange Server 2010 SP3', 'June 17, 2015', '14.3.248.2  14.03.0248.002'),
        Verstring('Update Rollup 9 for Exchange Server 2010 SP3', 'March 17, 2015', '14.3.235.1  14.03.0235.001'),
        Verstring('Update Rollup 8 v2 for Exchange Server 2010 SP3 ', 'December 12, 2014', '14.3.224.2  14.03.0224.002'),
        Verstring('Update Rollup 8 v1 for Exchange Server 2010 SP3 (recalled)  ', 'December 9, 2014', '14.3.224.1  14.03.0224.001'),
        Verstring('Update Rollup 7 for Exchange Server 2010 SP3', 'August 26, 2014', '14.3.210.2  14.03.0210.002'),
        Verstring('Update Rollup 6 for Exchange Server 2010 SP3', 'May 27, 2014', '14.3.195.1  14.03.0195.001'),
        Verstring('Update Rollup 5 for Exchange Server 2010 SP3', 'February 24, 2014', '14.3.181.6  14.03.0181.006'),
        Verstring('Update Rollup 4 for Exchange Server 2010 SP3', 'December 9, 2013', '14.3.174.1  14.03.0174.001'),
        Verstring('Update Rollup 3 for Exchange Server 2010 SP3', 'November 25, 2013', '14.3.169.1  14.03.0169.001'),
        Verstring('Update Rollup 2 for Exchange Server 2010 SP3', 'August 8, 2013', '14.3.158.1  14.03.0158.001'),
        Verstring('Update Rollup 1 for Exchange Server 2010 SP3', 'May 29, 2013', '14.3.146.0  14.03.0146.000'),
        Verstring('Exchange Server 2010 SP3', 'February 12, 2013', '14.3.123.4  14.03.0123.004'),
        Verstring('Exchange Server 2013 CU23', 'June 18, 2019', '15.0.1497.2 15.00.1497.002'),
        Verstring('Exchange Server 2013 CU22', 'February 12, 2019', '15.0.1473.3 15.00.1473.003'),
        Verstring('Exchange Server 2013 CU21', 'June 19, 2018', '15.0.1395.4 15.00.1395.004'),
        Verstring('Exchange Server 2013 CU20', 'March 20, 2018', '15.0.1367.3 15.00.1367.003'),
        Verstring('Exchange Server 2013 CU19', 'December 19, 2017', '15.0.1365.1 15.00.1365.001'),
        Verstring('Exchange Server 2013 CU18', 'September 19, 2017', '15.0.1347.2 15.00.1347.002'),
        Verstring('Exchange Server 2013 CU17', 'June 27, 2017', '15.0.1320.4 15.00.1320.004'),
        Verstring('Exchange Server 2013 CU16', 'March 21, 2017', '15.0.1293.2 15.00.1293.002'),
        Verstring('Exchange Server 2013 CU15', 'December 13, 2016', '15.0.1263.5 15.00.1263.005'),
        Verstring('Exchange Server 2013 CU14', 'September 20, 2016', '15.0.1236.3 15.00.1236.003'),
        Verstring('Exchange Server 2013 CU13', 'June 21, 2016', '15.0.1210.3 15.00.1210.003'),
        Verstring('Exchange Server 2013 CU12', 'March 15, 2016', '15.0.1178.4 15.00.1178.004'),
        Verstring('Exchange Server 2013 CU11', 'December 15, 2015', '15.0.1156.6 15.00.1156.006'),
        Verstring('Exchange Server 2013 CU10', 'September 15, 2015', '15.0.1130.7 15.00.1130.007'),
        Verstring('Exchange Server 2013 CU9', 'June 17, 2015', '15.0.1104.5 15.00.1104.005'),
        Verstring('Exchange Server 2013 CU8', 'March 17, 2015', '15.0.1076.9 15.00.1076.009'),
        Verstring('Exchange Server 2013 CU7', 'December 9, 2014', '15.0.1044.25', '15.00.1044.025'),
        Verstring('Exchange Server 2013 CU6', 'August 26, 2014', '15.0.995.29 15.00.0995.029'),
        Verstring('Exchange Server 2013 CU5', 'May 27, 2014', '15.0.913.22 15.00.0913.022'),
        Verstring('Exchange Server 2013 SP1', 'February 25, 2014', '15.0.847.32 15.00.0847.032'),
        Verstring('Exchange Server 2013 CU3', 'November 25, 2013', '15.0.775.38 15.00.0775.038'),
        Verstring('Exchange Server 2013 CU2', 'July 9, 2013', '15.0.712.24 15.00.0712.024'),
        Verstring('Exchange Server 2013 CU1', 'April 2, 2013', '15.0.620.29 15.00.0620.029'),
        Verstring('Exchange Server 2013 RTM', 'December 3, 2012', '15.0.516.32 15.00.0516.03'),
        Verstring('Exchange Server 2016 CU14', 'September 17, 2019', '15.1.1847.3 15.01.1847.003'),
        Verstring('Exchange Server 2016 CU13', 'June 18, 2019', '15.1.1779.2 15.01.1779.002'),
        Verstring('Exchange Server 2016 CU12', 'February 12, 2019', '15.1.1713.5 15.01.1713.005'),
        Verstring('Exchange Server 2016 CU11', 'October 16, 2018', '15.1.1591.10', '15.01.1591.010'),
        Verstring('Exchange Server 2016 CU10', 'June 19, 2018', '15.1.1531.3 15.01.1531.003'),
        Verstring('Exchange Server 2016 CU9', 'March 20, 2018', '15.1.1466.3 15.01.1466.003'),
        Verstring('Exchange Server 2016 CU8', 'December 19, 2017', '15.1.1415.2 15.01.1415.002'),
        Verstring('Exchange Server 2016 CU7', 'September 19, 2017', '15.1.1261.35', '15.01.1261.035'),
        Verstring('Exchange Server 2016 CU6', 'June 27, 2017', '15.1.1034.26', '15.01.1034.026'),
        Verstring('Exchange Server 2016 CU5', 'March 21, 2017', '15.1.845.34 15.01.0845.034'),
        Verstring('Exchange Server 2016 CU4', 'December 13, 2016', '15.1.669.32 15.01.0669.032'),
        Verstring('Exchange Server 2016 CU3', 'September 20, 2016', '15.1.544.27 15.01.0544.027'),
        Verstring('Exchange Server 2016 CU2', 'June 21, 2016', '15.1.466.34 15.01.0466.034'),
        Verstring('Exchange Server 2016 CU1', 'March 15, 2016', '15.1.396.30 15.01.0396.030'),
        Verstring('Exchange Server 2016 RTM', 'October 1, 2015', '15.1.225.42 15.01.0225.042'),
        Verstring('Exchange Server 2016 Preview', 'July 22, 2015', '15.1.225.16 15.01.0225.016'),
        Verstring('Exchange Server 2019 CU3', 'September 17, 2019', '15.2.464.5  15.02.0464.005'),
        Verstring('Exchange Server 2019 CU2', 'June 18, 2019', '15.2.397.3  15.02.0397.003'),
        Verstring('Exchange Server 2019 CU1', 'February 12, 2019', '15.2.330.5  15.02.0330.005'),
        Verstring('Exchange Server 2019 RTM', 'October 22, 2018', '15.2.221.12 15.02.0221.012'),
        Verstring('Exchange Server 2019 Preview', 'July 24, 2018', '15.2.196.0  15.02.0196.000'),
        Verstring('Exchange Server 2019 CU11', 'October 12, 2021', '15.2.986.9'),
        Verstring('Exchange Server 2019 CU11', 'September 28, 2021', '15.2.986.5'),
        Verstring('Exchange Server 2019 CU10', 'October 12, 2021', '15.2.922.14'),
        Verstring('Exchange Server 2019 CU10', 'July 13, 2021', '15.2.922.13'),
        Verstring('Exchange Server 2019 CU10', 'June 29, 2021', '15.2.922.7'),
        Verstring('Exchange Server 2019 CU9', 'July 13, 2021', '15.2.858.15'),
        Verstring('Exchange Server 2019 CU9', 'May 11, 2021', '15.2.858.12'),
        Verstring('Exchange Server 2019 CU9', 'April 13, 2021', '15.2.858.10'),
        Verstring('Exchange Server 2019 CU9', 'March 16, 2021', '15.2.858.5'),
        Verstring('Exchange Server 2019 CU8', 'May 11, 2021', '15.2.792.15'),
        Verstring('Exchange Server 2019 CU8', 'April 13, 2021', '15.2.792.13'),
        Verstring('Exchange Server 2019 CU8', 'March 2, 2021', '15.2.792.10'),
        Verstring('Exchange Server 2019 CU8', 'December 15, 2020', '15.2.792.3'),
        Verstring('Exchange Server 2019 CU7', 'March 2, 2021', '15.2.721.13'),
        Verstring('Exchange Server 2019 CU7', 'September 15, 2020', '15.2.721.2'),
        Verstring('Exchange Server 2019 CU6', 'March 2, 2021', '15.2.659.12'),
        Verstring('Exchange Server 2019 CU6', 'June 16, 2020', '15.2.659.4'),
        Verstring('Exchange Server 2019 CU5', 'March 2, 2021', '15.2.595.8'),
        Verstring('Exchange Server 2019 CU5', 'March 17, 2020', '15.2.595.3'),
        Verstring('Exchange Server 2019 CU4', 'March 2, 2021', '15.2.529.13'),
        Verstring('Exchange Server 2019 CU4', 'December 17, 2019', '15.2.529.5'),
        Verstring('Exchange Server 2019 CU3', 'March 2, 2021', '15.2.464.15'),
    )



    def __init__(self, logger, resolve, decode_all):
        self.text = ''
        self.results = {}
        self.resolve = resolve
        self.decode_all = decode_all
        self.logger = logger
        self.received_path = None

        # (number, header, value)
        self.headers = []

    @staticmethod
    def parseExchangeVersion(lookup):

        # Try strict matching
        for ver in SMTPHeadersAnalysis.Exchange_Versions:
            if ver.version == lookup:
                return ver

        lookupparsed = packaging.version.parse(lookup)

        # Go with version-wise comparison to fuzzily find proper version name
        sortedversions = sorted(SMTPHeadersAnalysis.Exchange_Versions)

        for i in range(len(sortedversions)):
            if sortedversions[i].version.startswith(lookup):
                sortedversions[i].name = 'fuzzy match: ' + sortedversions[i].name
                return sortedversions[i]

        for i in range(len(sortedversions)):
            prevver = packaging.version.parse('0.0')
            nextver = packaging.version.parse('99999.0')
            if i > 0:
                prevver = packaging.version.parse(sortedversions[i-1].version)
            thisver = packaging.version.parse(sortedversions[i].version)
            if i + 1 < len(sortedversions):
                nextver = packaging.version.parse(sortedversions[i+1].version)

            if lookupparsed >= thisver and lookupparsed < nextver:
                sortedversions[i].name = 'fuzzy match: ' + sortedversions[i].name
                return sortedversions[i]

        return None


    def getHeader(self, _header):
        for (num, header, value) in self.headers:
            if header.lower() == _header.lower():
                return (num, header, value)

        if '-Microsoft-' in _header:
            _header = _header.replace('-Microsoft-', '-Exchange-')

            for (num, header, value) in self.headers:
                if header.lower() == _header.lower():
                    return (num, header, value)

        return (-1, '', '')

    def collect(self, text):
        num = 0
        errorOnce = False
        lines = text.split('\n')
        boundary = ''
        inBoundary = False
        headers = []
        
        i = 0
        while i < len(lines):
            line = lines[i]

            if len(boundary) > 0 and f'--{boundary}' == line.strip():
                inBoundary = True
                i += 1
                continue

            elif inBoundary and f'--{boundary}--' == line.strip():
                inBoundary = False
                i += 1
                continue

            elif inBoundary:
                i += 1
                continue

            elif line.startswith(' ') or line.startswith('\t'):
                if len(headers) > 0:
                    headers[-1][2] += '\n' + line
                    i += 1
                    continue
                else:
                    logger.dbg(f'Skipping invalid line:\n\t( {line} )')
                    i += 1
                    continue
            else:
                line = line.strip()
                match = re.match(r'^([^:]+)\s*:\s+(.+)\s*', line, re.S)

                if match:
                    headers.append([num, match.group(1), match.group(2)])
                    logger.dbg(f'Extracted {num}. {match.group(1)}')
                    num += 1
                else:
                    match = re.match(r'^([^:]+)\s*:\s*', line, re.S)

                    if match:
                        val = ''

                        considerNextLineIndented = match.group(1) in SMTPHeadersAnalysis.Headers_Known_For_Breaking_Line

                        if match and i + 1 < len(lines) and (lines[i + 1].startswith(' ') \
                                or lines[i + 1].startswith('\t')) or considerNextLineIndented:
                            j = 1

                            if considerNextLineIndented and not errorOnce and \
                                (not lines[i + 1].startswith(' ') and not lines[i+1].startswith('\t')):
                                errorOnce = True
                                self.logger.err('''
-----------------------------------------
WARNING!
-----------------------------------------

Your SMTP headers are not properly indented! 
Results will be unsound. Make sure you have pasted your headers with correct spaces/tabs indentation.

''')


                            while i + j < len(lines):
                                l = lines[i + j]

                                if l.startswith(' ') or l.startswith('\t') or considerNextLineIndented:
                                    val += l + '\n'
                                    j += 1
                                    considerNextLineIndented = False
                                else:
                                    break

                            headers.append([num, match.group(1), val.strip()])
                            logger.dbg(f'Extracted {num}. {match.group(1)}')
                            num += 1

                            i += j - 1

            if headers[-1][1].lower() == 'content-type':
                m = re.search(r'boundary="([^"]+)"', headers[-1][2], re.I)
                if m:
                    boundary = m.group(1)

            i += 1

        self.logger.info(f'Analysing {num} headers...')
        return headers

    def parse(self, text):
        self.text = text

        self.headers = self.collect(text)

        self.results['Received - Mail Servers Flow']            = self.testReceived()
        self.results['Extracted IP addresses']                  = self.testExtractIP()
        self.results['Extracted Domains']                       = self.testResolveIntoIP()
        self.results['Bad Keywords In Headers']                 = self.testBadKeywords()
        self.results['From Address Analysis']                   = self.testFrom()
        self.results['Authentication-Results']                  = self.testAuthenticationResults()
        self.results['ARC-Authentication-Results']              = self.testARCAuthenticationResults()
        self.results['Received-SPF']                            = self.testReceivedSPF()
        self.results['Mail Client Version']                     = self.testXMailer()
        self.results['X-Forefront-Antispam-Report']             = self.testForefrontAntiSpamReport()
        self.results['X-Microsoft-Antispam-Mailbox-Delivery']   = self.testAntispamMailboxDelivery()
        self.results['X-Microsoft-Antispam Bulk Mail']          = self.testMicrosoftAntiSpam()
        
        if self.decode_all:
            self.results['X-Microsoft-Antispam-Message-Info']   = self.testMicrosoftAntiSpamMessageInfo()
            self.results['Decoded Mail-encoded header values']  = self.testDecodeEncodedHeaders()

        self.results['End-to-End Latency - Message Delivery Time'] = self.testTransportEndToEndLatency()
        self.results['X-MS-Oob-TLC-OOBClassifiers']             = self.testTLCOObClasifiers()
        self.results['MS Defender ATP Message Properties']      = self.testATPMessageProperties()
        self.results['Domain Impersonation']                    = self.testDomainImpersonation()
        self.results['Other unrecognized Spam Related Headers'] = self.testSpamRelatedHeaders()
        self.results['X-Exchange-Antispam-Report-CFA-Test']     = self.testAntispamReportCFA()
        self.results['SpamAssassin Spam Status']                = self.testSpamAssassinSpamStatus()
        self.results['SpamAssassin Spam Level']                 = self.testSpamAssassinSpamLevel()
        self.results['SpamAssassin Spam Flag']                  = self.testSpamAssassinSpamFlag()
        self.results['SpamAssassin Spam Report']                = self.testSpamAssassinSpamReport()
        self.results['Message Feedback Loop']                   = self.testMSFBL()
        self.results['Other interesting headers']               = self.testInterestingHeaders()
        self.results['OVH\'s X-VR-SPAMCAUSE']                   = self.testSpamCause()
        self.results['OVH\'s X-Ovh-Spam-Reason']                = self.testOvhSpamReason()
        self.results['OVH\'s X-Ovh-Spam-Score']                 = self.testOvhSpamScore()

        return {k: v for k, v in self.results.items() if v}

    @staticmethod
    def flattenLine(value):
        return ' '.join([x.strip() for x in value.split('\n')])

    @staticmethod
    def printable(input_str):
        istr = str(input_str)
        return all(ord(c) < 127 and c in string.printable for c in istr)

    @staticmethod
    def extractDomain(fqdn):
        if not fqdn:
            return ''

        parts = fqdn.split('.')
        return '.'.join(parts[-2:])

    @staticmethod
    def decodeSpamcause(msg):
        text = []
        for i in range(0, len(msg), 2):
            text.append(SMTPHeadersAnalysis.unrotSpamcause(msg[i: i + 2]))
        return str.join('', text)

    @staticmethod
    def unrotSpamcause(pair, key=ord('x')):
        offset = 0
        for c in 'cdefgh':
            if c in pair:
                offset = (ord('g') - ord(c)) * 16
                break
        return chr(sum(ord(c) for c in pair) - key - offset)

    @staticmethod
    def hexdump(data, addr = 0, num = 0):
        s = ''
        n = 0
        lines = []
        if num == 0: num = len(data)

        if len(data) == 0:
            return '<empty>'

        for i in range(0, num, 16):
            line = ''
            line += '%04x | ' % (addr + i)
            n += 16

            for j in range(n-16, n):
                if j >= len(data): break
                line += '%02x ' % (data[j] & 0xff)

            line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

            for j in range(n-16, n):
                if j >= len(data): break
                c = data[j] if not (data[j] < 0x20 or data[j] > 0x7e) else '.'
                line += '%c' % c

            lines.append(line)
        return '\n'.join(lines)

    def testOvhSpamScore(self):
        (num, header, value) = self.getHeader('X-VR-SPAMSCORE')
        if num == -1: return []

        result = f'- OVH considered this message as SPAM and attached following Spam '
        value = SMTPHeadersAnalysis.flattenLine(value).replace(' ', '').replace('\t', '')
        result += f'Score: {self.logger.colored(value.strip(), "red")}\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testOvhSpamReason(self):
        (num, header, value) = self.getHeader('X-Ovh-Spam-Reason')
        if num == -1: return []

        result = self.logger.colored(f'- OVH considered this message as SPAM', 'red') + ' and attached following information:\n'
        value = SMTPHeadersAnalysis.flattenLine(value).replace(' ', '').replace('\t', '')
        tmp = ''

        for part in value.split(';'):
            part = part.strip()
            tmp += f'\t- {part}\n'

        result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testSpamCause(self):
        (num, header, value) = self.getHeader('X-VR-SPAMCAUSE')
        if num == -1: return []

        result = ''
        value = SMTPHeadersAnalysis.flattenLine(value).replace(' ', '').replace('\t', '')

        decoded = SMTPHeadersAnalysis.decodeSpamcause(value)

        if SMTPHeadersAnalysis.printable(decoded):
            result += f'- SPAMCAUSE contains encoded information about spam reasons:\n'
            tmp = ''

            for part in decoded.split(';'):
                part = part.strip()
                tmp += f'\t- {part}\n'

            result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testMSFBL(self):
        (num, header, value) = self.getHeader('X-MSFBL')
        if num == -1: return []

        parts = value.split('|')
        result = ''

        for p in parts:
            if p.startswith('eyJ'):
                decoded = base64.b64decode(p)
                if SMTPHeadersAnalysis.printable(decoded):
                    result += f'\t- Headers contained Feedback Loop object used by marketing systems to offer ISPs way to notify the sender that recipient marked that e-mail as Junk/Spam.\n'
                    result += '\n' + json.dumps(json.loads(decoded), indent=4) + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testInterestingHeaders(self):
        return self._testListRelatedHeaders(
            'Other Interesting SMTP headers that were not processed', 
            SMTPHeadersAnalysis.Interesting_Headers
        )

    def testSpamRelatedHeaders(self):
        return self._testListRelatedHeaders(
            'Other Spam related SMTP headers that were not processed', 
            SMTPHeadersAnalysis.Header_Keywords_That_May_Contain_Spam_Info
        )

    def _testListRelatedHeaders(self, msg, listOfValues):
        result = ''
        tmp = ''
        num0 = 0
        shown = set()

        for num, header, value in self.headers:
            value = SMTPHeadersAnalysis.flattenLine(value)

            if header in shown: 
                continue

            for dodgy in listOfValues:
                if header in shown: 
                    break

                if dodgy in header.lower() and header not in SMTPHeadersAnalysis.Handled_Spam_Headers:
                    num0 += 1
                    hhh = re.sub(r'(' + re.escape(dodgy) + r')', self.logger.colored(r'\1', 'red'), header, flags=re.I)

                    tmp += f'\t({num0:02}) {self.logger.colored("Header", "magenta")}: {hhh}\n'
                    tmp += f'\t     Keyword:  {dodgy}\n'
                    tmp += f'\t     Value:    {value[:120]}\n\n'
                    shown.add(header)
                    break

                elif dodgy in value.lower() and header not in SMTPHeadersAnalysis.Handled_Spam_Headers:
                    num0 += 1
                    hhh = header
                    tmp += f'\t({num0:02}) Header:   {hhh}\n'

                    pos = value.lower().find(dodgy)
                    ctx = re.sub(r'(' + re.escape(dodgy) + r')', self.logger.colored(r'\1', 'red'), value, flags=re.I)

                    if len(ctx) > 1024:
                        a = pos-40
                        b = -10 + pos + len(dodgy) + 30
                        
                        if a < 0: a = 0
                        if b > len(ctx): b = len(ctx)

                        ctx = value[a:b]

                    tmp += f'\t     Keyword:  {dodgy}\n'
                    tmp += f'\t       {self.logger.colored("Value", "magenta")}:\n\n{ctx}\n\n'
                    shown.add(header)
                    break

        if len(tmp) > 0:
            result = f'- {msg}:\n\n'
            result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : result
        }

    def testSpamAssassinSpamStatus(self):
        (num, header, value) = self.getHeader('X-Spam-Status')
        if num == -1: return []

        result = '- SpamAssassin spam report\n\n'
        
        parsed = {}
        col = 'green'
        parsed['_result'] = value.strip().split(',')[0]

        if parsed['_result'].lower() == 'yes':
            col = 'red'
        
        parsed['_result'] = self.logger.colored(value.strip().split(',')[0], col)

        pos = len(parsed['_result'])+2

        while pos < len(value):
            pose = value.find('=', pos)
            if pose == -1: break

            k = value[pos:pose]

            l = len(k) - len(k.lstrip())
            if l > 0:
                k = k.strip()
                pos += l

            if k == 'tests':
                v = value[pose+1:].replace(' ', '').replace('\n', '').split(',')
            else:
                sp = value.find(' ', pose)
                if sp == -1: break

                v = value[pose+1:sp]
                pos = sp + 1

            parsed[k] = v
            if k == 'tests':
                break

        for k, v in parsed.items():
            if k in SMTPHeadersAnalysis.SpamAssassin_Spam_Status[1].keys():
                k0 = self.logger.colored(k, 'magenta')
                result += f'\t- {k0}: ' + SMTPHeadersAnalysis.SpamAssassin_Spam_Status[1][k] + '\n'

                if type(v) == str:
                    result += f'\t\t- {v}\n'
                else:
                    result += f'\t\t- elements {len(v)}:\n'
                    for a in v:
                        result += f'\t\t\t- {a}\n'
            else:
                k0 = self.logger.colored(k, 'magenta')
                result += f'\t- {k0}: \n'

                if type(v) == str:
                    result += f'\t\t- {v}\n'
                else:
                    result += f'\t\t- elements {len(v)}:\n'
                    for a in v:
                        result += f'\t\t\t- {a}\n'

            result += '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testDomainImpersonation(self):
        (num, header, value) = self.getHeader('From')
        if num == -1: return []

        result = ''
        m = re.search(r'<([^<@\s]+)@([^\s]+)>', value)
        domain = ''

        if m and len(self.received_path) > 2:
            username = m.group(1)
            domain = m.group(2)
            email = f'{username}@{domain}'

            firstHop = self.received_path[1]
            
            mailDomainAddr = ''
            revMailDomain = ''
            revFirstSenderDomain = ''
            
            firstSenderAddr = ''
            revFirstSenderDomain

            try:
                mailDomainAddr = socket.gethostbyname(domain)
                revMailDomain = socket.gethostbyaddr(mailDomainAddr)[0]

                if(len(firstHop['ip'])) > 0:
                    revFirstSenderDomain = socket.gethostbyaddr(firstHop['ip'])[0]

                if(len(firstHop['host'])) > 0:
                    firstSenderAddr = socket.gethostbyname(firstHop['host'])
                    revFirstSenderDomain = socket.gethostbyaddr(firstSenderAddr)[0]
            except: 
                pass

            senderDomain = SMTPHeadersAnalysis.extractDomain(revMailDomain)
            firstHopDomain1 = SMTPHeadersAnalysis.extractDomain(revFirstSenderDomain)

            result += f'\t- Mail From: <{email}>\n\n'
            result += f'\t- Mail Domain: {domain}\n'
            result += f'\t               --> resolves to: {mailDomainAddr}\n'
            result += f'\t                   --> reverse-DNS resolves to: {revMailDomain}\n'
            result += f'\t                       (sender\'s domain: {self.logger.colored(senderDomain, "cyan")})\n\n'

            result += f'\t- First Hop:   {firstHop["host"]} ({firstHop["ip"]})\n'
            result += f'\t               --> resolves to: {firstSenderAddr}\n'
            result += f'\t                   --> reverse-DNS resolves to: {revFirstSenderDomain}\n'
            result += f'\t                       (first hop\'s domain: {self.logger.colored(firstHopDomain1, "cyan")})\n\n'

            if firstHopDomain1.lower() != senderDomain.lower():
                response = None
                try:
                    response = dns.resolver.resolve(domain, 'TXT')
                except dns.resolver.NoAnswer as e:
                    response = []

                spf = False

                for answer in response:
                    txt = str(answer)
                    if 'v=spf' in txt:
                        result += f'- Domain SPF: {txt[:64]}\n'

                        for _domain in re.findall(r'([a-z0-9_\.-]+\.[a-z]{2,})', txt):
                            _domain1 = SMTPHeadersAnalysis.extractDomain(_domain)

                            if _domain1.lower() == firstHopDomain1:
                                result += self.logger.colored(f'\n\t- First Hop ({firstHopDomain1}) is authorized to send e-mails on behalf of ({domain}) due to SPF records.\n\n', 'green')
                                spf = True
                                break

                    if spf:
                        break

                if not spf:
                    result += self.logger.colored('\n- WARNING! Potential Domain Impersonation!\n', 'red')
                    result += f'\t- Mail\'s domain should resolve to: \t{self.logger.colored(senderDomain, "green")}\n'
                    result += f'\t- But instead first hop resolved to:\t{self.logger.colored(firstHopDomain1, "red")}\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }


    def testSpamAssassinSpamFlag(self):
        (num, header, value) = self.getHeader('X-Spam-Flag')
        if num == -1: return []

        if value.strip().lower() == 'yes':
            result = self.logger.colored(f'- SpamAssassin marked this message as SPAM:\n', 'red')
            result += f'\t- ' + self.logger.colored(value, 'red') + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testSpamAssassinSpamLevel(self):
        (num, header, value) = self.getHeader('X-Spam-Level')
        if num == -1: return []

        if len(value.strip()) > 0:
            result = f'- SpamAssassin assigned following spam level to this message:\n'
            _num = self.logger.colored(str(len(value.strip())), 'red')
            result += f'\t- ' + self.logger.colored(value.strip(), 'red') + f' (number: {_num})\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testSpamAssassinSpamReport(self):
        (num, header, value) = self.getHeader('X-Spam-Report')
        if num == -1: return []

        if len(value.strip()) > 0:
            result = f'- SpamAssassin assigned following spam report to this message:\n'
            tmp = ''

            for line in value.split('\n'):
                if line.strip().startswith('* '):
                    line = line.strip()[2:]
                    result += f'- {line}\n'

            result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testATPMessageProperties(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-AtpMessageProperties')
        if num == -1: return []

        props = value.split('|')
        result = '- MS Defender Advanced Threat Protection enabled following protections on this message:\n'

        for prop in props:
            if prop in SMTPHeadersAnalysis.ATP_Message_Properties.keys():
                result += f'- ' + self.logger.colored(SMTPHeadersAnalysis.ATP_Message_Properties[prop], 'magenta') + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testReceived(self):
        received = []

        for i in range(len(self.headers)):
            if self.headers[i][1].lower() == 'received':
                received.append(self.headers[i])

        result = ''
        path = []

        (n1, h1, v1) = self.getHeader('From')
        (n2, h2, v2) = self.getHeader('To')

        path.append({
            'type': 'from',
            'host' : v1,
            'timestamp' : None,
            'ip' : '',
            'ver' : '',
        })

        for i in range(len(received), 0, -1):
            r = received[i - 1][2]
            r = SMTPHeadersAnalysis.flattenLine(r)

            timestamp = re.search(r'(?P<timestamp>[A-Za-z]{3}\,\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:\s+[\+-]\d{4}(?:\s+\([A-Z]{3}\))?)?)', r)
            ver = re.search(r'id\s+([0-9\.]+)', r)
            match = re.match(r'(?:from\s+(?P<from>[^\s]+)\s*(?:\((?P<from_ip>[^\)]+)\))?)', r, re.I)
            match2 = re.match(r'(?:by\s+(?P<by>[^\s]+)\s*(?:\((?P<by_ip>[^\)]+)\))?)', r, re.I)

            ts = None
            if timestamp:
                ts = parser.parse(timestamp.group('timestamp')).astimezone(tzutc())

            vers = ''
            if ver:
                vers = str(SMTPHeadersAnalysis.parseExchangeVersion(ver.group(1)))

                if not vers or len(vers) == 0:
                    vers = ver.group(1)
                else:
                    vers = re.sub(r'fuzzy match:\s+fuzzy match:', 'fuzzy match:', vers)
                    vers = vers.replace('fuzzy match: fuzzy match:', 'fuzzy match: ')

            obj = None
            if match:
                obj = {
                    'type' : 'from',
                    'host' : match.group('from'),
                    'ip' : match.group('from_ip'),
                    'timestamp' : ts,
                    'ver' : vers,
                }
            
            elif match2:
                obj = {
                    'type' : 'by',
                    'host' : match2.group('by'),
                    'ip' : match2.group('by_ip'),
                    'timestamp' : ts,
                    'ver' : vers,
                }

            if obj:
                if (obj['ip'] == None or len(obj['ip']) == 0) and obj['host'] != None and len(obj['host']) > 0:
                    try:
                        obj['ip'] = socket.gethostbyname(obj['host'])
                    except:
                        pass

                if obj['ip'] != None and len(obj['ip']) > 0:
                    match = re.match(r'(?P<host>[^\s]+)\.?\s+\[(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', obj['ip'], re.I)
                    match2 = re.search(r'\[(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', obj['ip'], re.I)

                    if match:
                        obj['host'] = match.group('host')
                        obj['ip'] = match.group('ip')

                    elif match2:
                        obj['ip'] = match2.group(1)

                path.append(obj)

        path.append({
            'type': 'from',
            'host' : v2,
            'ip' : '',
            'timestamp' : None,
            'ver' : '',
        })

        result = '- List of server hops used to deliver message:\n\n'
        iindent = '  '
        indent = '    '
        num = 0

        for i in range(len(path)):
            elem = path[i]

            if elem['type'] != 'from': continue

            num += 1
            s = '-->'
            if i > 0:
                s = '|_>'
            
            if num == 2:
                result += iindent + indent * (num+1) + f'{s} ({num}) {self.logger.colored(elem["host"], "green")}'
            else:
                result += iindent + indent * (num+1) + f'{s} ({num}) {elem["host"]}'

            if elem['ip'] != None and len(elem['ip']) > 0:
                if num == 2:
                    result += f' ({self.logger.colored(elem["ip"], "green")})\n'
                else:
                    result += f' ({elem["ip"]})\n'
            else:
                result += '\n'

            if elem['timestamp'] != None:
                result += iindent + indent * (num+3) + 'time: ' + elem['timestamp'].strftime('%d %b %Y %H:%M:%S') + '\n'

            if len(elem['ver']) > 0:
                result += iindent + indent * (num+3) + 'version: ' + elem['ver'] + '\n'

            result += '\n'

        self.received_path = path

        return {
            'header' : 'Received',
            'value': '...',
            'analysis' : result
        }

    def testAntispamReportCFA(self):
        (num, header, value) = self.getHeader('X-Exchange-Antispam-Report-CFA-Test')
        if num == -1: return []

        obj = {
            'header' : header,
            'value' : value,
            'analysis' : ''
        }

        result = ''

        obj1 = self._parseBulk(num, header, value)
        result += obj1['analysis']

        obj2 = self._parseAntiSpamReport(num, header, value)
        result += obj2['analysis']

        obj['analysis'] = result
        return obj

    def testMicrosoftAntiSpam(self):
        (num, header, value) = self.getHeader('X-Microsoft-Antispam')
        if num == -1: return []

        return self._parseBulk(num, header, value)

    def _parseBulk(self, num, header, value):
        parsed = {}
        result = ''

        for entry in value.split(';'):
            if(len(entry.strip()) == 0): continue
            k, v = entry.strip().split(':')
            parsed[k] = v

        if 'BCL' in parsed.keys():
            scl = int(parsed['BCL'])
            tmp = ''
            lvl = self.logger.colored(str(scl), 'green')
            if scl > 0:
                lvl = self.logger.colored(str(scl), 'red')

            tmp += f'- {self.logger.colored("BCL", "magenta")}: BULK Confidence Level: ' + lvl + '\n'

            levels = list(SMTPHeadersAnalysis.ForeFront_Bulk_Confidence_Levels.keys())
            levels.sort()

            if scl in levels:
                tmp += '\t' + SMTPHeadersAnalysis.ForeFront_Bulk_Confidence_Levels[scl] + '\n'

            else:
                for i in range(len(levels)):
                    if scl <= levels[i] and i > 0:
                        tmp += '\t' + SMTPHeadersAnalysis.ForeFront_Bulk_Confidence_Levels[levels[i-1]] + '\n'
                        break
                    elif scl <= levels[0]:
                        tmp += '\t' + SMTPHeadersAnalysis.ForeFront_Bulk_Confidence_Levels[levels[0]] + '\n'
                        break

            tmp += f'''
    More information:
        - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/bulk-complaint-level-values

'''
            result += tmp

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testForefrontAntiSpamReport(self):
        (num, header, value) = self.getHeader('X-Forefront-Antispam-Report')
        if num == -1: return []

        return self._parseAntiSpamReport(num, header, value)
    
    def _parseAntiSpamReport(self, num, header, value):
        parsed = {}
        result = '- Microsoft Office365/Exchange ForeFront Anti-Spam report\n\n'

        for entry in value.split(';'):
            if len(entry.strip()) == 0: continue
            k, v = entry.split(':')
            if k not in parsed.keys():
                parsed[k] = v

        if 'CIP' in parsed.keys():
            res = ''
            if self.resolve:
                try:
                    res = socket.gethostbyaddr(parsed['CIP'])
                except:
                    pass

                result += f'- {self.logger.colored("CIP", "magenta")}: Connecting IP address: {parsed["CIP"]} (resolved: {res[0]})\n\n'
            else:
                result += f'- {self.logger.colored("CIP", "magenta")}: Connecting IP address: {parsed["CIP"]}\n\n'

        for k, v in parsed.items():
            elem = None

            if k.upper() in SMTPHeadersAnalysis.Forefront_Antispam_Report.keys():
                elem = SMTPHeadersAnalysis.Forefront_Antispam_Report[k.upper()]

            elif k in SMTPHeadersAnalysis.Forefront_Antispam_Report.keys():
                elem = SMTPHeadersAnalysis.Forefront_Antispam_Report[k]

            if elem:
                vals = v.split(',')
                found = False
                k0 = self.logger.colored(k, 'magenta')
                tmp = f'- {k0}: ' + elem[0] + '\n'

                if type(elem[1]) == dict:
                    for va in vals:
                        if va in elem[1].keys():
                            found = True
                            tmp += f'\t- {va}: {elem[1][va]}\n'

                    if not found and len(v.strip()) > 0:
                        tmp += f'\t- Unknown value: "{v}" in parameter {k0}\n'
                        found = True
                
                elif len(v) > 0:
                    found = True
                    tmp += f'\t- {v}\n'

                if found:
                    result += tmp + '\n'

        for k in ['SFS', 'RULEID', 'ENG']:
            if k in parsed.keys():
                res = ''
                rules = [x.replace('(', '') for x in parsed[k].split(')')]

                if len(rules) == 1 and len(rules[0].strip()) == 0:
                    rules = []

                k0 = self.logger.colored(k, 'magenta')
                tmp = f'- Message matched {len(rules)} Anti-Spam rules ({k0}):\n'

                rules.sort()
                for r in rules:
                    if len(r) == 0: continue

                    if r in SMTPHeadersAnalysis.Anti_Spam_Rules_ReverseEngineered.keys():
                        e = SMTPHeadersAnalysis.Anti_Spam_Rules_ReverseEngineered[r]
                        tmp += f'\t- ({r}) - {e}\n'
                    else:
                        tmp += f'\t- ({r})\n'

                result += tmp + '\n'

        sclpcl = {
            'SCL' : ('Spam Confidence Level', 'spam', SMTPHeadersAnalysis.ForeFront_Spam_Confidence_Levels),
            'PCL' : ('Phishing Confidence Level', 'phishing', SMTPHeadersAnalysis.ForeFront_Phishing_Confidence_Levels),
        }

        addscl = False
        tmpfoo = ''

        for k, v in sclpcl.items():
            if k in parsed.keys():
                addscl = True
                scl = int(parsed[k])
                k0 = self.logger.colored(k, 'magenta')
                tmpfoo += f'- {k0}: {v[0]}: ' + str(scl) + '\n'

                levels = list(v[2].keys())
                levels.sort()

                if scl in levels:
                    s = v[2][scl]
                    f = self.logger.colored(f'Not {v[1]}', 'green')
                    if s[0]:
                        f = self.logger.colored(v[1].upper(), 'red')

                    tmpfoo += f'\t- {f}: {s[1]}\n'

                else:
                    for i in range(len(levels)):
                        if scl <= levels[i] and i > 0:
                            s = v[2][levels[i-1]]
                            f = self.logger.colored(f'Not {v[1]}', 'green')
                            if s[0]:
                                f = self.logger.colored(v[1].upper(), 'red')

                            tmpfoo += f'\t- {f}: {s[1]}\n'
                            break
                        elif scl <= levels[0]:
                            s = v[2][levels[0]]
                            f = self.logger.colored(f'Not {v[1]}', 'green')
                            if s[0]:
                                f = self.logger.colored(v[1].upper(), 'red')

                            tmpfoo += f'\t- {f}: {s[1]}\n'
                            break

        if addscl:
            result += tmpfoo
            
        result += f'''

More information:
    - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers
    - https://docs.microsoft.com/en-us/exchange/antispam-and-antimalware/antispam-protection/antispam-stamps
    - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/spam-confidence-levels
    - https://docs.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/run-a-message-trace-and-view-results

'''

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testFrom(self):
        (num, header, value) = self.getHeader('From')
        if num == -1: return []

        result = ''
        m = re.search(r'<([^<@\s]+)@([^\s]+)>', value)

        if m:
            username = m.group(1)
            domain = m.group(2)
            email = f'{username}@{domain}'

            if username.lower() in SMTPHeadersAnalysis.Dodgy_User_Names:
                result += self.logger.colored(f'- Username "{username}" in your sender email ({email}) is known to be blacklisted!\n', 'red')

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testDecodeEncodedHeaders(self):
        result = ''
        tmp = ''
        found = False
        num0 = 0
        shown = set()

        for (num, header, value) in self.headers:
            v = SMTPHeadersAnalysis.flattenLine(value)
            if '=?us-ascii?Q?' in v:
                num0 += 1

                value_decoded = emailheader.decode_header(value)[0][0].decode()
                hhh = self.logger.colored(header, 'magenta')
                tmp += f'\t({num0:02}) Header: {hhh}\n'
                tmp += f'\t     Value:\n\n'
                tmp += value_decoded + '\n\n'

                tmp += f'\t     Base64 decoded Hexdump:\n\n'
                tmp += SMTPHeadersAnalysis.hexdump(base64.b64decode(value_decoded))
                tmp += '\n\n\n'

                shown.add(header)

        if len(tmp) > 0:
            result = '- Decoded headers:\n\n'
            result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': '...',
            'analysis' : result
        }

    def testMicrosoftAntiSpamMessageInfo(self):
        (num, header, value) = self.getHeader('X-Microsoft-Antispam-Message-Info')
        if num == -1: return []

        value = emailheader.decode_header(value)[0][0].decode()
        result = '- Base64 encoded & encrypted Antispam Message Info:\n\n'
        result += value

        tmp += f'\n\n\t- Base64 decoded Hexdump:\n\n'
        tmp += SMTPHeadersAnalysis.hexdump(base64.b64decode(value))
        tmp += '\n\n\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': '...',
            'analysis' : result
        }

    def testAntispamMailboxDelivery(self):
        (num, header, value) = self.getHeader('X-Microsoft-Antispam-Mailbox-Delivery')
        if num == -1: return []

        parsed = {}
        result = '- This header denotes what to do with received message, where to put it.\n\n'

        for entry in value.split(';'):
            if len(entry.strip()) == 0: continue
            k, v = entry.split(':')
            if k not in parsed.keys():
                parsed[k] = v

        for k, v in parsed.items():
            elem = None

            if k.upper() in SMTPHeadersAnalysis.Forefront_Antispam_Delivery.keys():
                elem = SMTPHeadersAnalysis.Forefront_Antispam_Delivery[k.upper()]

            elif k in SMTPHeadersAnalysis.Forefront_Antispam_Delivery.keys():
                elem = SMTPHeadersAnalysis.Forefront_Antispam_Delivery[k]

            if elem:
                vals = v.split(',')
                found = False
                k0 = self.logger.colored(k, 'magenta')
                tmp = f'- {k0}: ' + elem[0] + '\n'

                if type(elem[1]) == dict:
                    for va in vals:
                        if va in elem[1].keys():
                            found = True
                            tmp += f'\t- {va}: {elem[1][va]}\n'

                    if not found and len(v.strip()) > 0:
                        tmp += f'\t- Unknown value: "{v}" in parameter {k0}\n'
                        found = True
                
                elif len(v) > 0:
                    found = True
                    tmp += f'\t- {v}\n'

                if found:
                    result += tmp + '\n'

        for k in ['SFS', 'RULEID', 'ENG']:
            if k in parsed.keys():
                res = ''
                rules = [x.replace('(', '') for x in parsed[k].split(')')]

                if len(rules) == 1 and len(rules[0].strip()) == 0:
                    rules = []

                k0 = self.logger.colored(k, 'magenta')
                tmp = f'- Message matched {len(rules)} Anti-Spam Delivery rules ({k0}):\n'

                rules.sort()
                for r in rules:
                    if len(r) == 0: continue

                    if r in SMTPHeadersAnalysis.Anti_Spam_Rules_ReverseEngineered.keys():
                        e = SMTPHeadersAnalysis.Anti_Spam_Rules_ReverseEngineered[r]
                        tmp += f'\t- ({r}) - {e}\n'
                    else:
                        tmp += f'\t- ({r})\n'

                result += tmp + '\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testXMailer(self):
        (num, header, value) = self.getHeader('X-Mailer')
        if num == -1: return []

        vvv = self.logger.colored(value, 'magenta')
        result = f'- X-Mailer header was present and contained value: {vvv}\n'
        result +  '  This header typically indicates sending client\'s name (similar to User-Agent).'

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testTLCOObClasifiers(self):
        (num, header, value) = self.getHeader('X-MS-Oob-TLC-OOBClassifiers')
        if num == -1: return []

        result = f'- {self.logger.colored("OOB", "magenta")} Classifiers and their results:\n'
        value = value.replace(' ', '')

        for a in value.split(';'):
            if(len(a)) == 0: continue
            k, v = a.split(':')
            k0 = self.logger.colored(k, 'magenta')

            if k in SMTPHeadersAnalysis.TLCOOBClassifiers.keys():
                elem = SMTPHeadersAnalysis.TLCOOBClassifiers[k]

                if len(elem[0]) > 0:
                    result += f'\t- {k0}:{v} - ' + elem[0] + '\n'
                else:
                    result += f'\t- {k0}:{v}\n'

                if v in elem[1].keys():
                    result += f'\t\t- ' + elem[1][v] + '\n'
            else:
                result += f'\t- {k0}:{v}\n'

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testTransportEndToEndLatency(self):
        (num, header, value) = self.getHeader('X-MS-Exchange-Transport-EndToEndLatency')
        if num == -1: return []

        result = f'- How much time did it take to deliver message from End-to-End: ' + self.logger.colored(value, 'cyan')

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testReceivedSPF(self):
        (num, header, value) = self.getHeader('Received-SPF')
        if num == -1: return []

        value = SMTPHeadersAnalysis.flattenLine(value)
        result = ''
        words = [x.strip() for x in value.lower().split(' ') if len(x.strip()) > 0]
        
        if words[0] != 'pass':
            result += self.logger.colored(f'- Received-SPF test failed', 'red') + ': Should be "pass", but was: "' + str(words[0]) + '"\n'

            if words[0] in SMTPHeadersAnalysis.auth_result.keys():
                result += '\t- Meaning: ' + str(SMTPHeadersAnalysis.auth_result[words[0]]) + '\n\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }

    def testAuthenticationResults(self):
        (num, header, value) = self.getHeader('Authentication-Results')
        if num == -1: return []

        return self._testAuthenticationResults(num, header, value)

    def testARCAuthenticationResults(self):
        (num, header, value) = self.getHeader('ARC-Authentication-Results')
        if num == -1: return []

        return self._testAuthenticationResults(num, header, value)

    def _testAuthenticationResults(self, num, header, value):
        value = SMTPHeadersAnalysis.flattenLine(value)
        tests = {}
        result = ''

        for l in re.findall(r'([a-z]+=[a-zA-Z0-9]+)', value, re.I):
            a, b = l.lower().split('=')
            tests[a] = b

        for k in ['spf', 'dkim', 'dmarc']:
            expected = ['pass', ]
            
            if k == 'dmarc':
                expected.append('bestguesspass')

            if k in tests.keys() and tests[k] not in expected:
                result += self.logger.colored(f'- {k.upper()} test failed:', 'red') + ' Should be "pass", but was: "' + tests[k] + '"\n'

                if tests[k] in SMTPHeadersAnalysis.auth_result.keys():
                    result += '\t- Meaning: ' + SMTPHeadersAnalysis.auth_result[tests[k]] + '\n\n'

        if len(result) == 0:
            return []

        return {
            'header' : header,
            'value': value,
            'analysis' : result
        }
        
    def testExtractIP(self):
        addresses = re.findall(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', self.text)
        result = ''
        resolved = set()

        if len(addresses) == 0: return []

        self.logger.dbg('Running testExtractIP...')

        for addr in addresses:
            if addr in resolved: 
                continue

            try:
                resolved.add(addr)
                if self.resolve:
                    self.logger.dbg(f'testExtractIP: Resolving {addr}...')
                    out = socket.gethostbyaddr(addr)

                    addr = self.logger.colored(addr, 'magenta')
                    result += f'- Found IP address: ({addr}) that resolves to: {out[0]}\n'
                else:
                    addr = self.logger.colored(addr, 'magenta')
                    result += f'- Found IP address: ({addr})\n'
            
            except Exception as e:
                result += f'- Found IP address: ({addr}) that wasn\'t resolved\n'

        if len(resolved) == 0:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : result
        }

    def testResolveIntoIP(self):
        domains = set(re.findall(r'([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})', self.text, re.I))
        resolved = set()
        result = ''

        skip = (
            'smtp.mailfrom',
            'header.from',
        )

        if len(domains) == 0: return []

        self.logger.dbg('Running testResolveIntoIP...')

        for d in domains:
            if d in resolved: continue
            if d in skip: continue

            try:
                resolved.add(d)
                if self.resolve:
                    self.logger.dbg(f'testResolveIntoIP: Resolving {d}...')
                    out = socket.gethostbyname(d)

                    if type(out) == list:
                        out = out[0]

                    result += f'- Found Domain: {d}\n\t\t- that resolves to: {out}\n'
                else:
                    result += f'- Found Domain: {d}\n'

            
            except Exception as e:
                result += f'- Found Domain: ({d}) that wasn\'t resolved\n'

        if len(resolved) == 0:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : result
        }

    def testBadKeywords(self):
        result = ''
        for num, header, value in self.headers:
            for w in SMTPHeadersAnalysis.bad_keywords:
                if w.lower() in value.lower():
                    result += self.logger.colored(f'- Header\'s ({header}) value contained bad keyword: "{w}"\n', 'red')
                    result += f'  Value: {value}\n\n'

                elif w.lower() in header.lower():
                    result += self.logger.colored(f'- Header\'s ({header}) name contained bad keyword: "{w}"\n\n', 'red')

        if len(result) == 0:
            return []

        return {
            'header' : '-',
            'value': '-',
            'analysis' : result
        }

def opts(argv):
    global options
    global logger

    o = argparse.ArgumentParser(
        usage = 'decode-spam-headers.py [options] <file>'
    )
    
    req = o.add_argument_group('Required arguments')
    req.add_argument('infile', help = 'Input file to be analysed')

    opt = o.add_argument_group('Options')
    opt.add_argument('-o', '--outfile', default='', type=str, help = 'Output file with report')
    opt.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Analysis report format. JSON, text. Default: text')
    opt.add_argument('-N', '--nocolor', default=False, action='store_true', help='Dont use colors in text output.')
    opt.add_argument('-v', '--verbose', default=False, action='store_true', help='Verbose mode.')
    opt.add_argument('-d', '--debug', default=False, action='store_true', help='Debug mode.')

    tst = o.add_argument_group('Tests')
    tst.add_argument('-r', '--resolve', default=False, action='store_true', help='Resolve IPv4 addresses / Domain names.')
    tst.add_argument('-D', '--decode-all', default=False, action='store_true', help='Decode all =?us-ascii?Q? mail encoded messages and print their contents.')

    args = o.parse_args()

    if len(args.outfile) > 0:
        args.nocolor = True

    options.update(vars(args))
    logger = Logger(options)

    return args

def printOutput(out):
    output = ''

    if options['format'] == 'text':
        width = 100
        num = 0

        for k, v in out.items():
            num += 1
            analysis = v['analysis']
            value = v['value']

            analysis = analysis.replace('- ', '\t- ').strip()

            value = str(textwrap.fill(
                v['value'], 
                width=width - 1, 
                subsequent_indent=' ' * 4, 
                initial_indent='', 
                replace_whitespace=False
            )).strip()

            if len(v['header']) > 1 or len(value) > 1:
                output += f'''
------------------------------------------
({num}) Test: {logger.colored(k, "cyan")}

{logger.colored("HEADER", "blue")}: 
    {v['header']}

{logger.colored("VALUE", "blue")}: 
    {value}

{logger.colored("ANALYSIS", "yellow")}:
    {analysis}
'''
            else:
                output += f'''
------------------------------------------
({num}) Test: {logger.colored(k, "cyan")}

{logger.colored("ANALYSIS", "yellow")}:
    {analysis}
'''

    elif options['format'] == 'json':
        output = json.dumps(out)

    return output

def main(argv):
    args = opts(argv)
    if not args:
        return False

    logger.info('Analysing: ' + args.infile)

    text = ''
    with open(args.infile) as f:
        text = f.read()

    an = SMTPHeadersAnalysis(logger, args.resolve, args.decode_all)
    out = an.parse(text)

    output = printOutput(out)

    if len(args.outfile) > 0:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output2 = ansi_escape.sub('', output)

        with open(args.outfile, 'w') as f:
            f.write(output2)
    else:
        print(output)

if __name__ == '__main__':
    main(sys.argv)
