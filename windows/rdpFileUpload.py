#
#   RDP file upload utility via Keyboard emulation.
# Uploads specified input file or directory, encodes it and retypes encoded contents
# by emulating keyboard keypresses into previously focused RDP session window.
# That will effectively transmit contents of the file onto the remote host without use
# of any sort of built-in file upload functionality. Remote desktop protocols such as
# RDP/VNC could be abused in this way by smuggling to the connected host implant files, etc.
#
# In case a directory was specified on input, will recursively add every file from that directory
# and create a Zip archive that will be later uploaded.
#
# Mouse movements will suspend file upload process.
#
# Average transfer bandwidths largely depend on your connectivity performance and system utilization.
# I've experienced following:
#   - transfer to the Citrix Receiver RDP session: 40-60 bytes/s
#   - transfer to LAN RDP session RDP session: 400-800 bytes/s
#
# Requirements:
#   - pyautogui
#   - tqdm
#
# Author:
#   Mariusz Banach / mgeeky (@mariuszbit), '20
#   <mb [at] binary-offensive.com>
#

import os
import sys
import time
import hashlib
import base64
import zipfile
import argparse
from io import BytesIO

try:
    import pyautogui
except ImportError:
    print('[!] Module "pyautogui" not found. Install it using: pip3 install pyautogui')
    sys.exit(1)

try:
    import tqdm
except ImportError:
    print('[!] Module "tqdm" not found. Install it using: pip3 install tqdm')
    sys.exit(1)

config = {
	'debug': True,
	'verbose': True,
    'wait' : 10,
    'interval' : 5,
    'delay' : 0.5,
    'base64' : 10,
    'zip' : 10,
    'chunk' : 256,

    # Specifies what's the maximum mouse cursor position offset deviation (in pixels)
    # that will be tolerated and won't interrupt file upload/retype loop.
    # If mouse cursor will leave the N x N rectangle, we'll stop uploading/retyping.
    'maxMouseDeviationInPixels' : 50,

    'file' : '',
    'format': '',
}

outputFormats = {
    'raw',
    'certutil',
}

fileWasEncoded = False
progressBar = None

class Logger:
    @staticmethod
    def _out(x): 
        sys.stdout.write(x + '\n')

    @staticmethod
    def verbose(x): 
        if config['verbose']:
            Logger._out('[*] ' + x)
    
    @staticmethod
    def info(x):
        Logger._out('[.] ' + x)

    @staticmethod
    def dbg(x):
        if config['debug']:
            Logger._out('[dbg] ' + x)
    
    @staticmethod
    def err(x): 
        sys.stdout.write('[!] ' + x + '\n')
    
    @staticmethod
    def fail(x):
        Logger._out('[-] ' + x)
    
    @staticmethod
    def ok(x):  
        Logger._out('[+] ' + x)

class InMemoryZip(object):
    # Source: 
    #   - https://www.kompato.com/post/43805938842/in-memory-zip-in-python
    #   - https://stackoverflow.com/a/2463818

    def __init__(self):
        self.in_memory_zip = BytesIO()

    def append(self, filename_in_zip, file_contents):
        zf = zipfile.ZipFile(self.in_memory_zip, "a", zipfile.ZIP_DEFLATED, False)
        zf.writestr(filename_in_zip, file_contents)
        for zfile in zf.filelist:
            zfile.create_system = 0

        return self

    def read(self):
        self.in_memory_zip.seek(0)
        return self.in_memory_zip.read()

def fetch_files(rootdir):
    imz = InMemoryZip()
    for folder, subs, files in os.walk(rootdir):
        for filename in files:
            real_path = os.path.join(folder, filename)
            with open(real_path, 'rb') as src:
                zip_path = real_path.replace(rootdir + '/', '')
                imz.append(zip_path, src.read())

    return imz.read()

def reformatOutput(contents):
    out = contents
    if config['format'] == 'certutil':
        out = b'-----BEGIN CERTIFICATE-----\r\n'
        for chunk in [contents[i:i + 64] for i in range(0, len(contents), 64)]:
            out += chunk + b'\r\n'

        out += b'-----END CERTIFICATE-----\r\n'

    try:
        Logger.dbg(f'''After reformatting output, data looks as follows:
----------------------------------------------------------------
{out}
----------------------------------------------------------------

''')
    except: pass

    return out

def checkChar(a):
    if a >= 0x20 or a <= 0x7f:
        return True

    if a in [0x0a, 0x0d, 9]:
        return True

    return False

def encodeFile(filePath, contents, dontZip):
    global fileWasEncoded
    encoded = contents

    if config['zip'] and not dontZip:
        imz = InMemoryZip()
        imz.append(os.path.basename(filePath), contents)
        encoded = imz.read()

    if config['base64'] or config['format'] == 'certutil':
        encoded = base64.b64encode(encoded)

    try:
        Logger.dbg(f'''After encoding data:
----------------------------------------------------------------
{encoded}
----------------------------------------------------------------

''')
    except: pass

    out = reformatOutput(encoded)

    for a in out:
        if not checkChar(a):
            Logger.err(f'After encoding file/directory contents we resulted with binary data ({a}). That\'s not supported.')
            return None

    fileWasEncoded = contents != out
    return out.decode('utf-8', 'ignore')

def splitFile(contents, chunkSize):
    for i in range(0, len(contents), chunkSize):
        yield contents[i:i+chunkSize]

def flush():
    time.sleep(2)
    sys.stdout.flush()
    sys.stderr.flush()

def progress(pos, total):
    t = tqdm.tqdm(total=total, unit='characters')
    if pos > 0: t.update(pos)
    return t

def retypeFile(contents):
    global progressBar

    retypeMousePos = pyautogui.position()
    pyautogui.click()

    Logger.verbose(f'Mouse position of assumed RDP session window: {retypeMousePos}')
    Logger._out('')

    progressBar = progress(0, len(contents))

    for chunk in splitFile(contents, config['chunk']):
        prevPos = pyautogui.position()

        if abs(prevPos.x - retypeMousePos.x) > config['maxMouseDeviationInPixels'] or \
            abs(prevPos.y - retypeMousePos.y) > config['maxMouseDeviationInPixels']:

            msg = "[?] Mouse cursor was moved away from initially focused position. File upload PAUSED.\n"
            msg += "    Press ENTER to resume upload or Ctrl-C to interrupt.\n"

            progressBar.write(msg)

            input('')

            progressBar.clear()
            progressBar.write(f"\n[?] Position your mouse cursor at the end of written text. Waiting {config['wait']} seconds to resume...\n")
            if config['wait'] > 0: time.sleep(config['wait'])

            retypeMousePos = pyautogui.position()
            pyautogui.click()
            progressBar.clear()
            progressBar.unpause()
            progressBar.refresh()
            
        pyautogui.write(chunk, interval = (float(config['interval']) / 1000.0))
        progressBar.update(len(chunk))

        if config['delay'] > 0: time.sleep(config['delay'])

    flush()
    Logger._out('')

def printInstructions(hash1, hash2, filePath):
    additional = ''
    basename = os.path.basename(filePath)
    inputFile = basename + '.txt' if fileWasEncoded else basename
    output = basename

    if config['zip']:
        output = basename + '.zip'

    if config['format'] == 'certutil':
        inputFile = basename + '.b64'
        additional = f'''
        *) Base64 decode file using certutil:
            cmd> certutil -decode {inputFile} {output}
'''
    
    elif config['format'] != 'certutil' and config['base64']:
        inputFile = basename + '.b64'
        additional = f'''
        *) Base64 decode file:
            $ cat {inputFile} | base64 -d > {output}
              or
            cmd> powershell -c "[IO.File]::WriteAllBytes('{output}', [Convert]::FromBase64String([IO.File]::ReadAllText('{inputFile}')))"
''' 

    if config['zip']:
        additional += f'''
        *) Unzip resulting file:
            $ unzip -d . {output}
              or
            PS> Expand-Archive -Path .\\{output} -Dest .
'''

    if hash1 != hash2:
        additional += f'''
        *) Verify MD5 sum of final form of uploaded file to expected original value {hash1}:
            $ md5sum {output}
              or
            PS> Get-FileHash .\\{output} -Algorithm MD5
'''

    Logger.verbose(f'''
    ================================================================
    B) After file was uploaded, next steps are:

        *) Using your text editor: save the file in a remote system as "{inputFile}"

        *) Verify MD5 sum of retyped file to base value {hash2}:
            $ md5sum {inputFile}
              or
            PS> Get-FileHash .\\{inputFile} -Algorithm MD5
        {additional}
''')

def parseOptions(argv):
    global config

    print('''
    :: RDP file upload utility via Keyboard emulation.
    Takes an input file/folder and retypes it into focused RDP session window.
    That effectively uploads the file into remote host over a RDP channel.

    Mariusz Banach / mgeeky '20, (@mariuszbit)
    <mb@binary-offensive.com>
''')

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <inputFile>')

    parser.add_argument('inputFile', help='Input file or directory to upload. In case of directory - all files will get zipped recursively and resulting zip file will be uploaded.')

    parser.add_argument('-v', '--verbose', action='store_true', help='Displays verbose output containing field steps to follow.')
    parser.add_argument('-D', '--debug', action='store_true', help='Display debug output.')

    parser.add_argument('-f', '--format', choices=outputFormats, default='raw', help=f'Specifies into which format retype input file. Default: retype the file as is. "certutil" format implies --base64')

    timing = parser.add_argument_group('Timing & Performance', 'Adjusts settings impacting program\'s "upload" efficiency')
    timing.add_argument('-w', '--wait', type=int, default=config['wait'], help=f'Hold on before we start retyping file contents for this long (in seconds). Default: {config["wait"]} seconds.')
    timing.add_argument('-i', '--interval', type=int, default=config['interval'], help=f'Adjusts inter-key press interval (in milliseconds). Default: {config["interval"]} miliseconds.')
    timing.add_argument('-d', '--delay', type=int, default=config['delay'], help=f'Every next chunk (of size {config["chunk"]} bytes) wait this amount of time. Default: {config["delay"]} miliseconds.')

    encoding = parser.add_argument_group('Encoding', 'Controls how to encode the file before retyping it')
    encoding.add_argument('-b', '--base64', action='store_true', help='Encode and then retype base64 encoded file contents.')
    encoding.add_argument('-z', '--zip', action='store_true', help='Zip file contents before retyping them. If used with --base64 will retype results of base64(zip(file))')

    args = parser.parse_args()

    if not hasattr(args, 'inputFile') or args.inputFile is None:
        parser.print_help()
        return None

    config['verbose'] = args.verbose
    config['debug'] = args.debug

    if args.debug: config['verbose'] = True

    config['interval'] = args.interval
    config['format'] = args.format
    config['wait'] = args.wait
    config['zip'] = args.zip
    config['base64'] = args.base64

    if args.interval < 5:
        Logger.fail('WARNING: Setting too low inter-key press interval may result in keys being lost in the transit!')
        Logger.fail('         Be sure to verify uploaded file\'s md5 checksum!\n')

    return args

def main(argv):
    opts = parseOptions(argv)

    if not opts:
        return False

    contents = None
    dontZip = False
    t = 'file'

    try:
        if os.path.isfile(opts.inputFile):
            with open(opts.inputFile, 'rb') as f:
                contents = f.read()

        elif os.path.isdir(opts.inputFile):
            contents = fetch_files(rootdir)

            t = 'directory'
            dontZip = True

        else:
            Logger.err("Specified input file is neither a file nor directory (or it doesn't exist)!")
            return False

    except:
        Logger.err(f'Could not open file for reading: "{opts.inputFile}"')
        return False

    if contents == None or len(contents) == 0:
        Logger.fail("Specified file/directory was empty.")
        return False

    encoded = encodeFile(opts.inputFile, contents, dontZip)

    if encoded == None or len(encoded) == 0:
        Logger.fail("No encoded data to upload.")
        return False

    Logger.ok(f'Will upload {t}\'s contents: "{opts.inputFile}"\n')

    hash1 = hashlib.md5(contents).hexdigest()
    hash2 = hashlib.md5(encoded.encode()).hexdigest()

    Logger.ok('MD5 checksum of file to be uploaded:        ' + hash1)
    Logger.ok('MD5 checksum of encoded data to be retyped: ' + hash2)
    Logger.info(f'Size of input {t}: {len(contents)} - keys to retype: {len(encoded)}')
    Logger.verbose(f'Inter-key press interval: {opts.interval} miliseconds.')
    Logger.verbose(f'Every chunk cooldown delay: {1000*opts.delay} miliseconds.')
    del contents

    Logger.verbose('''
    ================================================================
    A) How to proceed now:

        1) In your RDP session, spawn a text editor (notepad, vim)
        2) Click inside of a text area as you were about to write something.
        3) Leave your mouse cursor in that RDP session window (client) having that window focused
''')

    Logger.info('Do not use your mouse/keyboard until file upload is completed!\n')
    Logger.ok('We\'re about to initiate upload process.')

    try:
        Logger.info(f'Waiting {config["wait"]} seconds before we begin...\n')

        time.sleep(opts.wait)

        Logger.ok('Starting file retype/upload...')

        retypeFile(encoded)

        Logger._out('')
        Logger.ok("FILE UPLOADED.")

        printInstructions(hash1, hash2, opts.inputFile)

    except KeyboardInterrupt:
        progressBar.clear()
        flush()
        Logger._out('')
        Logger.fail("FILE WAS NOT FULLY UPLOADED. User has interrupted file retype/upload process!\n")

        return False

    flush()
    progressBar.clear()
    return True

if __name__ == '__main__':
    main(sys.argv) 
