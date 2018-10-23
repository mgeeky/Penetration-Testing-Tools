#!/usr/bin/python

# 
# ReEncoder.py - script allowing for recursive encoding detection, decoding and then re-encoding. 
# To be used for instance in fuzzing purposes. Imagine you want to fuzz XML parameters within 
# **PaReq** packet of 3DSecure standard. This packet has been ZLIB compressed, then Base64 encoded, 
# then URLEncoded. In order to modify the inner XML you would need to peel off that encoding layers 
# and then reaplly them in reversed order. This script allows you to do that in an automated manner
# 
# NOTICE:
#   If the input string's length is divisble by 4, Base64 will be able to decode it - thus, the script
#   would wrongly assume it has been encoded using Base64. The same goes for Hex decoding.
#   In order to tackle this issue, the script builds up a tree of possible encoding schemes and then evaluate
#   that tree by choosing the best fitting encodings path (with most points counted upon resulted text's length,
#   entropy and printable'ity).
#
# Requires:
#   - jwt
#   - anytree
#
# Mariusz B., 2018
#

import os
import re
import sys
import jwt
import zlib
import math
import base64
import urllib
import string
import anytree
import binascii
from collections import Counter




# =============================================
# RE-ENCODER'S IMPLEMENTATION
#


class ReEncoder:

    # Switch this to show some verbose informations about decoding process.
    DEBUG = True

    PREFER_AUTO = 0     # Automatically determine final output format
    PREFER_TEXT = 1     # Prefer text/printable final output format
    PREFER_BINARY = 2   # Prefer binary final output format

    class Utils:
        @staticmethod
        def isBinaryData(data):
            nonBinary = 0
            percOfBinaryToAssume = 0.10

            for d in data:
                c = ord(d)
                if c in (10, 13): 
                    nonBinary += 1
                elif c >= 0x20 and c <= 0x7f:
                    nonBinary += 1

            binary = len(data) - nonBinary
            return binary >= int(percOfBinaryToAssume * len(data))

    # ============================================================
    # ENCODERS SECTION
    #

    class Encoder:
        def name(self):
            raise NotImplementedError

        def check(self, data):
            raise NotImplementedError
            
        def encode(self, data):
            raise NotImplementedError

        def decode(self, data):
            raise NotImplementedError

    class NoneEncoder(Encoder):
        def name(self):
            return 'None'

        def check(self, data):
            if not data:
                return False
            return True
            
        def encode(self, data):
            return data

        def decode(self, data):
            return data

    class URLEncoder(Encoder):
        def name(self):
            return 'URLEncoder'

        def check(self, data):
            if urllib.quote(urllib.unquote(data)) == data and (urllib.unquote(data) != data):
                return True

            if re.search(r'(?:%[0-9a-f]{2})+', data, re.I):
                return True

            return False
            
        def encode(self, data):
            return urllib.quote(data)

        def decode(self, data):
            return urllib.unquote(data)

    class HexEncoder(Encoder):
        def name(self):
            return 'HexEncoded'

        def check(self, data):
            m = re.match(r'^[0-9a-f]+$', data, re.I)
            if m:
                return True
            return False
            
        def encode(self, data):
            return binascii.hexlify(data).strip()

        def decode(self, data):
            return binascii.unhexlify(data).strip()

    class Base64Encoder(Encoder):
        def name(self):
            return 'Base64'

        def check(self, data):
            try:
                if base64.b64encode(base64.b64decode(data)) == data:
                    m = re.match('^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$', data, re.I)
                    if m: 
                        return True
                    return False
            except:
                pass
            return False
            
        def encode(self, data):
            return base64.b64encode(data)

        def decode(self, data):
            return base64.b64decode(data)

    class Base64URLSafeEncoder(Encoder):
        def name(self):
            return 'Base64URLSafe'

        def check(self, data):
            try:
                if base64.urlsafe_b64encode(base64.urlsafe_b64decode(data)) == data:
                    m = re.match('^(?:[A-Za-z0-9\-_]{4})*(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=|[A-Za-z0-9\-_]{4})$', data, re.I)
                    if m: 
                        return True
                    return False
            except:
                pass
            return False
            
        def encode(self, data):
            return base64.urlsafe_b64encode(data)

        def decode(self, data):
            return base64.urlsafe_b64decode(data)

    class JWTEncoder(Encoder):
        secret = ''

        def name(self):
            return 'JWT'

        def check(self, data):
            try:
                jwt.decode(data, verify = False)
                return True
            except jwt.exceptions.DecodeError:
                return False
            
        def encode(self, data):
            return jwt.encode(data, JWTEncoder.secret)

        def decode(self, data):
            return jwt.decode(data, verify = False)

    class ZlibEncoder(Encoder):
        def name(self):
            return 'ZLIB'

        def check(self, data):
            if not ReEncoder.Utils.isBinaryData(data):
                return False

            try:
                if zlib.compress(zlib.decompress(data)) == data:
                    return True
            except:
                pass
            return False
            
        def encode(self, data):
            return zlib.compress(data)

        def decode(self, data):
            return zlib.decompress(data)



    # ============================================================
    # ENCODING DETECTION IMPLEMENTATION
    #

    MaxEncodingDepth = 20

    def __init__(self):
        self.encodings = []
        self.encoders = (
            ReEncoder.URLEncoder(),
            ReEncoder.HexEncoder(),
            ReEncoder.Base64Encoder(),
            ReEncoder.Base64URLSafeEncoder(),
            ReEncoder.JWTEncoder(),
            ReEncoder.ZlibEncoder(),

            # None must always be the last detector
            ReEncoder.NoneEncoder(),
        )
        self.encodersMap = {}
        self.data = ''
        self.preferredOutputFormat = ReEncoder.PREFER_AUTO

        for encoder in self.encoders:
            self.encodersMap[encoder.name()] = encoder

    @staticmethod
    def log(text):
        if ReEncoder.DEBUG:
            print(text)

    def verifyEncodings(self, encodings):
        for encoder in encodings:
            if type(encoder) == str:
                if not encoder in self.encodersMap.keys():
                    raise Exception("Passed unknown encoder's name.")
            elif not issubclass(ReEncoder.Encoder, encoder):
                raise Exception("Passed encoder is of unknown type.")

    def generateEncodingTree(self, data):
        step = 0
        maxSteps = len(self.encoders) * ReEncoder.MaxEncodingDepth

        peeledBefore = 0
        peeledOff = 0
        currData = data

        while step < maxSteps:
            peeledBefore = peeledOff
            for encoder in self.encoders:
                step += 1

                ReEncoder.log('[.] Trying: {} (peeled off: {}). Current form: "{}"'.format(encoder.name(), peeledOff, currData))

                if encoder.check(currData):
                    if encoder.name() == 'None':
                        continue

                    if encoder.name().lower().startswith('base64') and (len(currData) % 4 == 0):
                        ReEncoder.log('[.] Unclear situation whether input ({}) is Base64 encoded. Branching.'.format(
                            currData
                        ))

                        yield ('None', currData, True)

                    if encoder.name().lower().startswith('hex') and (len(currData) % 2 == 0):
                        ReEncoder.log('[.] Unclear situation whether input ({}) is Hex encoded. Branching.'.format(
                            currData
                        ))

                        yield ('None', currData, True)

                    ReEncoder.log('[+] Detected encoder: {}'.format(encoder.name()))

                    currData = encoder.decode(currData)
                    yield (encoder.name(), currData, False)

                    peeledOff += 1

                    break

            if (peeledOff - peeledBefore) == 0: 
                break

    def formEncodingCandidates(self, root):
        iters = [[node for node in children] for children in anytree.LevelOrderGroupIter(root)]

        candidates = []

        for node in iters[-1]:
            name = node.name
            decoded = node.decoded

            ReEncoder.log('[.] Candidate for best decode using {}: "{}"...'.format(
                name, decoded[:20]
            ))

            candidates.append([name, decoded, 0.0])

        return candidates

    @staticmethod
    def entropy(data, unit='natural'):
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

    def evaluateEncodingTree(self, root):
        (printableEncodings, printableCandidate) = self.evaluateEncodingTreePicker(root, False)
        (binaryEncodings, binaryCandidate) = self.evaluateEncodingTreePicker(root, True)

        if self.preferredOutputFormat == ReEncoder.PREFER_TEXT:
            ReEncoder.log('Returning text/printable output format as requested preferred one.')
            return printableEncodings
        elif self.preferredOutputFormat == ReEncoder.PREFER_BINARY:
            ReEncoder.log('Returning binary output format as requested preferred one.')
            return binaryEncodings
        else:
            ReEncoder.log('Trying to determine preferred output format...')

        ReEncoder.log('\n---------------------------------------')
        ReEncoder.log('[>] Winning printable encoding path scored: {} points.'.format(
            printableCandidate[2]
        ))
        ReEncoder.log('[>] Winning binary encoding path scored: {} points.'.format(
            binaryCandidate[2]
        ))

        if(printableCandidate[2] >= binaryCandidate[2]):
            ReEncoder.log('\n[+] Choosing all-time winner: PRINTABLE output format.')
            return printableEncodings

        ReEncoder.log('\n[+] Choosing all-time winner: BINARY output format.')
        ReEncoder.log('---------------------------------------\n')
        return binaryEncodings

    def evaluateEncodingTreePicker(self, root, preferBinary):
        candidates = self._evaluateEncodingTreeWorker(root, preferBinary)

        maxCandidate = 0

        for i in range(len(candidates)):
            candidate = candidates[i]

            name = candidate[0]
            decoded = candidate[1]
            points = float(candidate[2])

            if points > candidates[maxCandidate][2]:
                maxCandidate = i

        winningCandidate = candidates[maxCandidate]
        winningPaths = anytree.search.findall_by_attr(
            root, 
            name = 'decoded',
            value = winningCandidate[1]
        )

        ReEncoder.log('[?] Other equally good candidate paths:\n' + str(winningPaths))
        winningPath = winningPaths[0]

        preferred = 'printable'
        if preferBinary:
            preferred = 'binary'

        ReEncoder.log('[+] Winning decode path for {} output is:\n{}'.format(
            preferred,
            str(winningPath))
        )

        encodings = [x.name for x in winningPath.path if x != 'None']
        return (encodings, winningCandidate)

    def _evaluateEncodingTreeWorker(self, root, preferBinary = False):
        weights = {
            'unreadableChars' : 0.0,
            'printableChars' : 9.6,
            'entropyScore' : 4.0,
            'length' : 1.0,
        }

        if preferBinary:
            weights['unreadableChars'] = 24.0
            weights['printableChars'] = 0.0
            weights['entropyScore'] = 2.666667

        candidates = self.formEncodingCandidates(root)

        for i in range(len(candidates)):
            candidate = candidates[i]

            name = candidate[0]
            decoded = candidate[1]
            points = float(candidate[2])
            entropy = ReEncoder.entropy(decoded)
            printables = sum([int(x in string.printable) for x in decoded])
            nonprintables = len(decoded) - printables

            ReEncoder.log('[=] Evaluating candidate: {} (entropy: {}, data: "{}")'.format(
                name, entropy, decoded
            ))

            # Step 1: Adding points for printable percentage.
            printablePoints = float(weights['printableChars']) * (float(printables) / float(len(decoded)))
            nonPrintablePoints = float(weights['unreadableChars']) * (float(nonprintables) / float(len(decoded)))

            # Step 2: If encoder is Base64 and was previously None
            #    - then length and entropy of previous values should be of slighly lower weights
            if name.lower() == 'none' \
                and len(candidates) > i+1 \
                and candidates[i+1][0].lower().startswith('base64'):
                ReEncoder.log('\tAdding fine for being base64')
                entropyPoints = entropy * (weights['entropyScore'] * 0.666666)
                lengthPoints = float(len(decoded)) * (weights['length'] * 0.666666)
            else:
                entropyPoints = entropy * weights['entropyScore']
                lengthPoints = float(len(decoded)) * weights['length']

            if printables > nonprintables:
                ReEncoder.log('More printable chars than binary ones.')
                ReEncoder.log('\tAdding {} points for printable entropy.'.format(entropyPoints))

                ReEncoder.log('\tAdding {} points for printable characters.'.format(printablePoints))
                points += printablePoints
            else:
                ReEncoder.log('More binary chars than printable ones.')
                ReEncoder.log('\tAdding {} points for binary entropy.'.format(entropyPoints))

                ReEncoder.log('\tAdding {} points for binary characters.'.format(nonPrintablePoints))
                points += nonPrintablePoints

            points += entropyPoints

            # Step 4: Add points for length
            ReEncoder.log('\tAdding {} points for length.'.format(lengthPoints))
            points += lengthPoints
            
            ReEncoder.log('\tScored in total: {} points.'.format(points))
            candidates[i][2] = points

        return candidates


    def getWinningDecodePath(self, root):
        return [x for x in self.evaluateEncodingTree(root) if x != 'None']

    def process(self, data):
        root = anytree.Node('None', decoded = data)
        prev = root

        for (name, curr, branch) in self.generateEncodingTree(data):
            ReEncoder.log('[*] Generator returned: ("{}", "{}", {})'.format(
                name, curr[:20], str(branch)
            ))

            currNode = anytree.Node(name, parent = prev, decoded = curr)
            if branch:
                pass
            else:
                prev = currNode

        for pre, fill, node in anytree.RenderTree(root):
            if node.name != 'None':
                ReEncoder.log("%s%s (%s)" % (pre, node.name, node.decoded[:20].decode('ascii', 'ignore')))

        self.encodings = self.getWinningDecodePath(root)
        ReEncoder.log('[+] Selected encodings: {}'.format(str(self.encodings)))

    def decode(self, data, preferredOutputFormat = PREFER_AUTO, encodings = []):
        self.preferredOutputFormat = preferredOutputFormat

        if preferredOutputFormat != ReEncoder.PREFER_AUTO and \
            preferredOutputFormat != ReEncoder.PREFER_TEXT and \
            preferredOutputFormat != ReEncoder.PREFER_BINARY:
            raise Exception('Unknown preferred output format specified in decode(): {}'.format(
                preferredOutputFormat
            ))

        if not encodings:
            self.process(data)
        else:
            self.verifyEncodings(encodings)
            self.encodings = encodings

        for encoderName in self.encodings:
            d = self.encodersMap[encoderName].decode(data)
            data = d

        return data

    def encode(self, data, encodings = []):
        if encodings:
            encodings.reverse()
            self.verifyEncodings(encodings)
            self.encodings = encodings

        for encoderName in self.encodings[::-1]:
            e = self.encodersMap[encoderName].encode(data)
            data = e

        return data


def main(argv):
    # Sample 1: ZLIB -> Base64 -> URLEncode
    sample = 'eJzzSM3JyVcozy%2FKSVFIK8rPVQhKdc1Lzk9JLVIEAIr8Cck%3D'

    # Sample 2: URLEncode -> Base64 -> HexEncode
    #sample = '4a5451344a5459314a545a6a4a545a6a4a545a6d4a5449774a5463334a545a6d4a5463794a545a6a4a5459304a5449784a5449774a544e684a544a6b4a544935'

    if len(argv) != 2:
        print('Usage: reencode.py <text|file>')
        print('Using sample: "{}"'.format(sample))
        text = sample
    else:
        text = argv[1]

        if os.path.isfile(text):
            f = open(text, 'rb')
            text = f.read()
            f.close()

    decoder = ReEncoder()
    decoded = decoder.decode(text)
    
    print('(1) DECODED TEXT: "{}"'.format(decoded))
    
    decoded = 'FOO ' + decoded + ' BAR'
    
    print('\n(2) TO BE ENCODED TEXT: "{}"'.format(decoded))
    
    decoded = decoder.encode(decoded)
    print('(3) ENCODED FORM: "{}"'.format(decoded))

if __name__ == '__main__':
    main(sys.argv)
