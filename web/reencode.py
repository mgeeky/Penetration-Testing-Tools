#!/usr/bin/python

# 
# ReEncoder.py - script allowing for recursive encoding detection, decoding and then re-encoding. 
# To be used for instance in fuzzing purposes.
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

import re
import sys
import jwt
import math
import base64
import urllib
import string
import anytree
import binascii
from collections import Counter


class ReEncoder:

    # Switch this to show some verbose informations about decoding process.
    DEBUG = False

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

            if re.match(r'^(?:%[0-9a-f]{2})+$', data, re.I):
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
                    return True
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
                    return True
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

            # None must always be the last detector
            ReEncoder.NoneEncoder(),
        )
        self.encodersMap = {}
        self.data = ''

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
        weights = {
            'printableChars' : 10.0,
            'highEntropy' : 4.0,
            'length' : 1.0
        }

        candidates = self.formEncodingCandidates(root)
        maxCandidate = 0

        for i in range(len(candidates)):
            candidate = candidates[i]

            name = candidate[0]
            decoded = candidate[1]
            points = float(candidate[2])

            ReEncoder.log('[=] Evaluating candidate: {} (data: "{}")'.format(
                name, decoded
            ))

            # Step 1: Adding points for printable percentage.
            printables = sum([int(x in string.printable) for x in decoded])
            printablePoints = weights['printableChars'] * (float(printables) / float(len(decoded)))
            ReEncoder.log('\tAdding {} points for printable characters.'.format(printablePoints))
            points += printablePoints

            # Step 4: If encoder is Base64 and was previously None
            #    - then length and entropy of previous values should be of slighly lower weights
            if name.lower() == 'none' \
                and len(candidates) > i+1 \
                and candidates[i+1][0].lower().startswith('base64'):
                entropyPoints = ReEncoder.entropy(decoded) * (weights['highEntropy'] * 0.75)
                lengthPoints = float(len(decoded)) * (weights['length'] * 0.75)
            else:
                entropyPoints = ReEncoder.entropy(decoded) * weights['highEntropy']
                lengthPoints = float(len(decoded)) * weights['length']

            # Step 2: Add points for entropy
            ReEncoder.log('\tAdding {} points for high entropy.'.format(entropyPoints))
            points += entropyPoints

            # Step 3: Add points for length
            ReEncoder.log('\tAdding {} points for length.'.format(lengthPoints))
            points += lengthPoints
            
            ReEncoder.log('\tScored in total: {} points.'.format(points))
            candidates[i][2] = points

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

        ReEncoder.log('[+] Winning decode path is:\n{}'.format(str(winningPath)))

        encodings = [x.name for x in winningPath.path if x != 'None']

        return encodings

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
            ReEncoder.log("%s%s (%s)" % (pre, node.name, node.decoded[:20].decode('ascii', 'ignore')))

        self.encodings = self.evaluateEncodingTree(root)
        ReEncoder.log('[+] Selected encodings: {}'.format(str(self.encodings)))

    def decode(self, data, encodings = []):
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
    sample = '4a5451344a5459314a545a6a4a545a6a4a545a6d4a5449774a5463334a545a6d4a5463794a545a6a4a5459304a5449784a5449774a544e684a544a6b4a544935'

    if len(argv) != 2:
        print('Usage: reencode.py <text>')
        print('Using sample: "{}"'.format(sample))
        text = sample
    else:
        text = argv[1]

    decoder = ReEncoder()
    decoded = decoder.decode(text)
    
    print('(1) DECODED TEXT: "{}"'.format(decoded))
    
    decoded = 'FOO ' + decoded + ' BAR'
    
    print('\n(2) TO BE ENCODED TEXT: "{}"'.format(decoded))
    
    decoded = decoder.encode(decoded)
    print('(3) ENCODED FORM: "{}"'.format(decoded))

if __name__ == '__main__':
    main(sys.argv)