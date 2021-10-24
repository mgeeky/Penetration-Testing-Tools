#!/usr/bin/python
#
# Simple XOR brute-force Key recovery script - given a cipher text, plain text and key length
# it searches for proper key that could decrypt cipher into text.
#
# Mariusz Banach, 2016
#

import sys

def xorstring(s, k):
    out = [0 for c in range(len(s))]
    key = []
    if type(k) == type(int):
        key = [k,]
    else:
        key = [ki for ki in k]

    for i in range(len(key)):
        for j in range(i, len(s), len(key)):
            out[j] = chr(ord(s[j]) ^ key[i])

    return ''.join(out)
        

def brute(input_xored, expected_output, key_len):
    key = []

    if len(input_xored) != len(expected_output):
        print '[!] Input xored and expected output lengths not match!'
        return False

    for i in range(key_len):
        cipher_letters = [ input_xored[x] for x in range(i, len(input_xored), key_len)]
        plaintext_letters = [ expected_output[x] for x in range(i, len(input_xored), key_len)]

        found = False
        for k in range(256):
            found = True
            for j in range(key_len):
                if chr(ord(cipher_letters[j]) ^ k) != plaintext_letters[j]:
                    found = False
                    break

            if found:
                key.append(k)
                break
            found = False

        if not found:
            print '[!] Could not found partial key value.'
            break

    return key, xorstring(input_xored, key) == expected_output

def main(argv):
    if len(argv) < 4:
        print 'Usage: %s <cipher> <plain> <key-len>'
        return False

    cipher = argv[1]
    plain = argv[2]
    keylen = int(argv[3])

    if len(cipher) != len(plain):
        print '[!] Cipher text and plain text must be of same length!'
        return False

    if len(cipher) % keylen != 0:
        print '[!] Cipher text and plain text lengths must be divisble by keylen!'
        return False

    print "Cipher text:\t%s" % cipher
    print "Plain text:\t%s" % plain
    print "Key length:\t%d" % keylen
    key, status = brute(cipher, plain, keylen)

    if status:
        print '[+] Key recovered!'
        print '\tKey:\t\t\t', str(key)
        print '\tDecrypted string:\t' + xorstring(cipher, key)
    else:
        print '[!] Key not found.'

if __name__ == '__main__':
    main(sys.argv)
