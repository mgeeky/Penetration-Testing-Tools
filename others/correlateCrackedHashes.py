#!/usr/bin/python3
#
# Takes two files on input. Tries to find every line of the second file within the first file
# and for every found match - extracts password value from the second file's line. Then prints these correlations.
#
# In other words:
#
#     FileA:
#         some-user@example.com,68eacb97d86f0c4621fa2b0e17cabd8c
#   
#     FileB - result of running hashcat:
#         68eacb97d86f0c4621fa2b0e17cabd8c:Test123
#
#     WILL RETURN:
#         some-user@example.com,68eacb97d86f0c4621fa2b0e17cabd8c,Test123
#        
# Mariusz Banach / mgeeky
#

import sys, os

def main(argv):
    if len(argv) < 3:
        print('''
Usage: ./correlateCrackedHashes.py <fileWithUsernames> <crackedHashesFile> [delimiter]

    <fileWithUsernames> - File containing usernames and their hashes (or just hashes)
    <crackedHashesFile> - File being a result of running hashcat, in a form of hash:password
    [delimiter]         - (optional) Delimiter to be prepended to the usernames file line containing password
                            Default: comma
        ''')
        return False

    usernamesFile = argv[1]
    crackedHashesFile = argv[2]
    delimiter = ',' if len(argv) < 4 else argv[3]

    if not os.path.isfile(usernamesFile):
        print(f'[!] Usernames file does not exist: "{usernamesFile}')
        return False

    if not os.path.isfile(crackedHashesFile):
        print(f'[!] Cracked passwords file does not exist: "{crackedHashesFile}')
        return False

    usernames = []
    cracked = []

    with open(usernamesFile) as f: usernames = [x.strip() for x in f.readlines()]
    with open(crackedHashesFile) as f: cracked = [x.strip() for x in f.readlines()]

    correlated = []

    for crackedPass in cracked:
        for user in usernames:
            posOfLastColon = crackedPass.rfind(':')
            hashValue = crackedPass[:posOfLastColon]
            password = crackedPass[posOfLastColon+1:]

            if hashValue in user:
                print(delimiter.join([user, password]))
                correlated.append(delimiter.join([user, password]))

if __name__ == "__main__":
    main(sys.argv)