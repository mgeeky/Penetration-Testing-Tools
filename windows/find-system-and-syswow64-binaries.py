#!/usr/bin/python3

import sys
import os
import glob

def main(argv):
    if len(argv) == 1:
        print('Usage: ./script <ext>')
        return False

    ext = argv[1]
    system32 = set()
    syswow64 = set()
    p1 = os.path.join(os.environ['Windir'], 'System32' + os.sep + '*.' + ext)
    p2 = os.path.join(os.environ['Windir'], 'SysWOW64' + os.sep + '*.' + ext)

    sys.stderr.write('[.] System32: ' + p1 + '\n')
    sys.stderr.write('[.] SysWOW64: ' + p2 + '\n')

    for file in glob.glob(p1):
        system32.add(os.path.basename(file))

    for file in glob.glob(p2):
        syswow64.add(os.path.basename(file))

    commons = system32.intersection(syswow64)
    sys.stderr.write(f"[.] Found {len(system32)} files in System32\n")
    sys.stderr.write(f"[.] Found {len(syswow64)} files in SysWOW64\n")
    sys.stderr.write(f"[.] Intersection of these two sets: {len(commons)}\n")

    for f in commons:
        print(f)

if __name__ == '__main__':
    main(sys.argv)