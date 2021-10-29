#!/usr/bin/python3

import os, sys, re
import string
import argparse
import json
import textwrap
import socket
import time
import glob
import base64

rules = {}
scanned = set()

def walk(path):
    global rules
    global scanned

    print(f'Walking {path}...')

    for file in glob.glob(os.path.join(path, '**'), recursive=True):
        if not file.lower().endswith('.txt'):
            continue

        if file in scanned: continue
        scanned.add(file)

        data = ''
        with open(file) as f:
            data = f.read()

        for m in re.finditer(r'(\(\d{4,}\))', data, re.I):
            rule = m.group(1)

            if rule in rules.keys():
                if file not in rules[rule]['files']:
                    rules[rule]['count'] += 1
                    rules[rule]['files'].add(file)
            else:
                rules[rule] = {}
                rules[rule]['count'] = 1
                rules[rule]['files'] = set([file, ])

def main(argv):

    paths = []
    for i in range(len(argv)):
        arg = argv[i]
        if i == 0: continue

        if not os.path.isdir(arg):
            print('[!] input path does not exist or is not a dir! ' + arg)
            sys.exit(1)

        walk(os.path.abspath(arg))

    print(f'[.] Found {len(rules)} unique rules.:')

    candidates = []
    for k, v in rules.items():
        if v['count'] > 1:
            print(f'\n\t- {k: <15}: occurences: {v["count"]} - files: {len(v["files"])}')

            if len(v['files']) < 6:
                for f in v['files']:
                    print('\t\t- ' + str(f))

if __name__ == '__main__':
    main(sys.argv)