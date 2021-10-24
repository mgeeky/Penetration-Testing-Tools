#!/usr/bin/python3

import os, sys, re
import string
import argparse
import yaml
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

options = {
    'gophish_addr': '',
    'token' : '',
    'file' : '',
    'template_name' : '',
    'subject': '',
    'first_name': '',
    'last_name': '',
    'position': '',
    'sender': '',
    'recipient': '',
    'url' : '',
    'dont_restore' : False
}

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36',
    'Authorization': '',
}

def get(url):
    r = requests.get(
        f"{options['gophish_addr']}" + url,
        headers = headers,
        verify = False
    )

    if r.status_code != 200:
        print(f'[!] URL: {url} returned status code: {r.status_code}!')
        print(r.json())
        sys.exit(1)

    return r.json()

def put(url, data):
    r = requests.put(
        f"{options['gophish_addr']}" + url,
        headers = headers,
        json = data,
        verify = False
    )

    if r.status_code != 200:
        print(f'[!] URL: {url} returned status code: {r.status_code}!')
        print(r.json())
        sys.exit(1)
        
    return r.json()

def post(url, data):
    r = requests.post(
        f"{options['gophish_addr']}" + url,
        headers = headers,
        json = data,
        verify = False
    )

    if r.status_code != 200:
        print(f'[!] URL: {url} returned status code: {r.status_code}!')
        print(r.json())
        sys.exit(1)
        
    return r.json()

def getTemplate():
    out = get("/api/templates/?{}")

    for obj in out:
        if obj['name'] == options['template_name']:
            return obj

    print(f'[!] Could not find template named: "{options["template_name"]}"!')
    sys.exit(1)

def updateTemplate(template, html):
    obj = {}
    obj.update(template)
    obj['html'] = html

    if len(options['subject']) > 0:
        obj['subject'] = options['subject']

    out = put(f'/api/templates/{template["id"]}', obj)

def sendEmail():
    obj = {
        "template":{
            "name": options['template_name']
        },

        "first_name": options['first_name'],
        "last_name": options['last_name'],
        "email": options['recipient'],
        "position": options['position'],
        "url":options['url'],
        "page": {
            "name": ""
        },
        "smtp": {
            "name": options['sender']
        }
    }

    out = post('/api/util/send_test_email', obj)

    if out['success']:
        print('[+] ' + out['message'])
    else:
        print('[!] ' + out['message'])

def opts(argv):
    global options
    global headers

    o = argparse.ArgumentParser(
        usage = 'gophish-send-mail.py [options] <config.yaml>'
    )
    
    req = o.add_argument_group('Required arguments')
    req.add_argument('config', help = 'YAML config file')

    args = o.parse_args()

    op = None
    with open(args.config, encoding='utf-8') as f:
        op = yaml.safe_load(f)

    for k in (
        'gophish_addr', 
        'token', 
        'file', 
        'template_name',
        'recipient',
        'sender'
    ):
        if k not in op.keys():
            print(f'[!] {k} not specified!')
            sys.exit(1)

    if op['gophish_addr'][-1] == '/':
        op['gophish_addr'] = op['gophish_addr'][:-1]

    headers['Authorization'] = f'Bearer {op["token"]}'

    options.update(op)
    return op

def main(argv):
    args = opts(argv)
    if not args:
        return False

    print('''
    :: GoPhish Single Mail Send utility
    Helping you embellish your emails by sending them one-by-one
    Mariusz Banach / mgeeky
''')

    template = getTemplate()

    print(f'''[+] Template to use:
    ID:      {template["id"]}
    Name:    {template["name"]}
    Subject: {template["subject"]}
''')

    print(f'[.] Updating it with file "{options["file"]}"...')

    html = ''
    with open(options['file'], 'rb') as f:
        html = f.read()

    updateTemplate(template, html.decode())

    print('[+] Template updated.')

    print(f'''[.] Sending e-mail via Campaign -> Send Test Email...
    From:      {options['sender']}
    Recipient: {options['recipient']}
''')
    sendEmail()

    if not options['dont_restore']:
        print('[.] Restoring template...')
        updateTemplate(template, template['html'])

    print('[+] Finished.')

if __name__ == '__main__':
    main(sys.argv)
