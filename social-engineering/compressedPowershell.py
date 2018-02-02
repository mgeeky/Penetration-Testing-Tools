#!/usr/bin/python3

import io
import sys
import gzip
import base64

def main(argv):
    if len(argv) < 2:
        print('Usage: ./compressedPowershell.py <input>')
        sys.exit(-1)

    out = io.BytesIO()
    encoded = ''
    with open(argv[1], 'rb') as f:
        inp = f.read()

        with gzip.GzipFile(fileobj = out, mode = 'w') as fo:
            fo.write(inp)

        encoded = base64.b64encode(out.getvalue())

    powershell = '''$s = New-Object IO.MemoryStream(, [Convert]::FromBase64String("{}"));

IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'''.format(encoded.decode())

    print(powershell)

if __name__ == '__main__':
    main(sys.argv)
