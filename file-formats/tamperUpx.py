#!/usr/bin/python3

import pefile
import string
import os, sys


def tamperUpx(outfile):
    pe = pefile.PE(outfile)

    newSectionNames = (
        '.text',
        '.data',
        '.rdata',
        '.idata',
        '.pdata',
    )

    num = 0
    sectnum = 0

    section_table_offset = (pe.DOS_HEADER.e_lfanew + 4 + 
        pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader)

    found = 0

    print('Step 1. Renaming UPX sections...')
    for sect in pe.sections:
        section_offset = section_table_offset + sectnum * 0x28
        sectnum += 1

        if sect.Name.decode().lower().startswith('upx'):
            found += 1
            newname = newSectionNames[num].encode() + ((8 - len(newSectionNames[num])) * b'\x00')
            print('\tRenamed UPX section ({}) => ({})'.format(
                sect.Name.decode(), newSectionNames[num]
            ))
            num += 1
            pe.set_bytes_at_offset(section_offset, newname)

    print('\nStep 2. Removing obvious indicators...')
    pos = pe.__data__.find(b'UPX!')

    if pos != -1:
        found += 1
        print('\tRemoved "UPX!" (UPX_MAGIC_LE32) magic value...')
        pe.set_bytes_at_offset(pos, b'\x00' * 4)

        prev = pe.__data__[pos-5:pos-1]
        if all(chr(c) in string.printable for c in prev):
            print('\tRemoved "{}" indicator...'.format(prev.decode()))
            pe.set_bytes_at_offset(pos-5, b'\x00' * 4)

        print('\nStep 3. Corrupting PackHeader...')

        version = pe.__data__[pos + 4]
        _format = pe.__data__[pos + 5]
        method = pe.__data__[pos + 6]
        level = pe.__data__[pos + 7]

        print('\tOverwriting metadata (version={}, format={}, method={}, level={})...'.format(
            version, _format, method, level
        ))

        pe.set_bytes_at_offset(pos + 4, b'\x00')            
        pe.set_bytes_at_offset(pos + 5, b'\x00')            
        pe.set_bytes_at_offset(pos + 6, b'\x00')            
        pe.set_bytes_at_offset(pos + 7, b'\x00')

        #
        # Src:
        #   https://github.com/upx/upx/blob/36670251fdbbf72f6ce165148875d369cae8f415/src/packhead.cpp#L187
        #   https://github.com/upx/upx/blob/36670251fdbbf72f6ce165148875d369cae8f415/src/stub/src/include/header.S#L33
        #
        u_adler = pe.get_dword_from_data(pe.__data__, pos + 8)
        c_adler = pe.get_dword_from_data(pe.__data__, pos + 12)
        u_len = pe.get_dword_from_data(pe.__data__, pos + 16)
        c_len = pe.get_dword_from_data(pe.__data__, pos + 20)
        origsize = pe.get_dword_from_data(pe.__data__, pos + 24)
        filter_id = pe.__data__[pos + 28]
        filter_cto = pe.__data__[pos + 29]
        unused = pe.__data__[pos + 30]
        header_chksum = pe.__data__[pos + 31]

        print('\tCorrupting stored lengths and sizes:')

        print('\t\t- uncompressed_adler (u_adler): ({} / 0x{:x}) => (0)'.format(u_adler, u_adler))
        pe.set_dword_at_offset(pos + 8, 0)
        print('\t\t- compressed_adler (c_adler): ({} / 0x{:x}) => (0)'.format(c_adler, c_adler))
        pe.set_dword_at_offset(pos + 12, 0)
        print('\t\t- uncompressed_len (u_len): ({} / 0x{:x}) => (0)'.format(u_len, u_len))
        pe.set_dword_at_offset(pos + 16, 0)            
        print('\t\t- compressed_len (c_len): ({} / 0x{:x}) => (0)'.format(c_len, c_len))
        pe.set_dword_at_offset(pos + 20, 0) 
        print('\t\t- original file size: ({} / 0x{:x}) => (0)'.format(origsize, origsize))
        pe.set_dword_at_offset(pos + 24, 0) 
        print('\t\t- filter id: ({} / 0x{:x}) => (0)'.format(filter_id, filter_id))
        pe.set_bytes_at_offset(pos + 28, b'\x00')
        print('\t\t- filter cto: ({} / 0x{:x}) => (0)'.format(filter_cto, filter_cto))
        pe.set_bytes_at_offset(pos + 29, b'\x00')
        print('\t\t- unused: ({} / 0x{:x}) => (0)'.format(unused, unused))
        pe.set_bytes_at_offset(pos + 30, b'\x00')
        print('\t\t- header checksum: ({} / 0x{:x}) => (0)'.format(header_chksum, header_chksum))
        pe.set_bytes_at_offset(pos + 31, b'\x00')

    if found > 0:
        pe.parse_sections(section_table_offset)
        pe.write(outfile)

        print('\n[+] UPX-protected executable corrupted: ' + outfile)
        return True

    else:
        print('\n[-] Input file does not resemble UPX packed executable (or it was already corrupted)')
        return False

def main(argv):
    print('''
    :: tamperUpx - a small utility that corrupts UPX-packed executables, 
    making them much harder to be decompressed & restored.

    Mariusz Banach / mgeeky, '21
''')

    if len(argv) < 2:
        print('Usage: ./tamperUpx.py <infile> [outfile]')

    infile = argv[1]
    outfile = ''

    if len(argv) >= 3:
        outfile = argv[2]

    if not os.path.isfile(infile):
        print('[!] Input file does not exist.')
        return 1

    if len(outfile) > 0:
        with open(outfile, 'wb') as f:
            with open(infile, 'rb') as g:
                f.write(g.read())
    else:
        outfile = infile

    if tamperUpx(outfile):
        print('[+] Success. UPX should have some issues decompressing output artifact now.')

if __name__ == '__main__':
    main(sys.argv)