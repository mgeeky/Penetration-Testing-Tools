## File-Formats Penetration Testing related scripts, tools and Cheatsheets

- [**`PackMyPayload`**](https://github.com/mgeeky/PackMyPayload) - A script that takes file/directory on input and creates a new (or backdoors existing) container file with input ones embedded. Some of the formats (ISO, IMG, VHD, VHDX) could be used to bypass Mark-of-the-Web (MOTW) file taint flag. Supported formats: 
  1. `ZIP` (+password)
  2. `7zip` (+password)
  3. `PDF` (+password)
  4. `ISO` 
  5. `IMG` 
  6. `CAB` 
  7. `VHD` 
  8. `VHDX` 


- **`tamperUpx.py`** - A small utility that corrupts UPX-packed executables, making them much harder to be decompressed & restored.

```powershell
c:\>py -3 tamperUpx.py foo-upx.exe foo-upx-corrupted.exe

    :: tamperUpx - a small utility that corrupts UPX-packed executables,
    making them much harder to be decompressed & restored.

    Mariusz Banach / mgeeky, '21

Step 1. Renaming UPX sections...
        Renamed UPX section (UPX0    ) => (.text)
        Renamed UPX section (UPX1    ) => (.data)

Step 2. Removing obvious indicators...
        Removed "UPX!" (UPX_MAGIC_LE32) magic value...
        Removed "3.96" indicator...

Step 3. Corrupting PackHeader...
        Overwriting metadata (version=13, format=36, method=2, level=10)...
        Corrupting stored lengths and sizes:
                - uncompressed_adler (u_adler): (2044521623 / 0x79dcec97) => (0)
                - compressed_adler (c_adler): (2542804071 / 0x97901c67) => (0)
                - uncompressed_len (u_len): (1802399544 / 0x6b6e6f38) => (0)
                - compressed_len (c_len): (2653142051 / 0x9e23bc23) => (0)
                - original file size: (529611336 / 0x1f913a48) => (0)
                - filter id: (73 / 0x49) => (0)
                - filter cto: (5 / 0x5) => (0)
                - unused: (0 / 0x0) => (0)
                - header checksum: (197 / 0xc5) => (0)

[+] UPX-protected executable corrupted: foo-upx-corrupted.exe
[+] Success. UPX should have some issues decompressing output artifact now.
```

- **`zipcrack.rb`** - Simple multi-threaded ZIP cracker. ([gist](https://gist.github.com/mgeeky/f89262744fa37e9ec2351dccdc81b44c))
