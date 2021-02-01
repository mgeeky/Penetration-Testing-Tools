## Windows penetration testing related scripts, tools and Cheatsheets


- **`awareness.bat`** - Little and quick Windows Situational-Awareness set of commands to execute after gaining initial foothold (coming from APT34: https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html ) ([gist](https://gist.github.com/mgeeky/237b48e0bb6546acb53696228ab50794))

- **`Find-CLSIDForProgID.ps1`** - Tries to locate COM object's `ProgID` based on a given CLSID.

- **`find-system-and-syswow64-binaries.py`** - Finds files with specified extension in both System32 and SysWOW64 and then prints their intersection. Useful for finding executables (for process injection purposes) that reside in both directories (such as `WerFault.exe`)

- **`Force-PSRemoting.ps1`** - Forcefully enable WinRM / PSRemoting. [gist](https://gist.github.com/mgeeky/313c22def5c86d7a529f41e5b6ff79b8)

- **`GlobalProtectDisable.cpp`** - Global Protect VPN Application patcher allowing the Administrator user to disable VPN without Passcode. ([gist](https://gist.github.com/mgeeky/54ac676226a1a4bd9fd8653e24adc2e9))

    Currently supported versions:
    - 3.1.6.19
    - 5.0.3.29
    - 5.1.3.12

    Steps are following:
    
    1. Launch the application as an Administrator
    2. Read instructions carefully and press OK
    3. Right-click on GlobalProtect tray-icon
    4. Select "Disable"
    5. Enter some random meaningless password
    
    After those steps - the GlobalProtect will disable itself cleanly. 
    From now on, the GlobalProtect will remain disabled until you reboot the machine (or restart the PanGPA.exe process or PanGPS service).

- **`impacket-binaries.sh`** - Simple one-liner that downloads all of the Windows EXE impacket binaries put out in [Impacket Binaries](https://github.com/ropnop/impacket_static_binaries) repo. [gist](https://gist.github.com/mgeeky/2f990f14f1e7cf78fce21b8761234604)

- **`PE-library`** - Simple, lightweight PE (Windows Portable Executable format) structures parsing library that I'm using in my various projects.

- **`pth-carpet.py`** - Pass-The-Hash Carpet Bombing utility - trying every provided hash against every specified machine. ([gist](https://gist.github.com/mgeeky/3018bf3643f80798bde75c17571a38a9))

- **`rdpFileUpload.py`** - RDP file upload utility via Keyboard emulation. Uploads specified input file or directory, encodes it and retypes encoded contents by emulating keyboard keypresses into previously focused RDP session window. That will effectively transmit contents of the file onto the remote host without use of any sort of built-in file upload functionality. Remote desktop protocols such as RDP/VNC could be abused in this way by smuggling to the connected host implant files, etc. In case a directory was specified on input, will recursively add every file from that directory and create a Zip archive that will be later uploaded. Average transfer bandwidths largely depend on your connectivity performance and system utilization.
I've experienced following:
   * transfer to the Citrix Receiver RDP session: `40-60 bytes/s`
   * transfer to LAN RDP session RDP session: `400-800 bytes/s`

Use `--verbose` for additional _field steps explanation_ output.

Sample usage:
```
PS> python3 rdpFileUpload.py -v -f certutil README.md

    :: RDP file upload utility via Keyboard emulation.
    Takes an input file/folder and retypes it into focused RDP session window.
    That effectively uploads the file into remote host over a RDP channel.

    Mariusz B. / mgeeky '20, (@mariuszbit)
    <mb@binary-offensive.com>

[+] Will upload file's contents: "README.md"

[+] MD5 checksum of file to be uploaded:        442949e7bef67384161b511c2dd3e6bb
[+] MD5 checksum of encoded data to be retyped: 667fee7e6528bbd07075e2e54f7fee69
[.] Size of input file: 4993 - keys to retype: 6926
[*] Inter-key press interval: 5 miliseconds.
[*] Every chunk cooldown delay: 0.5 miliseconds.
[*]
    ================================================================
    A) How to proceed now:

        1) In your RDP session, spawn a text editor (notepad, vim)
        2) Click inside of a text area as you were about to write something.
        3) Leave your mouse cursor in that RDP session window (client) having that window focused

[.] Do not use your mouse/keyboard until file upload is completed!

[+] We're about to initiate upload process.
[.] Waiting 10 seconds before we begin...

[+] Starting file retype/upload...
[*] Mouse position of assumed RDP session window: Point(x=2422, y=1142)

100%|███████████████████████████████████████████████████████████████████| 6926/6926 [01:07<00:00, 45.52characters/s]

[+] FILE UPLOADED.
[*]
    ================================================================
    B) After file was uploaded, next steps are:

        *) Using your text editor: save the file in a remote system as "README.md.b64"

        *) Verify MD5 sum of retyped file to base value 667fee7e6528bbd07075e2e54f7fee69:
            $ md5sum README.md.b64
              or
            PS> Get-FileHash .\README.md.b64 -Algorithm MD5

        *) Base64 decode file using certutil:
            cmd> certutil -decode README.md.b64 README.md

        *) Verify MD5 sum of final form of uploaded file to expected original value 442949e7bef67384161b511c2dd3e6bb:
            $ md5sum README.md
              or
            PS> Get-FileHash .\README.md -Algorithm MD5
```

- **`revshell.c`** - Utterly simple reverse-shell, ready to be compiled by `mingw-w64` on Kali. No security features attached, completely not OPSEC-safe.

- **`Simulate-DNSTunnel.ps1`** - Performs DNS Tunnelling simulation for purpose of triggering installed Network IPS and IDS systems, generating SIEM offenses and picking up Blue Teams.

- **`UnhookMe`** - Dynamically unhooking imports resolver. Implementation of dynamic imports resolver that would be capable of unhooking used functions in-the-fly is yet another step towards strengthening adversary resilience efforts. 

```
[~] Resolved symbol kernel32.dll!CreateFileA
[~] Resolved symbol kernel32.dll!ReadProcessMemory
[~] Resolved symbol kernel32.dll!MapViewOfFile
[~] Resolved symbol kernel32.dll!VirtualProtectEx
[#] Found trampoline hook in symbol: MessageBoxW . Restored original bytes from file.
[~] Resolved symbol user32.dll!MessageBoxW
```


- **`win-clean-logs.bat`** - Batch script to hide malware execution from Windows box. Source: Mandiant M-Trends 2017. ([gist](https://gist.github.com/mgeeky/3561be7e697c62f543910851c0a26d00))
