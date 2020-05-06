### A small collection of unobfuscated code-execution primitives in different languages

A handy collection of small primitives/templates useulf for code-execution, downloading or otherwise offensive purposes. Whenever a quick sample of VBScript/JScript/C# code is needed - this directory should bring you one.

Windows Script Host (WSH) subsystem can execute VBScript/JScript scritplets using two pre-installed interpreters:

- `cscript.exe` - to be used for command-line, dynamic script execution. **Doesn't load AMSI**

- `wscript.exe` - For general scripts execution. **This one loads AMSI**


#### VBScript

- **`download-file-and-exec.vbs`** - Downloads a binary file using `Msxml2.ServerXMLHTTP`, stores it to the disk `Adodb.Stream` and then launches it via `Wscript.Shell Run`

- **`wmi-exec-command.vbs`** - Example of VBScript code execution via WMI class' `Win32_Process` static method `Create`

- **`wscript-shell-code-exec.vbs`** - Code execution via `WScript.Shell` in a hidden window.

- **`wscript-shell-stdin-code-exec.vbs`** - Code execution via `WScript.Shell` in a hidden window through a command passed from StdIn to `powershell`


#### JScript


#### XSL

XSL files can be executed in the following ways:

- Using `wmic.exe`:
```
wmic os get /format:"jscript-xslt-template.xsl"
```

Templates:

- **`hello-world-jscript-xslt.xsl`** - A sample backbone for XSLT file with JScript code showing a simple message box.

- **`wscript-shell-run-jscript-xslt.xsl`** - JScript XSLT with `WScript.Shell.Run` method



#### COM Scriptlets

Sample code execution with `regsvr32` can be following:
```
regsvr32 /u /n /s /i:wscript-shell-run-jscript-scriptlet.sct scrobj.dll
```

- **`wscript-shell-run-jscript-scriptlet.sct`** - SCT file with JSCript code execution via `WScript.Shell.Run`


#### HTA

HTA files are HTML Applications

- **`wscript-shell-run-vbscript.hta`** - A backbone for `WScript.Shell.Run` via _VBScript_ 