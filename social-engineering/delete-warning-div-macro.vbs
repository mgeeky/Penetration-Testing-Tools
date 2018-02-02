Private Sub DeleteWarningPicture(ByVal textBoxName As String, ByVal saveDocAfter As Boolean)
    Dim shape As Word.shape
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