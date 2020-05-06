'
' This script uses classic WScript.Shell Run method to
' execute given command in a hidden window (second param = 0)
'
' Mariusz B. / mgeeky, <mb@binary-offensive.com>
' (https://github.com/mgeeky)
'

command = "notepad.exe"

With CreateObject("WScript.Shell")
	.Run command, 0, False
End With
