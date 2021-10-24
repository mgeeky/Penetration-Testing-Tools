'
' This script uses classic WScript.Shell Exec method to
' execute given command in a hidden window via StdIn passed to a dedicated
' launcher command (powershell.exe in this example).
'
' Mariusz Banach / mgeeky, <mb@binary-offensive.com>
' (https://github.com/mgeeky)
'

command = "notepad.exe"
launcher = "powershell -nop -w hid -Command -"

With CreateObject("WScript.Shell")
	With .Exec(launcher)
        .StdIn.WriteLine command
        .StdIn.WriteBlankLines 1
        .Terminate
    End With
End With
