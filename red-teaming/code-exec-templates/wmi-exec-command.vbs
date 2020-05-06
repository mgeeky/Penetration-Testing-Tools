'
' This script uses WMI class' Win32_Process static method Create to 
' execute given command in a hidden window (ShowWindow = 12).
'
' Mariusz B. / mgeeky, <mb@binary-offensive.com>
' (https://github.com/mgeeky)
'

command = "notepad.exe"
computer = "."

Set wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" _
        & computer & "\root\cimv2")

Set startup = wmi.Get("Win32_ProcessStartup")
Set conf = startup.SpawnInstance_
conf.ShowWindow = 12

Set proc = GetObject("winmgmts:root\cimv2:Win32_Process")
proc.Create command, Null, conf, intProcessID