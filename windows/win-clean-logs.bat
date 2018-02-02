@echo off
del /f /q /s %windir%\prefetch\*
reg delete “HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache” /va /f
reg delete “HKLM\Software\Microsoft\Windows\ShellNoRoam\MUICache” /va /f
reg delete “HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache” /va /f
reg delete “HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache” /va /f
reg delete “HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU” /va /f
reg delete “HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist” /va /f
wmic nteventlog where LogFileName=’File Replication Service’ Call ClearEventlog
wmic nteventlog where LogFileName=’Application’ Call ClearEventlog
wmic nteventlog where LogFileName=’System’ Call ClearEventlog
wmic nteventlog where LogFileName=’PowerShell’ Call ClearEventlog
ren %1 temp000 & copy /y %windir%\regedit.exe temp000 & del temp000