param (
	[Parameter(Mandatory=$true)]
	[string]
	$TargetPath,

	[Parameter(Mandatory=$true)]
	[string]
	$OutputLnk,

	[Parameter(Mandatory=$false)]
	[string]
	$Arguments = "",

	[Parameter(Mandatory=$false)]
	[string]
	$WorkingDirectory = ""
)

$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($OutputLnk)
$Shortcut.TargetPath = $TargetPath
$Shortcut.Arguments = $Arguments
$Shortcut.WorkingDirectory = $WorkingDirectory
$Shortcut.Save()