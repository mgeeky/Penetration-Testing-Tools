#requires -version 2

<#

	This script launches many PowerView cmdlets and stores their output 
	in Clixml files for later processing.

	Author: Mariusz Banach (mgeeky), '18
	License: BSD 3-Clause
	Required Dependencies: PowerSploit's Recon.psm1
#>

function Save-ReconData
{
	$DirName = (Get-Date).ToString("PowerView-MM-dd-yyyy-hh-mm-ss")
	New-Item -Name $DirName -ItemType Directory | Out-Null

	Write-Output "`n:: Logs to be stored in: $DirName`n"

	$ReconModuleCommands = Get-Command -Module Recon
	$Commands = @()

	$ReconModuleCommands `
		| Where-Object {$_.Name -like "Get-Net*"} `
		| Select Name `
		| ForEach-Object {$Commands += $_.Name}

	$Commands += "Invoke-UserHunter -ShowAll"
	$Commands += "Invoke-StealthUserHunter -ShowAll"
	$Commands += "Invoke-FileFinder -SearchSYSVol"
	$Commands += "Invoke-ShareFinder"
	$Commands += "Invoke-MapDomainTrust"
	$Commands += "Find-GPOLocation"
	$Commands += "Get-NetUser -AdminCount"
	$Commands += "Find-ForeignUser"
	$Commands += "Find-ForeignGroup"
	$Commands += "Invoke-FileFinder"

	$Commands | ForEach-Object {
		$Name = $_
		$Name -match "[A-Za-z]+-(.+)" | Out-Null

		$FileName = $matches[1] + ".xml"
		$FileName = $FileName -replace ' ',''

		If ($Name -like "Get-Net*")
		{
			#$Name = $Name + " -Recurse"
		}

		Write-Output "--- $Name ---"
		$Name | Invoke-Expression | Export-Clixml $DirName\$FileName
		Write-Output "Done.`n"
	}
}

function Load-ReconData
{
	Param
	(
		[Parameter(Position = 0, Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]
		$DirName
	)
	$path = Get-Location
	Set-Location -Path $DirName

	Get-ChildItem . -Filter *.xml |
	Foreach-Object {
		$Name = $_.BaseName -replace '-',''
		$Results = Import-Clixml -Path "$_"
		New-Variable -Name $Name -Force -Value $Results -Scope Global
		Write-Output "Loaded `$$Name results."
	}

	Set-Location -Path $path
}

function Get-ReconData
{
	Param
	(
		[Parameter(Position = 0, Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]
		$DirName
	)
	$path = Get-Location
	$Variables = Get-Variable
	Set-Location -Path $DirName

	Get-ChildItem . -Filter *.xml |
	Foreach-Object {
		$Name = $_.BaseName -replace '-',''
		If ($Variables | Where-Object { $_.Name -eq $Name })
		{
			Write-Output "Previously loaded: `$$Name"
		}
	}

	Set-Location -Path $path
}

Try 
{
	# You need to be in PowerSploit\Recon directory
	Import-Module .\Recon.psm1
} 
Catch [System.Exception]
{
	exit
}
