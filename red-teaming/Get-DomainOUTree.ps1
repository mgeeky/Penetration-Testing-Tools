#requires -version 2

<#
    Author: Mariusz B. (@mgeeky)
    License: BSD 3-Clause
    Required Dependencies: PowerView.ps1
    Optional Dependencies: None
#>

function Get-DomainOUTree
{
<#
	.SYNOPSIS

	    Author: Mariusz B. (@mgeeky)
    	License: BSD 3-Clause
   	 	Required Dependencies: PowerView.ps1
    	Optional Dependencies: None

    	Prints out Organizational Units collected from Get-DomainOU as a tree.

	.DESCRIPTION

		Collects OU lines returned from PowerView's Get-NetOU cmdlet,
		and then prints that structure as a Organizational Units tree.

		It works with newer PowerView version (from dev branch as of 2018), that
    	has reworked Get-NetOU into Get-DomainOU.

	.PARAMETER OU

		Parameter passed from pipelined PowerView's Get-DomainOU cmdlet.
		That cmdlet will return list of OUs in form of: "OU=...,DC=local,DC=test".

	.EXAMPLE

		PS> Get-DomainOU | Get-DomainOUTree

#>
	[CmdletBinding()]
	Param 
	(
		[Parameter(ValueFromPipelineByPropertyName = $True)]
		$Distinguishedname
	)

	begin
	{
		$OUlines = @()
	}
	
	process
	{
		$OUlines += $Distinguishedname
	}

	end 
	{
		$OUlines | Get-NetOUTree
	}	
}

function Get-NetOUTree 
{
<#
	.SYNOPSIS

	    Author: Mariusz B. (@mgeeky)
    	License: BSD 3-Clause
   	 	Required Dependencies: PowerView.ps1
    	Optional Dependencies: None

    	Prints out Organizational Units collected from Get-NetOU as a tree.

	.DESCRIPTION

		Collects OU lines returned from PowerView's Get-NetOU cmdlet,
		and then prints that structure as a Organizational Units tree.

		It works with older PowerView version (from before 12 dec 2016), that
    	got Get-NetOU cmdlet.

	.PARAMETER OU

		Parameter passed from pipelined PowerView's Get-NetOU cmdlet.
		That cmdlet will return list of OUs in form of: "LDAP://OU=...,DC=local,DC=test".

	.EXAMPLE

		PS> Get-NetOU | Get-NetOUTree

#>
	[CmdletBinding()]
	Param 
	(
		[Parameter(ValueFromPipeline = $True)]
		$OU
	)

	begin
	{
		$OUlines = @()
	}
	
	process
	{
		$OUlines += $OU
	}

	end 
	{
		$OUs = @{}
		$NetOU = $OUlines

		$NetOU = $NetOU | %{$_ -replace 'LDAP://','' }
		$NetOU | ForEach-Object {
			$ousplit = $_.ToString() -split ','
			[array]::Reverse($ousplit)
			$ousplit = $ousplit -join ','
			$ousplit = $ousplit -replace "DC=\w+,", ""
			$ousplit | ForEach-Object {
				$str = $_
				$currPath = ""

				While($str -match '^OU=([\s-\w]+),?.*$') {
					$thisOU = $matches[1]
					#Write-Output "Processing: $str / $thisOU ($currPath)"

					$hashRef = $null
					$fullPath = @()
					$fullPath += "`$OUs"
					$currPath -split ',' | ForEach-Object {
						If ($_) { 
							$fullPath += "[`"$_`"]"
						}
					}
					$hashPath = $fullPath -join ''
					$cmd = "If (-not ($hashPath.ContainsKey(`"$thisOU`"))) {"
					$cmd += $hashPath
					$cmd += ".Add(`"$thisOU`", @{})"
					$cmd += "}"
					#Write-Output "Will IEX: $cmd"

					$cmd | IEX

					$str = $str -replace "OU=$thisOU", ""
					$currPath += $thisOU + ","
					If ($str.StartsWith(",")) {
						$str = $str.Substring(1)
					}
				}
			}
		}

		pretty $OUs 0
	}
}

function pretty {
	param(
		[System.Collections.Hashtable]$hash,
		[Int]$indent
	)

	$hash.Keys | % {
		$k = $_
		$v = $hash.Item($_)

		$tabs = "   " * $indent
		Write-Output "$tabs+ $k"

		If ($v.GetType().Name -eq "Hashtable") {
			$i = $indent + 1
			pretty $v $i
		} 
	}
}
