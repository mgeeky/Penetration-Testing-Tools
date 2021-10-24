<#
  This script enumerates privileged groups (Tier-) and counts their users.
  By knowing how many privileged users are there in examined groups, we can
  briefly estimate the configuration debt impact on the assessed Active Directory
  or domain maintenance misconfiguration impact.

  Usage:
    PS> . .\Count-PrivilegedGroupMembers.ps1
    PS> Count-PrivilegedGroupMembers
  
  Mariusz Banach / mgeeky
#>

# This script requires PowerView 3.0 dev branch
# Import-Module powerview.ps1 -ErrorAction SilentlyContinue

Function Count-PrivilegedGroupMembers
{    
	[CmdletBinding()] Param(
		[Parameter(Mandatory=$false)]
        [String]
        $Domain,

		[Parameter(Mandatory=$false)]
        [Switch]
        $Recurse,

		[Parameter(Mandatory=$false)]
        [String]
        $AdditionalGroupsFile
    )

	$PrivilegedGroups = @(
		"Enterprise Admins"
		"Domain Admins"
		"Schema Admin"
		"Account Operators"
		"Backup Operators"
		"Print Operators"
		"Server Operators"
		"Domain Controllers"
		"Read-only Domain Controllers"
		"Group Policy Creator Owners"
		"Cryptographic Operators"
		"Distributed COM Users"
	)

	$AdditionalGroups = @()

	if($AdditionalGroupsFile.length -gt 0) {
		[string[]]$AdditionalGroups = Get-Content -Path $AdditionalGroupsFile
	}

	$groups = $PrivilegedGroups + $AdditionalGroups

	$GroupsMembers = @{}
	foreach ($group in $groups)
	{
		$command = "(Get-DomainGroupMember -Identity '$group'"
		if ($Recurse)
		{
			$command += " -Recurse"
		}

		if($Domain)
		{
			$command += " -Domain $Domain"
		}

		$command += " ).Count"
		Write-Verbose "Running '$command'..."
		$members = (Invoke-Expression $command) -as [int]
		$GroupsMembers.Add($group, $members)

		Write-Verbose "Got $members members in $group."
	}

	return $GroupsMembers
}