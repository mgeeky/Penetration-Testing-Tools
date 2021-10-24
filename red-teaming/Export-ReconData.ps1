#requires -version 2

<#
    This script launches many PowerView cmdlets and stores their output in Clixml 
    files for later processing. This script is compatible with newest PowerView's version,
    from dev branch (as of 2018) that uses Get-Domain*, Find-* (instead of Invoke-*) and others cmdlets.

    Author: Mariusz Banach (mgeeky), '18
    License: BSD 3-Clause
    Required Dependencies: PowerSploit's Recon.psm1
#>

function Export-ReconData
{
    $DirName = (Get-Date).ToString("PowerView-MM-dd-yyyy-hh-mm-ss")
    New-Item -Name $DirName -ItemType Directory | Out-Null

    Write-Output "`n:: Logs to be stored in: $DirName`n"

    $ReconModuleCommands = Get-Command -Module Recon
    $Commands = @()

    $ReconModuleCommands `
        | Where-Object {$_.Name -like "Get-Domain*" -or $_.Name -like "Get-Forest*" -or $_.Name -like "Get-Net*"} `
        | Select Name `
        | ForEach-Object {$Commands += $_.Name}

    $Commands += "Find-DomainUserLocation -ShowAll"
    $Commands += "Find-InterestingDomainShareFile"
    $Commands += "Find-DomainShare"
    $Commands += "Get-DomainTrustMapping"
    $Commands += "Get-DomainGPOUserLocalGroupMapping"
    $Commands += "Get-DomainUser -AdminCount"
    $Commands += "Get-DomainForeignUser"
    $Commands += "Get-DomainForeignGroupMember"
    $Commands += "Find-InterestingDomainShareFile"
    $Commands += "Invoke-Kerberoastable"

    $IdentityBased = @( 
        "Get-DomainGroupMember",
        "Get-DomainGPOComputerLocalGroupMapping",
        "Get-DomainGPOUserLocalGroupMapping"
    )

    $ToSkip = @(
        "Get-DomainDNSRecord",
        "Get-DomainObject",
        "Get-DomainObjectAttributeHistory",
        "Get-DomainObjectLinkedAttributeHistory",
        "Get-DomainSPNTicket",
        "Get-DomainUserEvent",
        "Get-ForestSchemaClass"
    )

    $Commands | ForEach-Object {
        $Name = $_
        $Name -match "[A-Za-z]+-(.+)" | Out-Null

        $FileName = $matches[1] + ".xml"
        $FileName = $FileName -replace ' ',''

        If ($IdentityBased -match $Name ) {
            $Name = $Name + " -Identity 'Domain Admins'"
        }
        ElseIf ($ToSkip -match $Name) {
        }
        Else {
            Write-Output "--- $Name ---"
            $Name | Invoke-Expression | Export-Clixml $DirName\$FileName
            Write-Output "Done.`n"      
        }

    }
}

function Import-ReconData
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

#Try 
#{
    # You need to be in PowerSploit\Recon directory
    #Import-Module .\Recon.psm1
#} 
#Catch [System.Exception]
#{
    #Write-Host "[!] BEFORE USING THIS SCRIPT MAKE SURE YOU'VE IMPORTED Recon.psm1 !"
#}
