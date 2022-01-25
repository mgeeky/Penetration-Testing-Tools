Function Get-ARTADRolePermissions {
    <#
    .SYNOPSIS
        Shows Azure AD role permissions.

    .DESCRIPTION
        Displays all granted permissions on a specified Azure AD role.

    .PARAMETER RoleName
        Name of the role to inspect.

    .EXAMPLE
        PS> Get-ARTADRolePermissions -RoleName "Global Administrator"
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $RoleName
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        Write-Host @"
---

#### ``$RoleName``

"@

        (Get-AzureADMSRoleDefinition -Filter "displayName eq '$RoleName'").RolePermissions | % {
            $_.AllowedResourceActions | % {
                Write-Host "- ``$_``"
            }
        }

        Write-Host ""
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTRolePermissions {
    <#
    .SYNOPSIS
        Shows Azure role permissions.

    .DESCRIPTION
        Displays all granted permissions on a specified Azure RBAC role.

    .PARAMETER RoleName
        Name of the role to inspect.

    .EXAMPLE
        PS> Get-ARTRolePermissions -RoleName Owner
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $RoleName
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        try {
            $role = Get-AzRoleDefinition -Name $RoleName
        }
        catch {
            Write-Host "[!] Could not get Role Definition. Possibly due to lacking privileges or lack of connection."
            Return
        }

        Write-Host @"

---

#### ``$RoleName``

"@

        if($role.Actions.Length -gt 0 ) {
            Write-Host "`n- Actions:"
            $role.Actions | % {
                Write-Host "  - ``$($_)``"
            }
        }

        if($role.NotActions.Length -gt 0 ) {
            Write-Host "`n- NotActions:"
            $role.NotActions | % {
                Write-Host "  - ``$($_)``"
            }
        }

        if($role.DataActions.Length -gt 0 ) {
            Write-Host "`n- DataActions:"
            $role.DataActions | % {
                Write-Host "  - ``$($_)``"
            }
        }

        if($role.NotDataActions.Length -gt 0 ) {
            Write-Host "`n- NotDataActions:"
            $role.NotDataActions | % {
                Write-Host "  - ``$($_)``"
            }
        }

        Write-Host ""
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Dump-AzureRoles {
    $creds = Get-Credential
    Connect-AzAccount -Credential $creds | Out-Null
    Connect-AzureAD -Credential $creds | Out-Null

    Write-Host @"
# Synopsis

First part of this gist contains list of Azure RBAC and Azure AD roles sorted by their names.

Second part contains full definitions of each role along with their permissions assigned.

## Role Definitions

### Azure RBAC Roles


| # | RoleName | RoleDescription | RoleId |
|---|----------|-----------------|--------|
"@

    $azureRbacRoles = (Get-AzRoleDefinition | ? { $_.IsCustom -eq $false } | sort -property Name)

    $count = 0
    $azureRbacRoles | % {
        $count += 1
        Write-Host "| $count | ``$($_.Name)`` | _$($_.Description)_ | ``$($_.Id)`` |"
    }

    Write-Host @"

---

### Azure AD Roles

| # | RoleName | RoleDescription | RoleId |
|---|----------|-----------------|--------|
"@

    $azureADRoles = (Get-AzureADDirectoryRoleTemplate | sort -property displayname)

    $count = 0
    $azureADRoles | % {
        $count += 1
        Write-Host "| $count | ``$($_.DisplayName)`` | _$($_.Description)_ | ``$($_.ObjectId)`` |"
    }

    Write-Host @"

--- 

## Role Permissions

This section contains detailed definitions of each role along with their assigned permissions sets.

### Azure RBAC Role Permissions

"@

    $azureRbacRoles | % {
        Get-ARTRolePermissions -RoleName $_.Name
    }

    Write-Host @"

---
    
### Azure AD Role Permissions

"@

    $azureADRoles | % {
        Get-ARTADRolePermissions -RoleName $_.DisplayName
    }
}