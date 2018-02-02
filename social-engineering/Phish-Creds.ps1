<#

try { 
  (Get-Credential -Credential $null).GetNetworkCredential() | 
  Select-Object @{name="User"; expression = {
      If ($_.Domain -ne [string]::Empty) {
        "{0}\{1}" -f ($_.Domain), ($_.UserName)
      } Else { 
        $_.UserName
      } 
    }
  }, Password | Format-List 
} catch { 
}

#>

try { ((Get-Credential -Credential $null).GetNetworkCredential() | Select-Object @{name="User"; expression={If ($_.Domain -ne [string]::Empty) {"{0}\{1}" -f ($_.Domain), ($_.UserName)} Else { $_.UserName} }}, Password | Format-List) } catch { }