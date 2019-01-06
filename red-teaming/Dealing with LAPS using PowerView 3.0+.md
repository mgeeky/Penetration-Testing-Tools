### Dealing with LAPS using PowerView 3.0+

**Finds all LAPS-enabled machines**

```
Get-DomainComputer -LDAPFilter '(ms-Mcs-AdmPwdExpirationtime=*)'
```


**Enumerates all users/groups who can view LAPS password on specified `LAPSCLIENT.test.local` machine**

```
Get-DomainComputer LAPSCLIENT.test.local | 
	Select-Object -ExpandProperty distinguishedname | 
	ForEach-Object { $_.substring($_.indexof('OU')) } | ForEach-Object { 
		Get-DomainObjectAcl -ResolveGUIDs $_.ObjectDN 
	} | Where-Object { 
		($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and 
		($_.ActiveDirectoryRights -match 'ReadProperty')
	} | Select-Object -ExpandProperty SecurityIdentifier | Get-DomainObject
```