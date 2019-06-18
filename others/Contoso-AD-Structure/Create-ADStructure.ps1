#
# Creates an utterly simple AD structure with groups, users and their profile images.
#
# This script was heavily based on:
#   https://github.com/kurobeats/Active-Directory-User-Script
#

Import-module activedirectory

$dnsDomain =gc env:USERDNSDOMAIN

$split = $dnsDomain.split(".")
$domain=$null
foreach($part in $split)
{
	if($domain -ne $null)
	{
		$domain+=","
	}
	$domain += "DC=$part"
}

#Declare any Variables
$dirpath = $pwd.path
$orgName = "Contoso"
$orgUnit = "OU=Groups,OU=$orgName"
$orgUnit2 = "OU=Users,OU=$orgName"
$counter = 0

$ImportFile = Import-csv "$dirpath\ADUsers.csv"
$TotalImports = $importFile.Count

New-ADOrganizationalUnit -Name $orgName -Path $domain
New-ADOrganizationalUnit -Name "Groups" -Path "OU=$orgName,$domain"
New-ADOrganizationalUnit -Name "Users" -Path "OU=$orgName,$domain"

$ImportFile | foreach {
	$counter++
	$progress = [int]($counter / $totalImports * 100)

	$pass = "Password$($counter)!"
    $ident = "CN=$($_.Name),$orgUnit2,$domain"
	$dummyPassword = ConvertTo-SecureString -AsPlainText $pass -Force

	if ($_.Manager -eq "") {
		New-ADUser -SamAccountName $_.SamAccountName -Name $_.Name -Surname $_.Sn -GivenName $_.GivenName -Path "$orgUnit2,$domain" -AccountPassword $dummyPassword -Enabled $true -title $_.title -officePhone $_.officePhone -department $_.department -emailaddress $_.mail
	} else {
        New-ADUser -SamAccountName $_.SamAccountName -Name $_.Name -Surname $_.Sn -GivenName $_.GivenName -Path "$orgUnit2,$domain" -AccountPassword $dummyPassword -Enabled $true -title $_.title -officePhone $_.officePhone -department $_.department -manager "$($_.Manager),$orgUnit2,$domain" -emailaddress $_.mail
	}
	Write-Host "$($_.Name) / $pass"
	If (gci "$dirpath\userimages\$($_.name).jpg") {
		$photo = [System.IO.File]::ReadAllBytes("$dirpath\userImages\$($_.name).jpg")
		Set-AdUser -Identity $ident -Replace @{thumbnailPhoto=$photo}
	}

	$san = $_.department -replace ' ', ''
	$dep = $_.department
	$group = (Get-ADGroup -Filter {Name -like $dep} -SearchBase "$orgUnit,$domain")
	if ($group -eq $null) {
		New-ADGroup -Name $_.department -SamAccountName $san -Path "$orgUnit,$domain" -GroupScope Global
        $group = (Get-ADGroup -Filter {Name -like $dep} -SearchBase "$orgUnit,$domain")
	}

    $user = Get-ADUser -Identity $ident
	Add-ADGroupMember -Identity $group -Members $user
}
