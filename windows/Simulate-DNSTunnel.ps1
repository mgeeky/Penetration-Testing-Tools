<#
    Simulate-DNSTunnel.ps1

    Author: Mariusz Banach (@mgeeky)
    License: GPL
    Required Dependencies: None
    Optional Dependencies: None

#>

$MaxQueryLength = 253
$MaxDnsLabelLength = 63

# Although it can get even up to 127, keeping it lower value may seem more genuine
$MaxNumberOfLevels = 5


function Simulate-DNSTunnel
{
<#
    .SYNOPSIS

        Performs DNS Tunnelling simulation.


    .DESCRIPTION

        This function performs DNS tunelling simulation for purpose 
        of triggering installed Network IPS and IDS systems. By issuing 
        DNS queries over system's default resolver, will introduce peak 
        in high-entropy anomalous queries to be picked up by blue teams.

    .PARAMETER Domain

        Domain to be queried against randomly generated anomalous-looking long subdomain.
        This domain should have a '*' type A record pointing to some IP address
        for every wildcard subdomain queried, to avoid subsequent DNS failures.
        Also, obviously the domain should be resolveable.

    .PARAMETER Interval

        This parameter introduces delay between subsequent queries (in seconds). When unset, 
        every query will be triggered sequentially one after another. Otherwise,
        a sleep will be introduced between queries, simulating thus DNS beaconing.

    .PARAMETER QueriesNumber

        Number of DNS queries to perform. If unset, script will perform inifinite number
        of DNS queries. In such case, it can be terminated by CTRL+C.

    .EXAMPLE

        Simulate-DNSTunnel -Domain google.com

#>
    
    [CmdletBinding()] Param(
        [String]
        $Domain,

        [Double]
        $Interval = 0.0,

        [Int]
        $QueriesNumber = 0
    )

    $Num = 0

    While ( ($Num -lt $QueriesNumber) -or ($QueriesNumber -eq 0))
    {
        $Num += 1
        $Query = Generate-AnomalousQuery -Domain $Domain

        If ($Interval -ne 0.0 )
        {
            Start-Sleep -m ($Interval * 1000)
        }

        Try
        {
            Write-Host "[+] $Num. Querying: $Query"
            [System.Net.Dns]::GetHostByName($Query).Hostname
        }
        Catch
        {
        }
    }

}

function Get-RandomString
{
    [CmdletBinding()] Param(
        [int]
        $Count
    )
    return -join ((65..90) + (97..122) | Get-Random -Count $Count | %{[char]$_})
}

function Generate-AnomalousQuery
{
    Param(
        [String]
        $Domain
    )

    $QueryToGenerateLen = (Get-Random) % ($MaxQueryLength - $Domain.Length - 1)
    $PartLen = [math]::Min($MaxDnsLabelLength, $QueryToGenerateLen)
    $NumberOfParts = (Get-Random) % $MaxNumberOfLevels

    $Query = ""

    For ($i = 0; $i -lt $NumberOfParts; $i++ )
    {
        $Query += Get-RandomString -Count ($PartLen / $NumberOfParts)
        $Query += "."
    }

    While ($Query.Length -lt $QueryToGenerateLen )
    {
        $Query += Get-RandomString -Count 1
    }

    If (($Query.Length + $Domain.Length) -ge ($MaxQueryLength + 1) )
    {
        $Query = $Query.Substring(0, $MaxQueryLength - $Domain.Length - 1)
    }

    $Query = $Query -replace "\.\.", "."

    $Query += ".$Domain"
    return $Query
}