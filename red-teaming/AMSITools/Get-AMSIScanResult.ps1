#Requires -RunAsAdministrator

function Get-AMSIScanResult {
<#
.SYNOPSIS

Starts AMSI ETW Trace and then either waits for user to trigger detection or scans input file.
Then collects AMSI events and prints them on output.

Based on Matt Graeber's AMSITools.ps1, sourced:
    https://gist.github.com/mgraeber-rc/1eb42d3ec9c2f677e70bb14c3b7b5c9c

.PARAMETER File

Input file to scan if Interactive is not used.

.PARAMETER Interactive

Will wait for user to trigger AMSI detections and await for Enter keypress.
When Enter is pressed, will pull collected AMSI events.

.PARAMETER StandardAppName

Specifies the application name to emulate that will supply the buffer to AmsiScanBuffer. The following application names are supported:
* PowerShell - Refers to PowerShell script code. This application name is supplied in System.Management.Automation.dll. PowerShell generates a dynamic application name string in the form of PowerShell_POWERSHELLPATH_POWERSHELLVERSION.
* VBScript - Refers to VBScript script code. This application name is supplied in vbscript.dll
* JScript - Refers to JScript script code. This application name is supplied in jscript.dll, jscript9.dll, and jscriptlegacy.dll
* WMI - Refers to WMI operations. This application name is supplied in fastprox.dll
* DotNet - Refers to in-memory .NET assembly loads in .NET 4.8+. This application name is supplied in clr.dll
* coreclr - Refers to in-memory .NET assembly loads in .NET 4.8+. This application name is supplied in coreclr.dll
* VSS - Refers to Volume Shadow Copy service operations. This application name is supplied in VSSVC.exe and swprv.dll
* Excel - Refers to Excel4 macro contents. This application name is supplied in EXCEL.EXE.
* Excel.exe - Refers to Excel4 macro contents. This application name is supplied in excelcnv.exe.
* OFFICE_VBA - Refers to VBA macro contents. This application name is supplied in VBE7.DLL.
* Exchange Server 2016 - Refers to Exchange Server AMSI integration (https://techcommunity.microsoft.com/t5/exchange-team-blog/more-about-amsi-integration-with-exchange-server/ba-p/2572371). This application name is supplied in Microsoft.Exchange.HttpRequestFiltering.dll.

.PARAMETER TraceFile

Path where to save ETL file with event logs.

#>
    param(
        [string]
        $File = "",

        [string]
        $StandardAppName = "OFFICE_VBA",

        [switch]
        $Interactive,

        [string]
        $TraceFile = "AMSITrace.etl"
    )

    if (-not $Interactive -and $File -eq "") {
        Write-Error "You must specify -File or -Interactive."
    }

    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

    #
    # Step 1: Disable AMSI for this powershell runspace.
    #
    [Runtime.InteropServices.Marshal]::WriteByte((([Ref].Assembly.GetTypes()|?{$_-clike'*Am*ls'}).GetFields(40)|?{$_-clike'*xt'}).GetValue($null),0x5)

    #
    # Step 2: Load Matt Graeber's AMSITools.ps1
    #
    . "$PSScriptRoot\AMSITools.ps1"

    #
    # Step 3: Start an ETW Trace 
    #
    Remove-Item $TraceFile -EA SilentlyContinue | Out-Null
    logman start AMSITrace -p Microsoft-Antimalware-Scan-Interface Event1 -o $TraceFile -ets | Out-Null

    if ($Interactive) {
        Write-Host "Trigger AMSI detections now and then press any key to pull AMSI events..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    }
    else {
        #
        # Step 4: Read input file
        #
        $bytes = Get-Content $File -Encoding Byte

        #
        # Step 5: Feed AMSI trace
        #
        Send-AmsiContent -StandardAppName $StandardAppName -ContentBytes $bytes
    }

    #
    # Step 6: Stop ETW Trace
    #
    logman stop AMSITrace -ets | Out-Null

    #
    # Step 7: Pull collected events
    #
    Get-AMSIEvent -Path $traceFile

    Write-Host "If you wish to pull AMSI events again, simply run in this terminal:`n`tGet-AMSIEvent -Path $traceFile`n"

}