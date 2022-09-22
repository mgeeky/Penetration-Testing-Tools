filter Send-AmsiContent {
<#
.SYNOPSIS

Supplies the AmsiScanBuffer function with a buffer to be scanned by an AMSI provider.

Author: Matt Graeber
Company: Red Canary

.DESCRIPTION

Send-AmsiContent is a wrapper for AMSI functions that passes off buffers to be scanned by an AMSI provider via the AmsiScanBuffer function. This function was designed to support AMSI debugging, testing, and validation scenarios without the need to execute malicious code.

In order to get the full functionality out of Send-AmsiContent, it is recommended to create an AV exception for this script as it is likely to flag AV engine signatures based on the presence of "AMSI" strings. 

One way to validate AMSI events is by capturing an ETW trace while using Send-AmsiContent. To start an ETW trace, run the following from an elevated prompt:

logman start AMSITrace -p Microsoft-Antimalware-Scan-Interface Event1 -o AMSITrace.etl -ets

Then, supply the buffers you want to test to Send-AmsiContent followed by stopping your tace with the following command:

logman stop AMSITrace -ets

Upon completing the AMSI trace, the ETL file can be interpreted in Event Viewer or with the Get-AmsiEvent function in this module.

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

.PARAMETER CustomAppName

Specifies a custom application name. Use this parameter when testing non-standard applications.

.PARAMETER ContentBytes

Specifies a byte array to be scanned by registered AMSI providers.

.PARAMETER ContentString

Specifies a string to be scanned by registered AMSI providers. A warning is presented if either the DotNet or VSS application names are specified as those are expected to be supplied as byte arrays.

.PARAMETER ContentName

Specifies an emulated path to the content being scanned.

.INPUTS

PSObject

Accepts the output of Get-AmsiEvent when the -AsByteArray switch is supplied.

.EXAMPLE

Send-AmsiContent -StandardAppName PowerShell -ContentString 'Write-Host foo' -ContentName 'D:\test.ps1'

.EXAMPLE

Send-AmsiContent -StandardAppName PowerShell -ContentString 'Invoke-Expression "Do-Stuff"'

.EXAMPLE

Send-AmsiContent -StandardAppName DotNet -ContentBytes ([IO.File]::ReadAllBytes('C:\Windows\System32\stordiag.exe'))

.EXAMPLE

Send-AmsiContent -StandardAppName VBScript -ContentString 'WScript.Echo "Hello, World"'

.EXAMPLE

Send-AmsiContent -StandardAppName JScript -ContentString 'WScript.Echo("Hello, Mimikatz?");'

.EXAMPLE

Send-AmsiContent -StandardAppName WMI -ContentString 'ActiveScriptEventConsumer.GetObject();\nActiveScriptEventConsumer.GetObject();\nSetPropValue.Name(\"WriteDateTime\");\nSetPropValue.ScriptText(\"Set FSO=CreateObject(\"Scripting.FileSystemObject\"):Set File = FSO.CreateTextFile(\"C:\\Windows\\Temp\\text.txt\"):File.WriteLine FormatDateTime(now):File.Close\");\n'
#>

    [CmdletBinding(DefaultParameterSetName = 'CustomAppNameByteContent')]
    param (
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'StandardAppNameStringContent')]
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'StandardAppNameByteContent')]
        [String]
        [ValidateSet('PowerShell', 'VBScript', 'JScript', 'WMI', 'DotNet', 'coreclr', 'VSS', 'Excel', 'Excel.exe', 'OFFICE_VBA', 'Exchange Server 2016')]
        $StandardAppName,

        [Parameter(Mandatory, Position = 0, ParameterSetName = 'CustomAppNameStringContent')]
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'CustomAppNameByteContent', ValueFromPipelineByPropertyName)]
        [String]
        [ValidateNotNullOrEmpty()]
        [Alias('AppName')]
        $CustomAppName,

        [Parameter(Mandatory, Position = 1, ParameterSetName = 'StandardAppNameByteContent')]
        [Parameter(Mandatory, Position = 1, ParameterSetName = 'CustomAppNameByteContent', ValueFromPipelineByPropertyName)]
        [Byte[]]
        [Alias('Content')]
        $ContentBytes,

        [Parameter(Mandatory, Position = 1, ParameterSetName = 'StandardAppNameStringContent')]
        [Parameter(Mandatory, Position = 1, ParameterSetName = 'CustomAppNameStringContent')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ContentString,

        [Parameter(Position = 2, ValueFromPipelineByPropertyName)]
        [String]
        $ContentName
    )

    if (-not ('AmsiNativeMethods' -as [Type])) {
        Add-Type -TypeDefinition @'
            using System.Runtime.InteropServices;

            public static class AmsiNativeMethods {
                public enum AMSI_RESULT {
                    AMSI_RESULT_CLEAN = 0,
                    AMSI_RESULT_NOT_DETECTED = 1,
                    AMSI_RESULT_BLOCKED_BY_ADMIN_BEGIN = 0x4000,
                    AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4fff,
                    AMSI_RESULT_DETECTED = 32768,
                }

                [DllImportAttribute("amsi.dll", CallingConvention = CallingConvention.StdCall)]
                public static extern int AmsiInitialize(
                    [InAttribute()][MarshalAsAttribute(UnmanagedType.LPWStr)] string appName,
                    ref System.IntPtr amsiContext
                );

                [DllImportAttribute("amsi.dll", CallingConvention = CallingConvention.StdCall)]
                public static extern void AmsiUninitialize(
                    System.IntPtr amsiContext
                );

                [DllImportAttribute("amsi.dll", CallingConvention = CallingConvention.StdCall)]
                public static extern int AmsiOpenSession(
                    System.IntPtr amsiContext,
                    ref System.IntPtr amsiSession
                );

                [DllImportAttribute("amsi.dll", CallingConvention = CallingConvention.StdCall)]
                public static extern void AmsiCloseSession(System.IntPtr amsiContext, System.IntPtr amsiSession);


                [DllImportAttribute("amsi.dll", CallingConvention = CallingConvention.StdCall)]
                public static extern int AmsiScanBuffer(
                    System.IntPtr amsiContext,
                    byte[] buffer,
                    uint length,
                    [InAttribute()][MarshalAsAttribute(UnmanagedType.LPWStr)] string contentName,
                    System.IntPtr amsiSession,
                    ref AMSI_RESULT result
                );
            }
'@
    }

    if ($CustomAppName) {
        $FullAppName = $CustomAppName
    } else {
        switch ($StandardAppName) {
            'PowerShell' {
                $PowerShellProcess = Get-Process -Id $PID

                # Emulate the dynamically build appname used by PowerShell: https://github.com/PowerShell/PowerShell/blob/03b07a0062648b6b6f9f58227dbd25fb0e0759e7/src/System.Management.Automation/security/SecuritySupport.cs#L1348
                $FullAppName = "PowerShell_$($PowerShellProcess.Path)_$($PSVersionTable.BuildVersion.ToString())"
            }

            'DotNet' {
                if (@('StandardAppNameStringContent', 'CustomAppNameStringContent') -contains $PSCmdlet.ParameterSetName) {
                    Write-Warning 'DotNet content is expected to be supplied as a byte array but string content was supplied.'
                }

                $FullAppName = $StandardAppName
            }

            'coreclr' {
                if (@('StandardAppNameStringContent', 'CustomAppNameStringContent') -contains $PSCmdlet.ParameterSetName) {
                    Write-Warning 'coreclr content is expected to be supplied as a byte array but string content was supplied.'
                }

                $FullAppName = $StandardAppName
            }

            'VSS' {
                if (@('StandardAppNameStringContent', 'CustomAppNameStringContent') -contains $PSCmdlet.ParameterSetName) {
                    Write-Warning 'VSS content is expected to be supplied as a byte array but string content was supplied.'
                }

                $FullAppName = $StandardAppName
            }

            default {
                $FullAppName = $StandardAppName
            }
        }
    }

    if ($ContentName) {
        $ContentNameString = $ContentName
    } else {
        $ContentNameString = [String]::Empty
    }

    if ($ContentBytes) {
        [Byte[]] $Content = $ContentBytes
    } else {
        # -ContentString was supplied
        [Byte[]] $Content = [Text.Encoding]::Unicode.GetBytes($ContentString)
    }

    $AmsiContext = [IntPtr]::Zero
    $AmsiSession = [IntPtr]::Zero
    $AmsiResult  = New-Object -TypeName AmsiNativeMethods+AMSI_RESULT

    $Result = [AmsiNativeMethods]::AmsiInitialize($FullAppName, [Ref] $AmsiContext)

    if ($Result -ne 0) {
        $Failure = [ComponentModel.Win32Exception] $Result

        Write-Error -Message "AmsiInitialize failed. Message: $($Failure.Message). Error code: $($Failure.NativeErrorCode)"
    }

    $Result = [AmsiNativeMethods]::AmsiOpenSession($AmsiContext, [Ref] $AmsiSession)

    if ($Result -ne 0) {
        [AmsiNativeMethods]::AmsiUninitialize($AmsiContext)

        $Failure = [ComponentModel.Win32Exception] $Result

        Write-Error -Message "AmsiOpenSession failed. Message: $($Failure.Message). Error code: $($Failure.NativeErrorCode)"
    }

    $Result = [AmsiNativeMethods]::AmsiScanBuffer(
        $AmsiContext,
        $Content,
        $Content.Length,
        $ContentNameString,
        $AmsiSession,
        [Ref] $AmsiResult
    )

    $ERROR_NOT_READY = 0x80070015

    if (($Result -ne 0) -and ($Result -ne $ERROR_NOT_READY)) {
        $Failure = [ComponentModel.Win32Exception] $Result

        Write-Error -Message "AmsiScanBuffer failed. Message: $($Failure.Message). Error code: $($Failure.NativeErrorCode)"
    }

    [AmsiNativeMethods]::AmsiCloseSession($AmsiContext, $AmsiSession)
    [AmsiNativeMethods]::AmsiUninitialize($AmsiContext)
}

function Get-AMSIEvent {
<#
.SYNOPSIS

Parses the contents of an AMSI ETW trace file.

Author: Matt Graeber
Company: Red Canary

.PARAMETER Path

Specifies the path to an ETL file consisting of an AMSI ETW trace.

.PARAMETER AsByteArray

Returns AMSI event data as a byte array in the Content property. By default, buffers are returned as a unicode string. This option facilitates passing raw AMSI content through to Send-AmsiContent.

.EXAMPLE

Get-AmsiEvent -Path C:\Test\AMSITrace.etl
#>

    param (
        [Parameter(Mandatory)]
        [String]
        [ValidatePattern('\.etl$')] # File path must end with .etl
        $Path,

        [Switch]
        $AsByteArray
    )

    # AMSI events correspond to event ID 1101
    Get-WinEvent -Path $Path -Oldest -FilterXPath 'Event[System[Provider[@Name="Microsoft-Antimalware-Scan-Interface"]] and System[EventID=1101]]' | ForEach-Object {
        $ScanResultValue = $_.Properties[2].Value

        if ($ScanResultValue -eq 0) {
            $ScanResult = 'AMSI_RESULT_CLEAN'
        } elseif ($ScanResultValue -eq 1) {
            $ScanResult = 'AMSI_RESULT_NOT_DETECTED'
        } elseif ($ScanResultValue -eq 32768) {
            $ScanResult = 'AMSI_RESULT_DETECTED'
        } elseif (($ScanResultValue -ge 0x4000) -and ($ScanResultValue -le 0x4FFF)) {
            $ScanResult = 'AMSI_RESULT_BLOCKED_BY_ADMIN'
        } else {
            $ScanResult = $ScanResultValue
        }

        $AppName = $_.Properties[3].Value

        if ($AsByteArray) {
            $AMSIContent = $_.Properties[7].Value
        } else {
            if ($AppName -eq 'DotNet') {
                # In this case, the AMSI buffer is a raw byte array of the full .NET assembly PE
                $AMSIContent = [BitConverter]::ToString($_.Properties[7].Value).Replace('-','')
            } else {
                # In this case, the AMSI buffer is raw byte array of unicode-encoded script code
                $AMSIContent = [Text.Encoding]::Unicode.GetString($_.Properties[7].Value)
            }
        }

        [PSCustomObject] @{
            ProcessId = $_.ProcessId
            ThreadId = $_.ThreadId
            TimeCreated = $_.TimeCreated
            Session = $_.Properties[0].Value
            ScanStatus = $_.Properties[1].Value
            ScanResult = $ScanResult
            AppName = $AppName
            ContentName = $_.Properties[4].Value
            ContentSize = $_.Properties[5].Value
            OriginalSize = $_.Properties[6].Value
            Content = $AMSIContent
            Hash = (($_.Properties[8].Value | ForEach-Object { '{0:X2}' -f $_ }) -join '')
            ContentFiltered = $_.Properties[9].Value
        }
    }
}