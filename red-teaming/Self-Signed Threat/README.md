## Easy-to-use test-it-yourself sign-your-malware 

A Powershell script that signs input Executable file with fake Microsoft code-signing certificate to demonstrate risks of Code Signing attacks.

Script was shamelessly borrowed from [Matt Graeber, @mattifestation](https://twitter.com/mattifestation) and his research titled:
- [_Code Signing Certificate Cloning Attacks and Defenses_](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec) 

**All credits go to Matt** - I merely copied his code & work for preserverance purposes.


### Effectiveness

As of 13/07/2022 this **dumb trick** still gets off the shelf malware evade detection of at least 8 modern security scanners.

| What                                                                         | Result    |
|------------------------------------------------------------------------------|-----------|
| Mythic Apollo.exe before fake-signing                                        | [30/70](https://www.virustotal.com/gui/file/1413de7cee2c7c161f814fe93256968450b4e99ae65f0b5e7c2e76128526cc73?nocache=1) |
| Mythic Apollo.exe after fake-signing with Microsoft code-signing certificate | [22/70](https://www.virustotal.com/gui/file/34543de8a6b24c98ea526d8f2ae5f1dbe99d64386d8a8f46ddbcdcebaac3df65?nocache=1) |

### Usage

```
PS C:\> . .\Sign-Artifact.ps1
PS C:\> Sign-Artifact -InputFile malware.exe -OutputFile nomalware.exe -Verbose
```
