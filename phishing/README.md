## Phishing and Social-Engineering related scripts, tools and CheatSheets


- **`DancingRightToLeft.py`** - A script abusing Right-To-Left Override unicode byte to rename phishing payloads.

```
PS> py DancingRightToLeft.py 502.html fax

    :: Dancing Right-To-Left

    A script abusing Right-To-Left Override unicode byte to rename phishing payloads.

    Mariusz Banach / mgeeky '22, (@mariuszbit)
    <mb@binary-offensive.com>

INPUT:

    Payload Filename                                 :  502.html
    Payload Extension                                :  ".html"
    Decoy payloads' extension as                     :  ".fax"

OUTPUT:

    Your file was named in following way             :  "502 \u202exaf.html"

    Your filename will look like this (simulated)    :  "502 lmth.fax"
    Your filename will look like this (real display) :  502                                              lmth.fax
```

- [**`decode-spam-headers.py`**](https://github.com/mgeeky/decode-spam-headers) - This tool accepts on input an `*.EML` or `*.txt` file with all the SMTP headers. It will then extract a subset of interesting headers and using **79+** tests will attempt to decode them as much as possible.

  This script also extracts all IPv4 addresses and domain names and performs full DNS resolution of them.
  Resulting output will contain useful information on why this e-mail might have been blocked.

  Processed headers (more than **67+** headers are parsed):

  - `X-forefront-antispam-report`
  - `X-exchange-antispam`
  - `X-exchange-antispam-mailbox-delivery`
  - `X-exchange-antispam-message-info`
  - `X-microsoft-antispam-report-cfa-test`
  - `Received-spf`
  - `X-mailer`
  - `X-originating-ip`
  - `User-agent`
  - `X-forefront-antispam-report`
  - `X-microsoft-antispam-mailbox-delivery`
  - `X-microsoft-antispam`
  - `X-exchange-antispam-report-cfa-test`
  - `X-spam-status`
  - `X-spam-level`
  - `X-spam-flag`
  - `X-spam-report`
  - `X-vr-spamcause`
  - `X-ovh-spam-reason`
  - `X-vr-spamscore`
  - `X-virus-scanned`
  - `X-spam-checker-version`
  - `X-ironport-av`
  - `X-ironport-anti-spam-filtered`
  - `X-ironport-anti-spam-result`
  - `X-mimecast-spam-score`
  - `Spamdiagnosticmetadata`
  - `X-ms-exchange-atpmessageproperties`
  - `X-ms-exchange-transport-endtoendlatency`
  - `X-ms-oob-tlc-oobclassifiers`
  - `X-ip-spam-verdict`
  - `X-amp-result`
  - `X-ironport-remoteip`
  - `X-ironport-reputation`
  - `X-sbrs`
  - `X-ironport-sendergroup`
  - `X-policy`
  - `X-ironport-mailflowpolicy`
  - `X-remote-ip`
  - `X-sea-spam`
  - `X-fireeye`
  - `X-antiabuse`
  - `X-tmase-version`
  - `X-tm-as-product-ver`
  - `X-tm-as-result`
  - `X-imss-scan-details`
  - `X-tm-as-user-approved-sender`
  - `X-tm-as-user-blocked-sender`
  - `X-tmase-result`
  - `X-tmase-snap-result`
  - `X-imss-dkim-white-list`
  - `X-tm-as-result-xfilter`
  - `X-tm-as-smtp`
  - `X-scanned-by`
  - `X-mimecast-spam-signature`
  - `X-mimecast-bulk-signature`
  - `X-forefront-antispam-report-untrusted`
  - `X-microsoft-antispam-untrusted`
  - `X-sophos-senderhistory`
  - `X-sophos-rescan`
  - and more...

  Most of these headers are not fully documented, therefore the script is unable to pinpoint all the details, but at least it collects all I could find on them.


- **`delete-warning-div-macro.vbs`** - VBA Macro function to be used as a Social Engineering trick removing "Enable Content" warning message as the topmost floating text box with given name. ([gist](https://gist.github.com/mgeeky/9cb6acdec31c8a70cc037c84c77a359c))

- **`gophish-send-mail`** - This script will connect to your GoPhish instance, adjust HTML template and will send a quick test e-mail wherever you told it to, in attempt to let you quickly test out your HTML code.

- **`MacroDetectSandbox.vbs`** - Visual Basic script responsible for detecting Sandbox environments, as presented in modern Trojan Droppers implemented in Macros. ([gist](https://gist.github.com/mgeeky/61e4dfe305ab719e9874ca442779a91d))

- **`Macro-Less-Cheatsheet.md`** - Macro-Less Code Execution in MS Office via DDE (Dynamic Data Exchange) techniques Cheat-Sheet ([gist](https://gist.github.com/mgeeky/981213b4c73093706fc2446deaa5f0c5))

- **`macro-psh-stdin-author.vbs`** - VBS Social Engineering Macro with Powershell invocation taking arguments from Author property and feeding them to StdIn. ([gist](https://gist.github.com/mgeeky/50c4b7fa22d930a80247fea62755fbd3))

- **`Phish-Creds.ps1`** - Powershell oneline Credentials Phisher - to be used in malicious Word Macros/VBA/HTA or other RCE commands on seized machine. ([gist](https://gist.github.com/mgeeky/a404d7f23c85954650d686bb3f02abaf))

    One can additionally add, right after `Get-Credential` following parameters that could improve pretext's quality during social engineering attempt:
    - `-Credential domain\username` - when we know our victim's domain and/or username - we can supply this info to the dialog
    - `-Message "Some luring sentence"` - to include some luring message

- [**`PhishingPost`**](https://github.com/mgeeky/PhishingPost) - (PHP Script intdended to be used during Phishing campaigns as a credentials collector linked to backdoored HTML <form> action parameter.

- **`phishing-HTML-linter.py`** - This script will help you identify issues with your HTML code that you wish to use as your Phishing template.

  It looks for things such as:

  - `Embedded Images`
  - `Images without ALT`
  - `Masqueraded Links`
  - `Use of underline tag <u>`
  - `HTML code in <a> link tags`
  - `<a href="..."> URL contained GET parameter`
  - `<a href="..."> URL contained GET parameter with URL`
  - `<a href="..."> URL pointed to an executable file`
  - `Mail message contained suspicious words`
  
  Such characteristics are known bad smells that will let your e-mail blocked.

- [**`RobustPentestMacro`**](https://github.com/mgeeky/RobustPentestMacro) - This is a rich-featured Visual Basic macro code for use during Penetration Testing assignments, implementing various advanced post-exploitation techniques.

- **`warnings\EN-Word.docx`** and **`warnings\EN-Excel.docx`**  - Set of ready-to-use Microsoft Office Word shapes that can be pasted / inserted into malicious documents for enticing user into clicking "Enable Editing" and "Enable Content" buttons.

- **`WMIPersistence.vbs`** - Visual Basic Script implementing WMI Persistence method (as implemented in SEADADDY malware and further documented by Matt Graeber) to make the Macro code schedule malware startup after roughly 3 minutes since system gets up. ([gist](https://gist.github.com/mgeeky/d00ba855d2af73fd8d7446df0f64c25a))

- **`Various-Macro-Based-RCEs.md`** - Various Visual Basic Macros-based Remote Code Execution techniques to get your meterpreter invoked on the infected machine. ([gist](https://gist.github.com/mgeeky/61e4dfe305ab719e9874ca442779a91d))

- **`vba-macro-mac-persistence.vbs`** - (WIP) Working on VBA-based MacPersistance functionality for MS Office for Mac Macros. ([gist](https://gist.github.com/mgeeky/dd184e7f50dfab5ac97b4855f23952bc))

- **`vba-windows-persistence.vbs`** - VBA Script implementing two windows persistence methods - via WMI EventFilter object and via simple Registry Run. ([gist](https://gist.github.com/mgeeky/07ffbd9dbb64c80afe05fb45a0f66f81))

- [**`VisualBasicObfuscator`**](https://github.com/mgeeky/VisualBasicObfuscator) - Visual Basic Code universal Obfuscator intended to be used during penetration testing assignments.
