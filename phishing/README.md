## Phishing and Social-Engineering related scripts, tools and CheatSheets


- **`decode-spam-headers.py`** - This tool accepts on input an `*.EML` or `*.txt` file with all the SMTP headers. It will then extract a subset of interesting headers and will attempt to parse them.

  This script also extracts all IPv4 addresses and domain names and performs full DNS resolution of them.

  Resulting output will contain useful information on why this e-mail might have been blocked.

  Processed headers:

  - `Authentication-Results`
  - `From`
  - `Received-SPF`
  - `Received`
  - `To`
  - `X-Forefront-Antispam-Report`
  - `X-Mailer`
  - `X-Microsoft-Antispam-Mailbox-Delivery`
  - `X-Microsoft-Antispam-Message-Info`
  - `X-Microsoft-Antispam`
  - `X-MS-Exchange-Transport-EndToEndLatency`
  - `X-MS-Oob-TLC-OOBClassifiers`
  - `X-MS-Exchange-AtpMessageProperties`
  - `X-Exchange-Antispam-Report-CFA-Test`
  - `X-Microsoft-Antispam-Report-CFA-Test`
  - `X-MS-Exchange-AtpMessageProperties`
  - `X-Spam-Status`
  - `X-Spam-Level`
  - `X-Spam-Flag`
  - `X-Spam-Report`
  - and more...

  Most of these headers are not fully documented, therefore the script is unable to pinpoint all the details, but at least it collects all I could find on them.

  Help:

```
PS> py .\decode-spam-headers.py --help
usage: decode-spam-headers.py [options] <file>

optional arguments:
  -h, --help            show this help message and exit

Required arguments:
  infile                Input file to be analysed

Options:
  -o OUTFILE, --outfile OUTFILE
                        Output file with report
  -f {json,text}, --format {json,text}
                        Analysis report format. JSON, text. Default: text
  -N, --nocolor         Dont use colors in text output.
  -v, --verbose         Verbose mode.
  -d, --debug           Debug mode.

Tests:
  -r, --resolve         Resolve IPv4 addresses / Domain names.
```

  Sample run:

```
  PS> py decode-spam-headers.py headers.txt

------------------------------------------
(1) Test: Received - Mail Servers Flow

HEADER:
    Received

VALUE:
    ...

ANALYSIS:
    - List of server hops used to deliver message:

          --> (1) "attacker" <attacker@attacker.com>

              |_> (2) ec2-11-22-33-44.eu-west-3.compute.amazonaws.com. (11.22.33.44)
                      time: 01 Jan 2021 12:34:18

                  |_> (3) mail-wr1-f51.google.com (209.85.221.51)
                          time: 01 Jan 2021 12:34:20
                          version: fuzzy match: Exchange Server 2019 CU11; October 12, 2021; 15.2.986.9

                      |_> (4) SN1NAM02FT0061.eop-nam02.prod.protection.outlook.com (2603:10b6:806:131:cafe::e5)
                              time: 01 Jan 2021 12:34:20
                              version: fuzzy match: Exchange Server 2019 CU11; October 12, 2021; 15.2.986.9

                          |_> (5) SA0PR11CA0138.namprd11.prod.outlook.com (2603:10b6:806:131::23)
                                  time: 01 Jan 2021 12:34:20
                                  version: fuzzy match: Exchange Server 2019 CU11; October 12, 2021; 15.2.986.9

                              |_> (6) CP2PR80MB4114.lamprd80.prod.outlook.com (2603:10d6:102:3c::15)
                                      time: 01 Jan 2021 12:34:23

                                  |_> (7) "Victim Surname" <victim@contoso.com>



------------------------------------------

[...]

------------------------------------------
(4) Test: Mail Client Version

HEADER:
    X-Mailer

VALUE:
    OEM

ANALYSIS:
    - X-Mailer header was present and contained value: "OEM".


------------------------------------------
(5) Test: X-Forefront-Antispam-Report

HEADER:
    X-Forefront-Antispam-Report

VALUE:
    CIP:209.85.221.51;CTRY:US;LANG:de;SCL:5;SRV:;IPV:NLI;SFV:SPM;H:mail-wr1-f51.google.com;PTR:mail-wr1
    -f51.google.com;CAT:SPM;SFS:(4636009)(6916009)(1096003)(6666004)(4744005)(19625305002)(58800400
    005)(166002)(336012)(356005)(55446002)(5660300002)(956004)(121216002)(7596003)(7636003)(9686003
    )(86362001)(224303003)(26005)(35100500006)(43540500002);DIR:INB;

ANALYSIS:
    - CIP: Connecting IP address: 209.85.221.51

        - CTRY: The source country as determined by the connecting IP address
                - US

        - LANG: The language in which the message was written
                - de

        - IPV: Ingress Peer Verification status
                - NLI: The IP address was not found on any IP reputation list.

        - SFV: Message Filtering
                - SPM: The message was marked as spam by spam filtering.

        - H: The HELO or EHLO string of the connecting email server.
                - mail-wr1-f51.google.com

        - PTR: Reverse DNS of the Connecting IP peer's address
                - mail-wr1-f51.google.com

        - CAT: The category of protection policy
                - SPM: Spam

        - DIR: Direction of email verification
                - INB: Inbound email verification

        - Message matched 23 Anti-Spam rules:
                - (1096003)
                - (121216002)
                - (166002)
                - (19625305002)
                - (224303003)
                - (26005)
                - (336012)
                - (35100500006)         - (SPAM) Message contained embedded image.
                - (356005)
                - (43540500002)
                - (4636009)
                - (4744005)
                - (55446002)
                - (5660300002)
                - (58800400005)
                - (6666004)
                - (6916009)
                - (7596003)
                - (7636003)
                - (86362001)
                - (956004)
                - (9686003)

        - SCL: Spam Confidence Level: 5
                - SPAM: Spam filtering marked the message as Spam


More information:
        - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers
        - https://docs.microsoft.com/en-us/exchange/antispam-and-antimalware/antispam-protection/antispam-stamps
        - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/spam-confidence-levels
        - https://docs.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/run-a-message-trace-and-view-results


------------------------------------------
(6) Test: X-Microsoft-Antispam-Mailbox-Delivery

HEADER:
    X-Microsoft-Antispam-Mailbox-Delivery

VALUE:
    ucf:0;jmr:1;auth:0;dest:J;ENG:(910001)(944506458)(944626604)(750132)(520011016);

ANALYSIS:
    - This header denotes what to do with received message, where to put it.

        - auth: Message originating from Authenticated sender
                - 0: Not Authenticated

        - dest: Destination where message should be placed
                - J: JUNK directory

        - Message matched 6 Anti-Spam Delivery rules:
                - (520011016)
                - (750132)
                - (910001)
                - (944506458)
                - (944626604)


------------------------------------------
(7) Test: X-Microsoft-Antispam Bulk Mail

HEADER:
    X-Microsoft-Antispam
VALUE:
    BCL:0;

ANALYSIS:
    - BCL: BULK Confidence Level: 0
        The message isn't from a bulk sender.

    More information:
                - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/bulk-complaint-level-values

------------------------------------------

[...]

------------------------------------------
(10) Test: MS Defender ATP Message Properties

HEADER:
    X-MS-Exchange-AtpMessageProperties

VALUE:
    SA|SL

ANALYSIS:
    - MS Defender Advanced Threat Protection enabled following protections on this message:
        - Safe Attachments Protection
        - Safe Links Protection


------------------------------------------
(11) Test: Domain Impersonation

HEADER:
    From

VALUE:
    "attacker" <attacker@attacker.com>

ANALYSIS:
    - Mail From: <attacker@attacker.com>

                - Mail Domain: attacker.com
                       --> resolves to: 11.22.33.44
                           --> reverse-DNS resolves to: ec2-11-22-33-44.eu-west-3.compute.amazonaws.com
                               (sender's domain: amazonaws.com)

                - First Hop:   SMTP-SERVICE (44.55.66.77)
                       --> resolves to:
                           --> reverse-DNS resolves to: host44-55-66-77.static.arubacloud.pl
                               (first hop's domain: arubacloud.pl)

        - Domain SPF: "v=spf1 include:_spf.google.com ~all"

        - WARNING! Potential Domain Impersonation!
                - Mail's domain should resolve to:      amazonaws.com
                - But instead first hop resolved to:    arubacloud.pl
```

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

  - Embedded images
  - Images with lacking `ALT=""` attribute
  - Anchors trying to masquerade links
  
  Such characteristics are known bad smells that will let your e-mail blocked.

- [**`RobustPentestMacro`**](https://github.com/mgeeky/RobustPentestMacro) - This is a rich-featured Visual Basic macro code for use during Penetration Testing assignments, implementing various advanced post-exploitation techniques.

- **`warnings\EN-Word.docx`** and **`warnings\EN-Excel.docx`**  - Set of ready-to-use Microsoft Office Word shapes that can be pasted / inserted into malicious documents for enticing user into clicking "Enable Editing" and "Enable Content" buttons.

- **`WMIPersistence.vbs`** - Visual Basic Script implementing WMI Persistence method (as implemented in SEADADDY malware and further documented by Matt Graeber) to make the Macro code schedule malware startup after roughly 3 minutes since system gets up. ([gist](https://gist.github.com/mgeeky/d00ba855d2af73fd8d7446df0f64c25a))

- **`Various-Macro-Based-RCEs.md`** - Various Visual Basic Macros-based Remote Code Execution techniques to get your meterpreter invoked on the infected machine. ([gist](https://gist.github.com/mgeeky/61e4dfe305ab719e9874ca442779a91d))

- **`vba-macro-mac-persistence.vbs`** - (WIP) Working on VBA-based MacPersistance functionality for MS Office for Mac Macros. ([gist](https://gist.github.com/mgeeky/dd184e7f50dfab5ac97b4855f23952bc))

- **`vba-windows-persistence.vbs`** - VBA Script implementing two windows persistence methods - via WMI EventFilter object and via simple Registry Run. ([gist](https://gist.github.com/mgeeky/07ffbd9dbb64c80afe05fb45a0f66f81))

- [**`VisualBasicObfuscator`**](https://github.com/mgeeky/VisualBasicObfuscator) - Visual Basic Code universal Obfuscator intended to be used during penetration testing assignments.
