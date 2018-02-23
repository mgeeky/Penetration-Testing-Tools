## Networks Penetration Testing related scripts, tools and Cheatsheets

- **`CDPFlooder.py`** - CDP Flooding tool, intended to take out entire segment switched by some old Cisco switches, vulnerable to Denial of Service after receiving big amount of invalid CDP packets.

- **`dtpscan.py`** - DTP Scanner - simple script trying to determine type of configured switchport and DTP negotation mode in order to assist in VLAN Hopping attacks. ([gist](https://gist.github.com/mgeeky/3f678d385984ba0377299a844fb793fa))

- **`host-scanner-via-udp.py`** - Running Hosts scanner leveraging ICMP Destination Unreachable response upon UDP closed port packet. ([gist](https://gist.github.com/mgeeky/eae20db2d3dd4704fc6f04ea233bca9c))

- **`iis_webdav_upload.py`** - Microsoft IIS WebDAV Write Code Execution exploit (based on Metasploit HDM's <iis_webdav_upload_asp> implementation). ([gist](https://gist.github.com/mgeeky/ce179cdbe4d8d85979a28c1de61618c2))

- **`networkConfigurationCredentialsExtract.py`** - Network-configuration Credentials extraction script - intended to sweep input configuration file and extract keys, hashes, passwords. ([gist](https://gist.github.com/mgeeky/861a8769a261c7fc09a34b7d2bd1e1a0))

- **`nmap-grep-to-table.sh`** - Script converting nmap's greppable output (-oG) into a printable per-host tables. ([gist](https://gist.github.com/mgeeky/cd3092cf60fd513d786286a21c6fa915))

- **`pingsweep.py`** - Quick Python Scapy-based ping-sweeper. ([gist](https://gist.github.com/mgeeky/a360e4a124ddb9ef6a9ac1557b47d14c))

- **`sshbrute.py`** - ripped out from Violent Python - by TJ O'Connor. ([gist](https://gist.github.com/mgeeky/70606be7249a61ac26b34b1ef3b07553))

- **`smb-credential-leak.html`** - SMB Credentials leakage by MSEdge as presented in Browser Security White Paper, X41 D-Sec GmbH. ([gist](https://gist.github.com/mgeeky/44ce8a8887c169aa6a0093d915ea103d))

- **`smtpdowngrade.rb`** - Bettercap TCP Proxy SMTP Downgrade module - prevents the SMTP client from sending "STARTTLS" and returns "454 TLS Not available..." to the client. ([gist](https://gist.github.com/mgeeky/188f3f319e6f3536476e4b272ec0fb19))

- **`smtpvrfy.py`** - SMTP VRFY python tool intended to check whether SMTP server is leaking usernames. ([gist](https://gist.github.com/mgeeky/1df141b18082b6f424df98fa6a630435))

- **`wpa2-enterprise-utils`** - Couple of scripts that became needed/useful during **WPA2-Enterprise** penetration-testing assignment.

- **`VLANHopperDTP.py`** - VLAN Hopping via DTP Trunk (Switch) Spoofing exploit - script automating full VLAN Hopping attack, from DTP detection to VLAN Hop with DHCP lease request ([gist](https://gist.github.com/mgeeky/7ff9bb1dcf8aa093d3a157b3c22432a0))

    Sample output:

```
$ ./VLANHopperDTP.py --help

        :: VLAN Hopping via DTP Trunk negotiation 
        Performs VLAN Hopping via negotiated DTP Trunk / Switch Spoofing technique
        Mariusz B. / mgeeky, '18
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
        Mariusz B. / mgeeky, '18
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
