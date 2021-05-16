
## Other Penetration-Testing related scripts and tools


- **`bluetoothObexSpam.py`** - Script intended to flood bluetooth enabled devices with incoming OBEX Object Push requests containing attacker-specified file. ([gist](https://gist.github.com/mgeeky/5b35453cd46837a01200a0eca4aa1e41))

- **`Contoso-AD-Structure`** - Simple script intended to create a sample AD structure filled out with users and groups.

- **`correlateCrackedHashes.py`** - Hashcat results correlation utility.
Takes two files on input. Tries to find every line of the second file within the first file and for every found match - extracts password value from the second file's line. Then prints these correlations.

  In other words - having the following in FileA:
  `some-user@example.com,68eacb97d86f0c4621fa2b0e17cabd8c`

  and a line in FileB that would be a result of running hashcat:
  `68eacb97d86f0c4621fa2b0e17cabd8c:Test123`

  the script will print out:
  `some-user@example.com,68eacb97d86f0c4621fa2b0e17cabd8c,Test123`

- **`encrypt.rb`** - Simple File Encryption utility (with support for Blowfish, GOST, IDEA, AES) capable of encrypting directories. ([gist](https://gist.github.com/mgeeky/751c01c4dac99871f4da))

- **`forticlientsslvpn-expect.sh`** - Forticlient SSL VPN Client launching script utilizing expect. Useful while working for clients exposing their local networks through a Fortinet SSL VPN. [gist](https://gist.githubusercontent.com/mgeeky/8afc0e32b8b97fd6f96fce6098615a93/raw/cf127be09d02e04c00eb578e4ef1219a773d21cf/forticlientsslvpn-expect.sh)

- **`playRTPStream.sh`** - Using rtpdump to play RTP streams from PCAP files with VLC. This script was useful to extract RTP Streams from sniffed VoIP communication and then with a help of VLC to dump those streams into valid .wav files. (https://github.com/hdiniz/rtpdump). [gist](https://gist.github.com/mgeeky/0b8bd81a3f6fb70eec543bc0bae2f079)

- **`vm-manager.sh`** - A bash script offering several aliases/functions for quick management of a single Virtualbox VM machine. Handy to use it for example to manage a Kali box. By issuing `startkali` the VM will raise, `sshkali` - offers instant SSH into your VM, `getkali` - returns VM's IP address, `iskali` - checks whether VM is running, `stopkali` goes without explanation. [gist](https://gist.github.com/mgeeky/80b1f7addb792796d8bfb67188d72f4a)

```bash
user@my-box $ startkali
[>] Launching kali in headless
[>] Awaiting for machine to get up...
Waiting for VM "kali" to power on...
VM "kali" has been successfully started.
	1. Attempting to connect with kali...
[.] Testing: 192.168.56.1
[.] Testing: 192.168.56.101
[+] Found VM by ssh probing: 192.168.56.101
[+] Running VM init commands...
[?] Timed out while trying to run VM_INIT_COMMANDS.
Continuing anyway...
[.] Testing: 192.168.56.1
[.] Testing: 192.168.56.102
[+] Found VM by ssh probing: 192.168.56.102
[+] Running VM init commands...
[+] Updated /etc/hosts file with '192.168.56.102 kali' entry.
[+] Succeeded. kali found in network.

user@my-box $ sshkali
Linux Kali 5.3.0-kali2-amd64 #1 SMP Debian 5.3.9-1kali1 (2019-11-11) x86_64
Last login: Fri Dec  6 07:40:19 2019 from 192.168.56.1
root@Kali:~ # hostname
Kali
```

- **`xor-key-recovery.py`** - Simple XOR brute-force Key recovery script - given a cipher text, plain text and key length - it searches for proper key that could decrypt cipher into text. ([gist](https://gist.github.com/mgeeky/589b2cf781901288dfea0894a780ff98))

