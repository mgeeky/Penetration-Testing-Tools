### WPA2-Enterprise penetration testing utilities

Here are several utilities that came handy during real-world **WPA2-Enterprise** penetration testing assignments centered round great [eaphammer](https://github.com/s0lst1c3/eaphammer.git) tool.

- **`config.txt`** - example of configuraion file for `massDeauth.sh` script.

- **`initDHCPServer.sh`** - This script set's up a DHCP server for Rouge AP / Evil Twin attack purposes, to make the victim actually reach out to the WAN. Nothing fancy, just set of needed commands. Especially handy when used with `startEAPHammer.sh` script.

- **`massDeauth.sh`** - Simple script intended to perform mass-deauthentication of any associated&authenticated client to the Access-Point. Helpful to actively speed up Rogue AP/Evil Twin attacks in multiple Access-Points within an ESSID environments. In other words, if you have an ESSID set up from many access-points (BSSIDs) - this script will help you deauthenitcate all clients from those APs iteratively.

- **`startEAPHammer.sh`** - This script launches `eaphammer` tool by s0lst1c3, available from: https://github.com/s0lst1c3/eaphammer.git . The tool is a great way to manage hostapd-wpe server as well as perform additional attacks around the concept. Although when used in penetration testing assignments, the tool may not be as reliable as believed due to various nuances with WLAN interface being blocked, not reloaded, DHCP-forced and so on. This is where this script comes in - it tries to automatize those steps before launching the tool and after. Especially handy when used with companion script called: `initDHCPServer.sh`

