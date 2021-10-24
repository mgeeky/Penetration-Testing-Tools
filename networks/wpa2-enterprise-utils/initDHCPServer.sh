#!/bin/bash

#
# This script set's up a DHCP server for Rouge AP / Evil Twin
# attack purposes, to make the victim actually reach out to the WAN.
#
# Nothing fancy, just set of needed commands. Especially handy when
# used with `startEAPHammer.sh` script.
#
# Mariusz Banach / mgeeky '18, <mb@binary-offensive.com>
#

if [ $# -ne 2 ]; then
    echo "Usage: initDhcp.sh <inputIface> <outputIface>"
	echo
	echo -e "\tinputIface - Interface upon which DHCP leases should be offered."
	echo -e "\toutputIfave - Interface offering access to WAN (default gateway)"
    exit 1
fi

INP=$1
OUT=$2

ifconfig $INP up 10.0.0.1 netmask 255.255.255.0
sleep 2

if [ "$(ps -e | grep dhcpd)" == "" ]; then
echo "[+] Started DHCP server."
dhcpd $INP &
fi

# Enable NAT
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables --table nat --append POSTROUTING --out-interface $OUT -j MASQUERADE
iptables --append FORWARD --in-interface $INP -j ACCEPT

sysctl -w net.ipv4.ip_forward=1
