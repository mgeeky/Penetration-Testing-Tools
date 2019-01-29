#!/bin/bash

rtpdump_bin=/home/user/tools/rtpdump/rtpdump

if (( $# < 2 )); then
	echo
	echo This script tries to extract RTP streams from PCAP file using 
	echo 	https://github.com/hdiniz/rtpdump 
	echo utility and passing that stream to VLC player, or to output file.
	echo
	#echo "Usage: playStream.sh <file> <streamNum> [outfile]"
	echo "Usage: playStream.sh <file> <streamNum>"
	echo
	echo "   file - pcap file to process."
	echo "   streamNum - number of stream to play, or '-l' to list them."
	#echo "   outfile - (optional) path to output file where to dump that stream."
	echo
	exit 1
fi

file=$1
num=$2
vlc_bin=cvlc

if [ "$num" == "-l" ]; then
	$rtpdump_bin streams $file
else

	if (( $# > 2 )); then
		echo "[ERROR] Not implemented at the moment."
		#outfile=$3
		#echo "[Step 1]: Dumping RTP stream ($num) to file ($outfile)"
		#nc -nlp 4444 127.0.0.1 > $outfile &
		#echo $num | $rtpdump_bin play --host 0.0.0.0 --port 4444 $file > /dev/null
		#echo "[Step 2]: File: $outfile written."
	else
		echo "[Step 1]: Starting VLC on 0.0.0.0:4444"
		$vlc_bin rtp://@0.0.0.0:4444 2> /dev/null &disown; 

		echo "[Step 2]: Playing RTP stream ($num) on 0.0.0.0:4444"
		echo $num | $rtpdump_bin play --host 0.0.0.0 --port 4444 $file > /dev/null

		pkill vlc
	fi
fi
