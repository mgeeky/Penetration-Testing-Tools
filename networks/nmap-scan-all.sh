#!/bin/bash

if [ $# -lt 2 ]; then
	echo "Usage: ./nmap-scan-all.sh <host> <output-file>"
	exit 1
fi

if [ $EUID != 0 ]; then
	echo "[!] This script must be launched as root."
	exit 1
fi

HOST="$1"
shift
OUT="$1"
shift
eXTRA_PARAMS="$@"

COMMON_OPTS="-Pn -A -T4 --osscan-guess --fuzzy --version-all -vv --reason --min-rate 300"
SCRIPTS="not (dos or brute or http-sql-injection)"
SCRIPTS_ARGS="--script-args http.useragent=\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/53.0 (KHTML, like Gecko) Chrome/64.0.32 Safari/53.0\""

echo "[+] Will scan: '$HOST' and store output to: '$OUT'"

nmap --script-updatedb > /dev/null

echo ""
echo "=========================================================================="
echo "SCAN 1: All TCP ports, SYN scan."
echo ""
echo "Scan using:"
echo -e "\tnmap $COMMON_OPTS -sS -p- --script \"$SCRIPTS\" $SCRIPTS_ARGS -oA \"$OUT.tcp-scan.log\" $HOST"
nmap $COMMON_OPTS -sS -p- --script "$SCRIPTS" $SCRIPTS_ARGS -oA "$OUT.tcp-scan.log" $HOST


echo ""
echo "=========================================================================="
echo "SCAN 2: SCTP INIT scan."
echo ""
echo "Scan using:"
echo -e "\tnmap $COMMON_OPTS -sZ -p- --script \"$SCRIPTS\" $SCRIPTS_ARGS -oA \"$OUT.sctp-init.log\" $HOST"
nmap $COMMON_OPTS -sZ -p- --script "$SCRIPTS" $SCRIPTS_ARGS -oA "$OUT.sctp-init.log" $HOST


echo ""
echo "=========================================================================="
echo "SCAN 3: UDP top 8192 ports."
echo ""
echo "Scan using:"
echo -e "\tnmap $COMMON_OPTS -sU --top-ports 8192 --script \"$SCRIPTS\" $SCRIPTS_ARGS -oA \"$OUT.tcp-scan.log\" $HOST"
nmap $COMMON_OPTS -sU --top-ports 8192 --script "$SCRIPTS" $SCRIPTS_ARGS -oA "$OUT.udp-scan.log" $HOST

