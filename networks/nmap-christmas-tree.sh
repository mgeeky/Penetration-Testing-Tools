#!/bin/bash

if [ $# -ne 3 ]; then
	echo "Usage: ./nmap-christmas-tree.sh <host> <opened-port> <closed-port>"
	echo -e "\nopened-port\t- A TCP port number that is known to be opened/listening, e.g. 443"
	echo -e "closed-port\t- A TCP port number that is known to be closed, e.g. 44444"
	echo
	exit 1
fi

HOST=$1
PORT1=$2
PORT2=$3

OPTS="-Pn -T4"

function scan {
	opts=$@
	echo "Trying $opts..."
	out=$(sudo nmap "$OPTS" -p $PORT1,$PORT2 $opts $HOST | grep -E "$PORT1|$PORT2")
	num=$(echo "$out" | awk '{print $2}' | uniq | wc -l)
	if [[ $num == 2 ]]; then
		echo
		echo "== DISCREPANCY occured on: $opts"
		echo -e "NMAP:\tsudo nmap "$OPTS" -p $PORT1,$PORT2 $opts $HOST"
		echo "$out"
		echo
	fi
}

scan -sS
scan -sT
scan -sA
scan -sW
scan -sM
scan -sN
scan -sF
scan -sX
scan --scanflags SYN
scan --scanflags SYNACK
scan --scanflags SYNFIN
scan --scanflags SYNPSH
scan --scanflags SYNRST
scan --scanflags SYNURG
scan --scanflags URG
scan --scanflags URGACK
scan --scanflags URGFIN
scan --scanflags URGPSH
scan --scanflags URGRST
scan --scanflags PSH
scan --scanflags PSHACK
scan --scanflags PSHFIN
scan --scanflags PSHRST
scan --scanflags ACK
scan --scanflags ACKFIN
scan --scanflags ACKRST
scan --scanflags RST
scan --scanflags RSTFIN
scan --scanflags FIN
scan -sS -f
scan -sT -f
scan -sA -f
scan -sW -f
scan -sM -f
scan -sN -f
scan -sF -f
scan -sX -f
scan --scanflags SYN -f
scan --scanflags SYNACK -f
scan --scanflags SYNFIN -f
scan --scanflags SYNPSH -f
scan --scanflags SYNRST -f
scan --scanflags SYNURG -f
scan --scanflags URG -f
scan --scanflags URGACK -f
scan --scanflags URGFIN -f
scan --scanflags URGPSH -f
scan --scanflags URGRST -f
scan --scanflags PSH -f
scan --scanflags PSHACK -f
scan --scanflags PSHFIN -f
scan --scanflags PSHRST -f
scan --scanflags ACK -f
scan --scanflags ACKFIN -f
scan --scanflags ACKRST -f
scan --scanflags RST -f
scan --scanflags RSTFIN -f
scan --scanflags FIN -f
scan -sS -f --badsum
scan -sA -f --badsum
scan -sW -f --badsum
scan -sM -f --badsum
scan -sN -f --badsum
scan -sF -f --badsum
scan -sX -f --badsum
scan --scanflags SYN -f --badsum
scan --scanflags SYNACK -f --badsum
scan --scanflags SYNFIN -f --badsum
scan --scanflags SYNPSH -f --badsum
scan --scanflags SYNRST -f --badsum
scan --scanflags SYNURG -f --badsum
scan --scanflags URG -f --badsum
scan --scanflags URGACK -f --badsum
scan --scanflags URGFIN -f --badsum
scan --scanflags URGPSH -f --badsum
scan --scanflags URGRST -f --badsum
scan --scanflags PSH -f --badsum
scan --scanflags PSHACK -f --badsum
scan --scanflags PSHFIN -f --badsum
scan --scanflags PSHRST -f --badsum
scan --scanflags ACK -f --badsum
scan --scanflags ACKFIN -f --badsum
scan --scanflags ACKRST -f --badsum
scan --scanflags RST -f --badsum
scan --scanflags RSTFIN -f --badsum
scan --scanflags FIN -f --badsum
scan -sS --badsum
scan -sA --badsum
scan -sW --badsum
scan -sM --badsum
scan -sN --badsum
scan -sF --badsum
scan -sX --badsum
scan --scanflags SYN --badsum
scan --scanflags SYNACK --badsum
scan --scanflags SYNFIN --badsum
scan --scanflags SYNPSH --badsum
scan --scanflags SYNRST --badsum
scan --scanflags SYNURG --badsum
scan --scanflags URG --badsum
scan --scanflags URGACK --badsum
scan --scanflags URGFIN --badsum
scan --scanflags URGPSH --badsum
scan --scanflags URGRST --badsum
scan --scanflags PSH --badsum
scan --scanflags PSHACK --badsum
scan --scanflags PSHFIN --badsum
scan --scanflags PSHRST --badsum
scan --scanflags ACK --badsum
scan --scanflags ACKFIN --badsum
scan --scanflags ACKRST --badsum
scan --scanflags RST --badsum
scan --scanflags RSTFIN --badsum
scan --scanflags FIN --badsum
scan -sS --mtu 16
scan -sA --mtu 16
scan -sW --mtu 16
scan -sM --mtu 16
scan -sN --mtu 16
scan -sF --mtu 16
scan -sX --mtu 16
scan --scanflags SYN --mtu 16
scan --scanflags SYNACK --mtu 16
scan --scanflags SYNFIN --mtu 16
scan --scanflags SYNPSH --mtu 16
scan --scanflags SYNRST --mtu 16
scan --scanflags SYNURG --mtu 16
scan --scanflags URG --mtu 16
scan --scanflags URGACK --mtu 16
scan --scanflags URGFIN --mtu 16
scan --scanflags URGPSH --mtu 16
scan --scanflags URGRST --mtu 16
scan --scanflags PSH --mtu 16
scan --scanflags PSHACK --mtu 16
scan --scanflags PSHFIN --mtu 16
scan --scanflags PSHRST --mtu 16
scan --scanflags ACK --mtu 16
scan --scanflags ACKFIN --mtu 16
scan --scanflags ACKRST --mtu 16
scan --scanflags RST --mtu 16
scan --scanflags RSTFIN --mtu 16
scan --scanflags FIN --mtu 16
scan -sS --mtu 65528
scan -sT --mtu 65528
scan -sA --mtu 65528
scan -sW --mtu 65528
scan -sM --mtu 65528
scan -sN --mtu 65528
scan -sF --mtu 65528
scan -sX --mtu 65528
scan --scanflags SYN --mtu 65528
scan --scanflags SYNACK --mtu 65528
scan --scanflags SYNFIN --mtu 65528
scan --scanflags SYNPSH --mtu 65528
scan --scanflags SYNRST --mtu 65528
scan --scanflags SYNURG --mtu 65528
scan --scanflags URG --mtu 65528
scan --scanflags URGACK --mtu 65528
scan --scanflags URGFIN --mtu 65528
scan --scanflags URGPSH --mtu 65528
scan --scanflags URGRST --mtu 65528
scan --scanflags PSH --mtu 65528
scan --scanflags PSHACK --mtu 65528
scan --scanflags PSHFIN --mtu 65528
scan --scanflags PSHRST --mtu 65528
scan --scanflags ACK --mtu 65528
scan --scanflags ACKFIN --mtu 65528
scan --scanflags ACKRST --mtu 65528
scan --scanflags RST --mtu 65528
scan --scanflags RSTFIN --mtu 65528
scan --scanflags FIN --mtu 65528
