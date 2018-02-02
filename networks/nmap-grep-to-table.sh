#!/bin/bash

#
# Simple script converting nmap's greppable output into a
# printable per-host table with protocol, port, state and service
# columns in it.
#

#
# WARNING: 
# This script looks for gnmap (-oG) files within 
# current working directory (cwd)
#

for host in $(find -name "*.gnmap" | sort -t'.' -n -k5)
do
  if cat $host | grep -q "Status: Up" && cat $host | grep -q "Ports:"; then
    hostip=$(grep Ports $host | cut -d' ' -f2)
    ports=$(cat ${hostip}*.gnmap | grep Ports | cut -d: -f3 | sed 's:/, :\n:g' | awk '{$1=$1}1')

    IFS=$'\n'

    echo -e "\n\nHost: $hostip\n"
    echo -e "Proto\t| Port\t| State\t\t| Service"
    echo -e "----------------------------------------------------"

    for port in $ports
    do
      proto=$(echo $port | cut -d/ -f3)
      portnum=$(echo $port | cut -d/ -f1)
      state=$(echo $port | cut -d/ -f2)
      service=$(echo $port | cut -d/ -f5)
      
      printf "%s\t| %-5s\t| %-13s\t| %s\n" $proto $portnum $state $service
    done | sort -u -k3,3 -n
  fi
done
