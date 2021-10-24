#!/bin/bash
#
# Simple vm-specific management bash functions and aliases.
# Coming with basic functionality of starting, stopping and status checking
# routines. Easy to change to manage other type of VMs.
#
# Providing commands for:
#   - starting/stopping selected VM
#   - checking whether selected VM is running
#   - easily ssh'ing to the selected VM
#   - scanning for other VMs
#   - setting selected VM's IP address within /etc/hosts (and alike) file
#
# Mariusz Banach / mgeeky, '16-'19
# v0.7
#

# VM_NAME as defined in VirtualBox. Name must not contain any special characters, not
# even space.
VM_NAME=kali

# User's name to be used during ssh.
VM_USER=root

# Host-only's interface network address and interface
HOST_ONLY_NET=192.168.56.1
HOST_ONLY_IFACE=vboxnet0

# Hosts file where to put the VM's host IP address
HOSTS_FILE=/etc/hosts

# Command to be run to detect proper VM and pattern to be matched then.
VM_DETECT_COMMAND="uname -a"
VM_DETECT_PATTERN="Linux Kali"

# Initial commands one would like to get executed upon VM start.
VM_INIT_COMMANDS="dhclient -r eth1 ; dhclient -v eth1"



#
# Will set the following aliases:
#   - ssh<vm> alias for quick ssh-connection
#   - get<vm> alias for quick vm's ip resolution
#   - start<vm> alias for starting up particular vm
#   - stop<vm> alias for stopping particular vm
#   - is<vm> alias for checking whether the vm is running.
#
# For instance, when VM_NAME=Kali - the following aliases will be defined:
#   sshkali, getkali, and so on
#
function setup_aliases() {
  name=$VM_NAME
  if [ -z $name ]; then
    echo "[!] You must set the VM_NAME variable within that script first!"
    exit 1
  fi
  alias ssh$name="ssh -o StrictHostKeyChecking=no -Y $VM_USER@$name"
  alias get$name="cat $HOSTS_FILE | grep -i $name | cut -d' ' -f1"
  alias start$name="startvm"
  alias stop$name="stopvm"
  alias is$name="VBoxManage list runningvms | grep -qi $name && echo '[+] Running' || echo '[-] Not running';"
}


#
# Function for starting particular VM and then detecting it within
# user-specified host-only network, in order to setup correct entry in hosts file.
# Afterwards some additional actions like sshfs mounting could be deployed.
#
function startvm() {
  if [ -n "$1" ] && [[ "$1" == "-h" ]]; then
    echo "[?] Usage: startvm [mode] - where [mode] is: headless (default) or gui"
    return
  fi
  
  name=$VM_NAME
  #hostname=${name,,}
  hostname=$name
  mode=$1
  if [[ "$mode" == "" ]]; then
    mode='headless'
  elif [[ "$mode" == "gui" ]]; then
    mode='gui'
  else
    echo "[?] Usage: startvm [mode] - where [mode] is: headless (default) or gui"
    return
  fi
    
  echo "[>] Launching $name in $mode"
  if [[ $(VBoxManage list runningvms | grep -i $name) ]]; then
    echo "[+] Already running..."
  else
    echo "[>] Awaiting for machine to get up..."
    VBoxManage startvm $name --type $mode
    if [ $? -ne 0 ]; then
      echo "[!] Could not get $name started. Bailing out."
      exit 1
    fi

    found=0
    sleep 16
    
    for i in `seq 1 25`;
    do
      if [ $found -ne 0 ]; then
        break
      fi

      echo -e "\t$i. Attempting to connect with $name..."
      sleep 3

      if scan_for_vm; then
        found=1
        break
      fi
    done

    if [ $found -ne 1 ]; then
      echo "[!] Critical - could not locate $name VM machine on network."
      echo -e "\tYou can always try 'scan_for_vm' command to do a sweep again and retry process."
      return
    fi

    echo "[+] Succeeded. $name found in network."
  fi
}


#
# Function for stopping particular VM.
#
function stopvm() {
  name=$VM_NAME
  hostname=$name

  if VBoxManage list runningvms | grep -qi $name
  then
    sleep 2
    sudo sed -i "/$hostname/d" $HOSTS_FILE
    echo "[+] Stopping $VM_NAME..."
    VBoxManage controlvm $name savestate
  else
    echo "[-] Not running."
    return
  fi

  sleep 3
  if VBoxManage list runningvms | grep -qi $name
  then
    echo "[?] Seems that $name do not want to be pasued..."
    sleep 2
    VBoxManage controlvm $name acpipowerbutton

    if VBoxManage list runningvms | grep -qi $name
    then
      echo "[-] Could not pause $name politely. Cut his head!"
      sleep 3
      VBoxManage controlvm $name poweroff
    else
      echo "[+] Ok, it had shut itself down."
    fi
  fi
}


#
# One can use that very function to enumerate available machines 
# visible from VMs network interface (under ARP scanning).
#
function find_vms_netdiscover {
    sudo netdiscover -i $HOST_ONLY_IFACE -r $HOST_ONLY_NET/24 -N -P | grep ${HOST_ONLY_NET:0:5} | cut -d' ' -f2 | tail -n +2 
}

function find_vms_nmap {
    nmap -sn $HOST_ONLY_NET/24 -oG - | grep Up | awk '{print $2}'
}

function find_vms {
    sudo ifconfig $HOST_ONLY_IFACE up
    out=""
    if [ -x "$(command -v nmap)" ]; then
      out=$(find_vms_nmap)
      if test "$out" != ""; then
        echo "$out"
        return
      fi
    fi
    if [ -x "$(command -v netdiscover)" ]; then
      out=$(find_vms_netdiscover)
      if test "$out" != ""; then
        echo "$out"
        return
      fi
    fi
    echo ""
}

function detect_vm {
    out=$(timeout 30s ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 $VM_USER@$1 "$VM_DETECT_COMMAND" 2>/dev/null )
    if [ $? -eq 124 ] || [ $? -eq 255 ]; then
      echo "[!] Machine $1 timed out while trying to detect it by ssh probing."
      return 1
    fi

    if echo "$out" | grep -qi "$VM_DETECT_PATTERN" ; then
      return 0
    else
      return 1
    fi
}

# 
# If for some reason `start` command didn't manage to find the VM
# that was starting at that moment, one can repeat the scan & set process
# manually using the below command.
#
function scan_for_vm {

  # Scanning hosts in host-only network made by VirtualBox and then every
  # found host will be ssh'd to get it's uname and determine whether it is our vm.
  # Thanks to this loop we will not be failing to connect to our VM in case it's
  # IP would get assigned differently from VBox dhcp.
  hosts=$(find_vms)
 
  declare -a hostsarray
  while read -r host
  do
    hostsarray+=($host)
  done <<< "$hosts"

  sorted_hostsarray=($(echo "${hostsarray[@]}" | tr ' ' '\n' | sort -u))
  for host in $sorted_hostsarray[@]; do
    echo "[.] Testing: $host"
    detect_vm $host
    if [ $? -eq 0 ]
    then
      # VM found by match in uname's output.
      echo "[+] Found VM by ssh probing: $host"

      if [ -n "$VM_INIT_COMMANDS" ]; then
        echo "[+] Running VM init commands..."
        timeout 1m ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 $VM_USER@$host "$VM_INIT_COMMANDS" 2>/dev/null 
        if [ $? -eq 124 ]; then
          echo "[?] Timed out while trying to run VM_INIT_COMMANDS."
          #return 1
          echo "Continuing anyway..."
        fi
        detect_vm $host
        if [ $? -ne 0 ]; then
          if [ $# -eq 1 ] && [ "$1" == "again" ] ; then
			echo "[!] After initial commands the connection with VM is lost. Repeat the 'scan_for_vm' process"
			return 1
          else
            scan_for_vm "again"
          fi
        fi
      fi
          
      # Since the shell does output redirection not sudo, we have to write
      # to the hosts file like so:
      #
      cat $HOSTS_FILE | grep -qi $VM_NAME
      if [ $? -eq 0 ] && [ "$1" != "again" ]; then
        sudo sed -i -E "s/^[0-9]{1,3}.[0-9]{1,3}+.[0-9]{1,3}+.[0-9]{1,3}+\s+$VM_NAME/$host $VM_NAME/" $HOSTS_FILE
        echo "[+] Updated /etc/hosts file with '$host $VM_NAME' entry."
      else
        echo "$host $hostname" | sudo tee --append $HOSTS_FILE > /dev/null
      fi
      return 0
    else
      #echo "[.] Not our target VM: '$host'"
      continue
    fi
  done

  echo "[!] Could not locate $VM_NAME machine within the network."
  return 1
}

setup_aliases
