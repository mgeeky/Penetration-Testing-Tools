#!/bin/bash

modname=security2
friendlyname=WAF

if [ $# -ne 1 ]; then
    echo "Usage: ./toggleWaf <on|off|status>"
    exit 1
fi

case $1 in
    "on")
        if [ $EUID -ne 0 ]; then
            echo "[!] This function must be run as root. Use sudo."
            exit 1
        fi
        a2enmod $modname > /dev/null
        systemctl reload apache2
        echo "[+] $friendlyname enabled."
        ;;

    "off")
        if [ $EUID -ne 0 ]; then
            echo "[!] This function must be run as root. Use sudo."
            exit 1
        fi
        a2dismod $modname > /dev/null
        systemctl reload apache2
        echo "[-] $friendlyname disabled."
        ;;

    "status")
        if a2query -m $modname 2> /dev/null | grep -q 'enabled' ; then
            echo "[+] $friendlyname is enabled."
        else
            echo "[-] $friendlyname is disabled."
        fi
        ;;
esac
