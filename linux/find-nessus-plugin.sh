#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: ./find-nessus-plugin.sh <PLUGIN-ID>"
	exit 1
fi

PLUGIN_ID=$1
PLUGINS_DIR=$(find / -name zinwave_series_3000_das_default_credentials.nasl -exec dirname {} \; -quit)

if [[ "$PLUGINS_DIR" == "" ]]; then
	echo "[!] Could not find Nessus plugins directory."
	exit 1
fi

grep -l -a -o -r -m 1 --include=*.nasl -G "script_id($PLUGIN_ID)" $PLUGINS_DIR

