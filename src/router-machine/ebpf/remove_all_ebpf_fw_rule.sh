#!/bin/bash

# Copyright (c) 2020
# Author: Angelo Feraudo
# starting from: https://github.com/osmud/osmud/blob/master/src/openwrt/remove_ip_fw_rules.sh
# Removes all firewall rules involving the IP address
# this script requires to be superuser


BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -i <ip-addr> -e <ebpf_program_path>" 1>&2; 
  exit 0; 
}

DEVICE_IP=""
EBPF_PROGRAM=""

while getopts 'hi:e:' option; do
    case "${option}" in
        i) DEVICE_IP=$OPTARG;;
        e) EBPF_PROGRAM=$OPTARG;;
	h | *) usage;;
    esac
done


if [[ -z "${DEVICE_IP/ //}" ]]; then
    echo -e "ERROR: Please specify the source ip!\n"
    exit 1
fi

if [[ -z "${EBPF_PROGRAM/ //}" ]]; then
    echo -e "ERROR: Please specify the ebpf program path!\n"
    exit 1
fi


LINE_NUMBERS_IP=$(grep ${DEVICE_IP} -n rules/ebpf.rules | cut -f 1 -d:)
LINE_NUMBER_CONFIRMED=$(grep CONFIRMED -n rules/ebpf.rules | cut -f 1 -d:)

LINE_REMOVED=0
for LINE in $LINE_NUMBERS_IP; do
    if [ $LINE -lt $LINE_NUMBER_CONFIRMED ]; then
        # Removing rules committed
        TO_REMOVE=`expr $LINE - $LINE_REMOVED`
        RULE=$(sed "${TO_REMOVE}q;d" rules/ebpf.rules)

        echo "Delete rule ebpf firewall"
        # Delete rule from firewall
        $EBPF_PROGRAM -r $RULE

        # Delete the rule from the file
        sed -i "${TO_REMOVE}d" rules/ebpf.rules
        LINE_REMOVED=`expr $LINE_REMOVED + 1`
    fi
done

# Debug
# echo "Total rules removed: $LINE_REMOVED"

exit 0