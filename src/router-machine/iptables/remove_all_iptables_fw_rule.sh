#!/bin/bash

# Removes all firewall rules involving the IP address
# this script requires to be superuser

BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -i <ip-addr>" 1>&2; 
  exit 0; 
}

DEVICE_IP=""

while getopts 'hi:' option; do
    case "${option}" in
        i) DEVICE_IP=$OPTARG;;
	h | *) usage;;
    esac
done


if [[ -z "${DEVICE_IP/ //}" ]]; then
    echo -e "ERROR: Please specify the source ip!\n"
    exit 1
fi


# Remove procedure now is implemented for each chain + mud chain: when the right chain is found, this could be changed
# We refer to the only filtering table
MUD_CHAIN="MUD_CHAIN"

# Check on INPUT chain
LINE_NUMBERS=$(iptables -L INPUT --line-numbers | awk "/$DEVICE_IP/ {print\$1}")
COUNTER=0
for i in $LINE_NUMBERS
do
    INDEX=`expr $i - $COUNTER`
    iptables -D INPUT $INDEX
    COUNTER=`expr $COUNTER + 1`
done

# Check on FORWARD chain
LINE_NUMBERS=$(iptables -L FORWARD --line-numbers | awk "/$DEVICE_IP/ {print\$1}")
COUNTER=0
for i in $LINE_NUMBERS
do
    INDEX=`expr $i - $COUNTER`
    iptables -D FORWARD $INDEX
    COUNTER=`expr $COUNTER + 1`
done

# Check on OUTPUT chain
LINE_NUMBERS=$(iptables -L OUTPUT --line-numbers | awk "/$DEVICE_IP/ {print\$1}")
COUNTER=0
for i in $LINE_NUMBERS
do
    INDEX=`expr $i - $COUNTER`
    iptables -D OUTPUT $INDEX
    COUNTER=`expr $COUNTER + 1`
done


# Check on MUD chain
# It generates one error at the beginning because the chain has not been created yet
LINE_NUMBERS=$(iptables -L ${MUD_CHAIN} --line-numbers | awk "/$DEVICE_IP/ {print\$1}")
COUNTER=0
for i in $LINE_NUMBERS
do
    INDEX=`expr $i - $COUNTER`
    iptables -D ${MUD_CHAIN} $INDEX > /dev/null 2>&1
    COUNTER=`expr $COUNTER + 1`
done
