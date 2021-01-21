#!/bin/bash

# Copyright (c) 2020
# Author: Angelo Feraudo
# starting from: https://github.com/osmud/osmud/blob/master/src/openwrt/create_ip_fw_rules.sh

# This script is designed to work on a linux machine, which means to produce rules for
# a linux firewall (netfilter)


# In order to make everything work:
# * Enable your firewall (Debian/ubuntu: 'sudo ufw enable' RHEL/CentOS/Fedora: chkconfig iptables on; service iptables start);
# * Configure your interfaces correctly (lan and wan)
# * Launch osmud as superuser


# The script arguments remain the same of the openwrt script, except the packet rate addition.

BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -t <target_firewall_action> -n <rule-name> -i <src-ip> -a <src-port> 
Optional: -p <proto> -s <src-zone>  -d <dest-zone> -j <dest-ip> -b <dest-port> -c <device host name> -r <packet rate> -m <byte rate>" 1>&2; 
  exit 0; 
}

TARGET=""
PROTO=""
SRC=""
SRC_IP=""
SRC_PORT=""
DEST=""
DEST_IP=""
DEST_PORT=""
RULE_NAME=""
HOST_NAME=""
FAMILY=""
PACKET_RATE=""  # New field -r
BYTE_RATE=""  # New field -e


while getopts 'ht:p:s:i:a:d:j:b:n:f:c:r:m:' option; do
    case "${option}" in
	t) TARGET=$OPTARG;;
	f) FAMILY=$OPTARG;;
	n) RULE_NAME=$OPTARG;;
	p) PROTO=$OPTARG;;
    s) SRC=$OPTARG;;
    i) SRC_IP=$OPTARG;;
    a) SRC_PORT=$OPTARG;;
    d) DEST=$OPTARG;;
    j) DEST_IP=$OPTARG;;
    b) DEST_PORT=$OPTARG;;
    c) HOST_NAME=$OPTARG;;
    r) PACKET_RATE=$OPTARG;;
    m) BYTE_RATE=$OPTARG;;
	h | *) usage;;
    esac
done


if [[ -z "${TARGET/ //}" ]]; then
    echo -e "ERROR: Plese specify target firewall action [ACCEPT|REJECT|DENY]!\n"
    exit 1
fi

if [[ -z "${HOST_NAME/ //}" ]]; then
    echo -e "ERROR: Plese specify target device host name action!\n"
    exit 1
fi

if [[ -z "${FAMILY/ //}" ]]; then
    echo -e "ERROR: Plese specify firewall protocol family [ipv4|ipv6|all]!\n"
    exit 1
fi

if [[ -z "${PROTO/ //}" ]]; then
    echo -e "ERROR: Plese specify protocol [tcp|udp|all].\n"
    exit 1
fi

if [[ -z "${SRC/ //}" ]]; then
    echo -e "ERROR: Plese specify source zone!\n"
    exit 1
fi

if [[ -z "${SRC_IP/ //}" ]]; then
    echo -e "ERROR: Please specify source ip!\n"
    exit 1
fi

if [[ -z "${SRC_PORT/ //}" ]]; then
    echo -e "ERROR: Please specify source port or 'any'.\n"
    exit 1
fi

if [[ -z "${DEST/ //}" ]]; then
    echo -e "ERROR: Plese specify dest zone!\n"
    exit 1
fi

if [[ -z "${DEST_IP/ //}" ]]; then
    echo -e "ERROR: Please specify dest ip or 'any'.\n"
    exit 1
fi

if [[ -z "${DEST_PORT/ //}" ]]; then
    echo "ERROR: Please specify dest port or 'any'\n"
    exit 1
fi
# The control is not true for the packet rate, because it could be null. 
# In such a case even the rule production changes



covertMeasureInByte() {
    # This method supports only kb and Mb. All the others possibility are directly considered as seconds
    
    case "${TO_BYTE}" in
    "kb")
        CONVERSION_FACTOR=1000 # in Decimal
        # CONVERSION_FACTOR=1024 # in Binary
        ;;
    "Mb") 
        CONVERSION_FACTOR=1000000 # in Decimal
        # CONVERSION_FACTOR=1048576 # in binary
        ;;
    *)
        # Here we leave everything as it is
        CONVERSION_FACTOR=1
        ;;
    esac
}

convertRateInSec () {
    # Convert Rate in second. Possible values: /minute, /hour, /day
    local RATE=$(echo ${BYTE_RATE} | awk -F/ '{print $2}')
    local VALUE=$(echo $BYTE_RATE | grep -o '[0-9]\+') # Obatains onlyu the numbers
    
    TO_BYTE=$(echo $BYTE_RATE | awk -F/ '{print $1}' | sed "s/$VALUE//g")
    covertMeasureInByte
    
    case "${RATE}" in
    "minute")
        VALUE=$(echo "scale=2; ${VALUE} * ${CONVERSION_FACTOR} / 60" | bc -l)
        ;;
    "hour") 
        VALUE=$(echo "scale=2; ${VALUE} * ${CONVERSION_FACTOR} / 3600" | bc -l)
        ;;
    "day") 
        VALUE=$(echo "scale=2; ${VALUE} * ${CONVERSION_FACTOR} / 86400" | bc -l)
        ;;
    *)
        ;;
    esac

    RATE="second"
    
    # Rounding the value
    VALUE=$(echo "(${VALUE}+0.5)/1" | bc)

    BYTE_RATE="${VALUE}b/$RATE"
}


FINAL_HOST_NAME="mud_${HOST_NAME}_${RULE_NAME}"

IPTABLES_RULE=""

# A MUD file defines rules for incoming packets destinated for another host (external to the network)
CHAIN="FORWARD" # First chain: checking packet and byte rate and jump to the next chain
MUD_CHAIN="MUD_CHAIN" # Second chain accept or drop the traffic

# Create mudfile chain, if exists, redirect the error on /dev/null
iptables -N $MUD_CHAIN > /dev/null 2>&1


IP_ADDRESSES=""
MODES=""
PROTOCOL=""
PORTS=""
ADDITIONAL_FIELDS=""

# Chain organisation
# This must be defined, because a custom chain does not have default policy.
# This could represent a probelm in case of externa ip addresses, for which a default policy is not defined by MUD!
if [ "${SRC}" = "wan" ]; then
    MUD_CHAIN=$CHAIN
fi

# Defining the IP protocol
if [ "${FAMILY}" = "ipv6" ]; then
    IPTABLES_RULE="ip6tables"
else
    IPTABLES_RULE="iptables"
fi

# Source ip address
IP_ADDRESSES="-s ${SRC_IP}"
MODES="srcip"

# Creating general rule to jump at MUD_CHAIN
eval "${IPTABLES_RULE} -C ${CHAIN} ${IP_ADDRESSES} -j ${MUD_CHAIN}" > /dev/null 2>&1
if [ $? -eq 1 -a "${SRC}" != "wan" ]; then
    eval "${IPTABLES_RULE} -A ${CHAIN} ${IP_ADDRESSES} -j ${MUD_CHAIN}"
fi

if [ ${DEST_IP} != 'any' ]; then
    IP_ADDRESSES="${IP_ADDRESSES} -d ${DEST_IP}"
    MODES="$MODES,dstip"
fi


# Defining packet rate for outgoing packets from that SRC
if  [ -n "${PACKET_RATE/ //}" -a "${PACKET_RATE}" != '(null)' ]; then
    # By default the initial burst limit is set to 5 + packetrate
    BURST_LIMIT=`expr 5 + $(echo $PACKET_RATE | awk -F/ '{print $1}')`
    
    # Default rate per seconds
    RATE=$(echo ${PACKET_RATE} | awk -F/ '{print $2}')
    if [[ -z "${RATE/ //}" ]]; then
        RATE="/second"
    else
        RATE=""
    fi

    ADDITIONAL_FIELDS="${ADDITIONAL_FIELDS} -m hashlimit --hashlimit-mode ${MODES} --hashlimit-upto ${PACKET_RATE}${RATE} --hashlimit-burst ${BURST_LIMIT} --hashlimit-name packet-rate-${SRC_IP}"
fi

if  [ -n "${BYTE_RATE/ //}" -a "${BYTE_RATE}" != '(null)' ] ; then
    
    # Converting rate in sec (Now even the unit is converted in byte)
    convertRateInSec
    
    ADDITIONAL_FIELDS="${ADDITIONAL_FIELDS} -m hashlimit --hashlimit-mode ${MODES} --hashlimit-upto ${BYTE_RATE} --hashlimit-name byte-rate-${SRC_IP}"
fi


# Source and destination zone should be used for something (e.g. to choose the interfaces direction)
# TODO implement this part, once you know the network structure

PROTOCOL="-p ${PROTO}"

if [ ${PROTO} == 'tcp' -o ${PROTO} == 'udp' ]; then
    
    # This parameters can be specified only if the protocol has been specified (that's how iptables works).
    # In particular, --sport and --dport are defined only for TCP and UDP protocol
    if [ ${SRC_PORT} != 'any' ]; then
        PORTS="${PORTS} --sport ${SRC_PORT}"
    fi

    if [ ${DEST_PORT} != 'any' ]; then
        PORTS="${PORTS} --dport ${DEST_PORT}"
    fi
fi

# All rules will be appended on MUD_CHAIN
IPTABLES_RULE="${IPTABLES_RULE} -A ${MUD_CHAIN} ${PROTOCOL} ${IP_ADDRESSES} ${PORTS} ${ADDITIONAL_FIELDS} -j ${TARGET}"
eval "${IPTABLES_RULE}"

exit 0
