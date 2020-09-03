#!/bin/bash

# TODO Still in work in progress

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
Optional: -p <proto> -s <src-zone>  -d <dest-zone> -j <dest-ip> -b <dest-port> -c <device host name> -r <packet rate>" 1>&2; 
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
PACKET_RATE=""  # New field


while getopts 'ht:p:s:i:a:d:j:b:n:f:c:r:' option; do
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

FINAL_HOST_NAME="mud_${HOST_NAME}_${RULE_NAME}"

IPTABLES_RULE=""

# A MUD file defines rules for incoming packets destinated for another host (external to the network)
CHAIN="FORWARD"

IP_ADDRESSES=""
PROTOCOL=""
PORTS=""


# All the rules will be appended!
if [ ${FAMILY} == 'ipv6' ]; then
    IPTABLES_RULE="ip6tables -A ${CHAIN}"
else
    IPTABLES_RULE="iptables -A ${CHAIN}"
fi

# Source ip address
IP_ADDRESSES="-s ${SRC_IP}"

# Defining packet rate for outgoing packets from that SRC
# TODO It should be noted that packet rate is defined only at ipv4 layer. For a more fine grained control,
# we should define it in other layers as well (e.g. syn flooding)
if [ ${PACKET_RATE} != '(null)' ]; then
    # By default the initial burst limit is set to 5 + packetrate
    BURST_LIMIT=`expr 5 + $PACKET_RATE`
    eval "${IPTABLES_RULE} ${IP_ADDRESSES} -m limit --limit ${PACKET_RATE}/s --limit-burst ${BURST_LIMIT} -j ${TARGET}"
fi

if [ ${DEST_IP} != 'any' ]; then
    IP_ADDRESSES="${IP_ADDRESSES} -d ${DEST_IP}"
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


IPTABLES_RULE="${IPTABLES_RULE} ${PROTOCOL} ${IP_ADDRESSES} ${PORTS} -j ${TARGET}"
eval $IPTABLES_RULE

exit 0
