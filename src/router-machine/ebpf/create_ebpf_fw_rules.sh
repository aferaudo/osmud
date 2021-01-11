#!/bin/bash

# Copyright (c) 2020
# Author: Angelo Feraudo
# starting from: https://github.com/osmud/osmud/blob/master/src/openwrt/create_ip_fw_rules.sh

# This script uses the ebpf middleware developed by Diana Andreea Popescu

# EBPF needs to be attached to the input and output interfaces, but considering that this is not supported
# by MUD standard, we need to introduce a configuration file where they can be specified.


BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -t <target_firewall_action> -n <rule-name> -i <src-ip> -a <src-port> 
Optional: -p <proto> -s <src-zone>  -d <dest-zone> -j <dest-ip> -b <dest-port> -c <device host name> -r <packet rate> -e <byte rate>" 1>&2; 
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


while getopts 'ht:p:s:i:a:d:j:b:n:f:c:r:e:' option; do
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
    e) BYTE_RATE=$OPTARG;;
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

