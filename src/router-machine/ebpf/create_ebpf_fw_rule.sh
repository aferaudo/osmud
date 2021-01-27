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
Required: -t <target_firewall_action> -n <rule-name> -i <src-ip> -a <src-port> -e <ebpf_program_path>
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
EBPF_PROGRAM="" # EBPF program
PACKET_RATE=""  # New field -r
BYTE_RATE=""  # New field -m


while getopts 'ht:p:s:i:a:e:d:j:b:n:f:c:r:m:' option; do
    case "${option}" in
	t) TARGET=$OPTARG;;
	f) FAMILY=$OPTARG;;
	n) RULE_NAME=$OPTARG;;
	p) PROTO=$OPTARG;;
    s) SRC=$OPTARG;;
    i) SRC_IP=$OPTARG;;
    a) SRC_PORT=$OPTARG;;
    e) EBPF_PROGRAM=$OPTARG;;
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

if [[ -z "${EBPF_PROGRAM/ //}" ]]; then
    echo "ERROR: Please specify EBPF program path"
    exit 1
fi

# The control is not true for the packet rate, because it could be null. 
# In such a case even the rule production changes




convertMeasureInByte() {

    local VALUE=$(echo $BYTE_RATE | grep -o '[0-9]\+')

    local TO_BYTE=$(echo $BYTE_RATE | awk -F/ '{print $1}' | sed "s/$VALUE//g")

    case "${TO_BYTE}" in
    "kb")
        BYTE=`expr ${VALUE} \* 1000` # in Decimal
        # BYTE=1024 # in Binary
        ;;
    "Mb") 
        BYTE=`expr ${VALUE} \* 1000000` # in Decimal
        # BYTE=1048576 # in binary
        ;;
    *)
        # Here we leave everything as it is
        BYTE=${VALUE}
        ;;
    esac

    # If window size as been defined by the packet rate, we should convert
    # the byte rate in the correct metrics
    if [ -n "${WINDOW_SIZE/ //}" ]; then
        local RATE=$(echo ${BYTE_RATE} | awk -F/ '{print $2}')
        case "${RATE}" in
        "minute")
            WINDOW_SIZE_BYTE="60";;
        "hour") 
            WINDOW_SIZE_BYTE="3600";;
        "day") 
            WINDOW_SIZE_BYTE="86400";;
        *)
            WINDOW_SIZE_BYTE="1";;
        esac

        FACTOR=$(echo ${WINDOW_SIZE} | awk '{print $2}')

        # Create the right amount of byte based on the window defined
        BYTE=$(echo "(${FACTOR}/${WINDOW_SIZE_BYTE})*${BYTE}" | bc -l)
        BYTE=$(echo "scale=0; (${BYTE}+0.5)/1" | bc)
    fi
    
}

defineWindowSize() {
    
    # By default the window is set to 60 secs
    case "${RATE}" in
    "minute")
        WINDOW_SIZE="-w 60";;
    "hour") 
        WINDOW_SIZE="-w 3600";;
    "day") 
        WINDOW_SIZE="-w 86400";;
    *)
        WINDOW_SIZE="-w 1";;
    esac

}

PORTS=""
OPTION_IP_SRC=""
OPTION_IP_DEST=""
ADDITIONAL_FIELDS=""

if [ ${PROTO} == 'tcp' -o ${PROTO} == 'udp' ]; then
    
    # This parameters can be specified only if the protocol has been specified (that's how iptables works).
    # In particular, --sport and --dport are defined only for TCP and UDP protocol
    if [ ${SRC_PORT} != 'any' ]; then
        PORTS="--src-port ${SRC_PORT}"
    fi

    if [ ${DEST_PORT} != 'any' ]; then
        PORTS="--dest-port ${DEST_PORT}"
    fi
fi

# Defining packet rate limit
if  [ -n "${PACKET_RATE/ //}" -a "${PACKET_RATE}" != '(null)' ]; then
    # Metrics that can be defined in MUD file are second/minute/hour/day
    # Observation: EBPF-IOT supports only one window!
    # So, packet and byte rate must have the same metric (per second/minute/hour/day)
    

    PACKET=$(echo ${PACKET_RATE} | awk -F/ '{print $1}')
    RATE=$(echo ${PACKET_RATE} | awk -F/ '{print $2}')
    
    # Computing window size 
    defineWindowSize

    # -g|--max-packet-rate Specify maximum packet rate for MUD rule.
    ADDITIONAL_FIELDS="$WINDOW_SIZE --max-packet-rate $PACKET"

fi

# Defining byte rate
if  [ -n "${BYTE_RATE/ //}" -a "${BYTE_RATE}" != '(null)' ] ; then


    if [ -z "${ADDITIONAL_FIELDS/ //}" ]; then
        # Computing window size (By default the window size used is that defined with packet rate)
        RATE=$(echo ${BYTE_RATE} | awk -F/ '{print $2}')
        defineWindowSize
        ADDITIONAL_FIELDS="$WINDOW_SIZE"
    fi

    # Convert to byte
    convertMeasureInByte

    # -j|--max-bytes-rate Specify maximum bytes rate for MUD rule.
    ADDITIONAL_FIELDS="${ADDITIONAL_FIELDS} --max-bytes-rate ${BYTE}"

fi

# Defining the IP protocol
if [ "${FAMILY}" = "ipv6" ]; then
    OPTION_IP_SRC="-6"
    OPTION_IP_DEST="-7"
else
    OPTION_IP_SRC="-4"
    OPTION_IP_DEST="-5"
fi

# The usage of another variable can help in removing phase
RULE="${OPTION_IP_SRC} ${SRC_IP} ${OPTION_IP_DEST} ${DEST_IP}  ${PORTS} -p ${PROTO} -o ${ADDITIONAL_FIELDS}"


# The MUD manager is designed to add a final rule to deny all the communications from that device.
# In this case it's not necessary, because by default all the communications are dropped
# So we skip the rules where destination address is any or protocol is all
if [ ${DEST_IP} != 'any' -o ${PROTO} != 'all' ]; then
    # Insert a rule
    ${EBPF_PROGRAM} -i ${RULE}
    echo "${RULE}" >> rules/ebpf.rules
fi


exit 0



