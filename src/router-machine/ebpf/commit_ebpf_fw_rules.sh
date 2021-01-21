#!/bin/bash
# Copyright (c) 2020
# Author: Angelo Feraudo

# Remove confirmed line from that file if any
LINE_NUMBER=$(grep CONFIRMED -n rules/ebpf.rules | cut -f 1 -d:)

if [ -n "${LINE_NUMBER}" ]; then
    sed -i "${LINE_NUMBER}d" rules/ebpf.rules
fi


# write confirmed
echo "---CONFIRMED---" >> rules/ebpf.rules
exit 0