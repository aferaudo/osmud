#!/bin/bash

# Copyright (c) 2020
# Author: Angelo Feraudo

# Rollback operations:
# Delete all rules not yet confirmed


LINE_NUMBER_CONFIRMED=$(grep CONFIRMED -n rules/ebpf.rules | cut -f 1 -d:)

# Counting total lines
TOTAL_LINES=$(awk 'END{print NR}' rules/ebpf.rules) 
LINE_NUMBER_CONFIRMED=`expr $LINE_NUMBER_CONFIRMED + 1`

LINE_REMOVED=0
for LINE in $(seq ${LINE_NUMBER_CONFIRMED} ${TOTAL_LINES});do
    # Fetching rule committed but not confirmed
    TO_REMOVE=`expr $LINE - $LINE_REMOVED`
    RULE=$(sed "${TO_REMOVE}q;d" rules/ebpf.rules)

    # Removing rule committed but not confirmed
    $EBPF_PROGRAM -r $RULE

    # Delete the rule from the file
    sed -i "${TO_REMOVE}d" rules/ebpf.rules
    LINE_REMOVED=`expr $LINE_REMOVED + 1`

done

exit 0
