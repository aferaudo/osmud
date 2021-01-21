#!/bin/bash

# Copyright (c) 2020
# Author: Angelo Feraudo
# starting from: https://github.com/osmud/osmud/blob/master/src/openwrt/rollback_ip_fw_rules.sh

# Rollback operations:
# Delete all the rules
# Restore from the last rules state


iptables -F
iptables-restore < rules/iptables.rules

exit 0