#!/bin/bash
# Copyright (c) 2020
# Author: Angelo Feraudo
# starting from: https://github.com/osmud/osmud/blob/master/src/openwrt/commit_ip_fw_rules.sh

# The commit in iptables saves the rules inserted in a file called /etc/iptables.rules


iptables-save > iptables_rules/iptables.rules
exit 0