#!/bin/bash

# Rollback operations:
# Delete all the rules
# Restore from the last rules state

iptables -F
iptables-restore < iptables_rules/iptables.rules