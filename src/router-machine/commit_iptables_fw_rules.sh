#!/bin/bash

# The commit in iptables saves the rules inserted in a file called /etc/iptables.rules

# TODO: Problems to take into account:
# Should we use the commit also as command executor? Execution of a sh file containing the iptables rules
# Should we restart the firewall after this operation?

iptables-save > iptables_rules/iptables.rules
exit 0