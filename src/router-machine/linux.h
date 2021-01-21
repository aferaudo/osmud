/* Copyright 2018 osMUD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _OMS_OPENWRT
#define _OMS_OPENWRT

// IPTABLES FIREWALL
#define IPTABLES_FIREWALL_SCRIPT "router-machine/iptables/create_iptables_fw_rule.sh"
#define IPTABLES_FIREWALL_REMOVE_SCRIPT "router-machine/iptables/remove_all_iptables_fw_rule.sh"

#define IPTABLES_FIREWALL_COMMIT_SCRIPT "router-machine/iptables/commit_iptables_fw_rules.sh"
#define IPTABLES_FIREWALL_ROLLBACK_SCRIPT "router-machine/iptables/rollback_iptables_fw_rules.sh"

//EBPF FIREWALL
#define EBPF_FIREWALL_SCRIPT "router-machine/ebpf/create_ebpf_fw_rule.sh"
#define EBPF_FIREWALL_REMOVE_SCRIPT "router-machine/ebpf/remove_all_ebpf_fw_rule.sh"

#define EBPF_FIREWALL_COMMIT_SCRIPT "router-machine/ebpf/commit_ebpf_fw_rules.sh"
#define EBPF_FIREWALL_ROLLBACK_SCRIPT "router-machine/ebpf/rollback_ebpf_fw_rules.sh"

#define MUD_DB_CREATE_SCRIPT "router-machine/create_mud_db_entry.sh"
#define MUD_DB_REMOVE_SCRIPT "router-machine/remove_mud_db_entry.sh"

#define MUD_STATE_FILE "mudStateFile.txt"

extern char *ebpfPath;

#endif
