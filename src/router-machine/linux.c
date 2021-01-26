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


/* Import function prototypes acting as the implementation interface
 * from the osmud manager to a specific physical device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include "../mudparser.h"
#include "../mud_manager.h"
#include "../oms_utils.h"
#include "../oms_messages.h"
#include "../etc/interface_conf_parser.h"
#include "linux.h"

#define BUFSIZE 4096

Interfaces *interfaces = NULL;

char *getProtocolName(const char *protocolNumber)
{
	if (!protocolNumber)
		return "all";

	if (!strcmp(protocolNumber, "all")) {
		return "all";
	} else if (!strcmp(protocolNumber, "1")) {
		return "icmp";
	} else if (!strcmp(protocolNumber, "6")) {
		return "tcp";
	} else if (!strcmp(protocolNumber, "17")) {
		return "udp";
	} else {
		return "none";
	}
}

char *getActionString(const char *mudAction)
{
	if (!strcmpi(mudAction, "reject")) {
		return "REJECT";
	} else if (!strcmpi(mudAction, "accept")) {
		return "ACCEPT";
	} else {
		return "DROP";
	}
}

char *getProtocolFamily(const char *aclType)
{
	if (!aclType)
		return "all";
	if (!strcmpi(aclType, "all")) {
		return "all";
	} else if (!strcmpi(aclType, "ipv6-acl")) {
		return "ipv6";
	} else {
		return "ipv4";
	}
}

char *getPortRangeFixed(char *portRange)
{
	return strstr(portRange,"(null)") != NULL ? "any" : portRange;
	
}

/*
 * This uses the blocking call system() to run a shell script. This is for testing only
 */
int installFirewallIPRule(char *srcIp, char *destIp, char *port, char *srcDevice, 
			char *destDevice, char *protocol, char *packetRate, char *byteRate, char *ruleName, 
			char *fwAction, char *aclType, char *hostname)
{
	char execBuf[BUFSIZE];
	int retval;

	// The following parameter will be changed based on the direction: 
	// WAN -> LAN : src_port = port; dest_port = 'any'
	// LAN -> WAN : src_port = any; dest_port = port
	char *src_port, *dest_port;
	if(strcmp(LAN_DEVICE_NAME,srcDevice) == 0){
		src_port = "any";
		dest_port = getPortRangeFixed(port);
	}else{
		src_port = getPortRangeFixed(port);
		dest_port = "any";
	}
	
	if (ebpfPath) 
	{
		// Check config file only if not previously checked	
		// TODO use interfaces in general case
		if(!interfaces)
			// osmudConfigFile contains the path to the config file containing the internal an external conf
			interfaces = get_interfaces(osmudConfigFile);
		
		sprintf(execBuf, "%s -s %s -d %s -i %s -a %s -e %s -j %s -b %s -p %s -n %s -t %s -f %s -c %s -r \"%s\" -m \"%s\"", 
				EBPF_FIREWALL_SCRIPT, srcDevice, 
				destDevice, srcIp, src_port, ebpfPath, destIp, dest_port,
				getProtocolName(protocol), ruleName, 
				getActionString(fwAction), getProtocolFamily(aclType),
				hostname, packetRate, byteRate);
		execBuf[BUFSIZE-1] = '\0';
		retval = system(execBuf);
		logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);

	}
	else {
		// By default the firewall used is Netfilter
		sprintf(execBuf, "%s -s %s -d %s -i %s -a %s -j %s -b %s -p %s -n %s -t %s -f %s -c %s -r \"%s\" -m \"%s\"", 
				IPTABLES_FIREWALL_SCRIPT, srcDevice, 
				destDevice, srcIp, src_port, destIp, dest_port,
				getProtocolName(protocol), ruleName, 
				getActionString(fwAction), getProtocolFamily(aclType),
				hostname, packetRate, byteRate);
		execBuf[BUFSIZE-1] = '\0';
		retval = system(execBuf);

		logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);
	}
	if (retval) {
		logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
	}

	return retval;
}

int removeFirewallIPRule(char *ipAddr, char *macAddress){
	// TODO: implement removing by macAddress

	char execBuf[1024];
	int retval;
	if (ebpfPath) 
	{
		// Check config file only if not previously checked	
		// TODO Check interface in general case (Maybe they are not necessary)
		// if(!interfaces)
		// 	// osmudConfigFile contains the path to the config file containing the internal an external conf
		// 	interfaces = get_interfaces(osmudConfigFile);
		
		sprintf(execBuf,"%s -i %s -e %s", EBPF_FIREWALL_REMOVE_SCRIPT, ipAddr, ebpfPath);
		execBuf[BUFSIZE-1] = '\0';
		retval = system(execBuf);
	}
	else {

		sprintf(execBuf,"%s -i %s", IPTABLES_FIREWALL_REMOVE_SCRIPT, ipAddr);
		execBuf[BUFSIZE-1] = '\0';

		retval = system(execBuf);
	}

	// TODO: to remove
	logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);

	if (retval) {
		logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
	}

	return retval;
}


// TODO: Both of these need to be threadsafe with regard to read/write operations on the dnsFileName
// Appends a DNS entry to the DNS whitelist
int installDnsRule(char *targetDomainName, char *srcIpAddr, char *srcMacAddr, char *srcHostName, char *dnsFileNameWithPath)
{
	FILE *fp= NULL;
        int retval = 0;
	fp = fopen (dnsFileNameWithPath, "a");
	logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, "dnsFileNameWithPath");

	if (fp != NULL)
	{
		fprintf(fp, "%s %s %s %s\n", targetDomainName, srcHostName, srcIpAddr, srcMacAddr);
		logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, "installDNSRule writing in the file");
		fflush(fp);
		fclose(fp);
	}
	else
	{
			logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, "installDNSRule not writing in the file");
            logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "Could not write DNS rule to file.");
            retval = 1;
	}

	return retval;
}

// Removes a DNS entry from the DNS whitelist
int removeDnsRule(char *targetDomainName, char *srcIpAddr, char *srcMacAddr, char *dnsFileNameWithPath)
{
	logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, "RemoveDnsRule method has been called");
	return 0;
}

int verifyCmsSignature(char *mudFileLocation, char *mudSigFileLocation)
{
	/* openssl cms -verify -in mudfile.p7s -inform DER -content badtxt */

	char execBuf[BUFSIZE];
	int retval, sigStatus;

	snprintf(execBuf, BUFSIZE, "openssl cms -verify -in %s -inform DER -content %s", mudSigFileLocation, mudFileLocation);
	execBuf[BUFSIZE-1] = '\0';

	logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);
	retval = system(execBuf);

	/* A non-zero return value indicates the signature on the mud file was invalid */
	if (retval) {
		logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
		sigStatus = INVALID_MUD_FILE_SIG;
	}
	else {
		sigStatus = VALID_MUD_FILE_SIG;
	}

	return sigStatus;

}

int commitAndApplyFirewallRules(){
	int retval;

	
	if(ebpfPath){
		logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, EBPF_FIREWALL_COMMIT_SCRIPT);
		retval = system(EBPF_FIREWALL_COMMIT_SCRIPT);
	}else{
		logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, IPTABLES_FIREWALL_COMMIT_SCRIPT);
		retval = system(IPTABLES_FIREWALL_COMMIT_SCRIPT);
	}
	

	if (retval) {
		logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, IPTABLES_FIREWALL_COMMIT_SCRIPT);
	}
	return retval;
}

int rollbackFirewallConfiguration(){
	int retval;
	if(ebpfPath){
		logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, EBPF_FIREWALL_ROLLBACK_SCRIPT);
		retval = system(EBPF_FIREWALL_ROLLBACK_SCRIPT);

	}else {
		logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, IPTABLES_FIREWALL_ROLLBACK_SCRIPT);
		retval = system(IPTABLES_FIREWALL_ROLLBACK_SCRIPT);
	}

	if (retval) {
		logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, IPTABLES_FIREWALL_ROLLBACK_SCRIPT);
	}
	return retval;
}

// Script used is the same as the one used for openwrt platforms (with some corrections)
int installMudDbDeviceEntry(char *mudDbDir, char *ipAddr, char *macAddress, char *mudUrl, char *mudLocalFile, char *hostName)
{
	char execBuf[BUFSIZE];
	int retval;

	snprintf(execBuf, BUFSIZE, "%s -d %s/%s -i %s -m %s -c %s -u %s -f %s", MUD_DB_CREATE_SCRIPT, mudDbDir, MUD_STATE_FILE, ipAddr,
			macAddress,
			(hostName?hostName:"-"),
			(mudUrl?mudUrl:"-"),
			(mudLocalFile?mudLocalFile:"-"));
	execBuf[BUFSIZE-1] = '\0';

	logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);
	retval = system(execBuf);

	if (retval) {
		logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
	}
	return retval;
}


// Script used is the same as the one used for openwrt platforms
int removeMudDbDeviceEntry(char *mudDbDir, char *ipAddr, char *macAddress)
{
	char execBuf[BUFSIZE];
	int retval;

	snprintf(execBuf, BUFSIZE, "%s -d %s/%s -i %s -m %s", MUD_DB_REMOVE_SCRIPT, mudDbDir, MUD_STATE_FILE, ipAddr, macAddress);
	execBuf[BUFSIZE-1] = '\0';

	logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);
	retval = system(execBuf);
	/* retval = run_command_with_output_logged(execBuf); */

	if (retval) {
		logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
	}
	return retval;
}

/*
 * Creates the MUD storage location on the device filesystem
 * Return non-zero in the event the creation fails.
 */
int createMudfileStorage(char *mudFileDataLocationInfo)
{
	return mkdir_path(mudFileDataLocationInfo);
}
