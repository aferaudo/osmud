# This script enable the -a option, which will ask for other mudfile to a local server for which the address is: https://www.mfs.example.com
# This could be used in case of problem with openssl
#!/bin/sh

if [ `ps | grep osmud | wc -l` -gt 1 ];then
	echo "Already exist a process of osmud"
	/etc/init.d/osmud stop
	echo "Not anymore!"
fi

echo "This is a first version that launch osmud always in foreground"
echo "If you wanna see more details read the file /var/log/osmud.log"
echo "-a option activated"

echo "starting osmud"
echo "STDOUT and STDERR are activated!"
osmud -k -x "/var/run/osmud.pid" -e "/var/log/dhcpmasq.txt" -w "/var/state/osmud/dnswhitelist" -b "/var/state/osmud/mudfiles" -l "/var/log/osmud.log" -p -a "https://www.mfs.example.com/" 

