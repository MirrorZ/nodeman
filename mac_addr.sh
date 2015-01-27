output=$(ping -c 5 192.168.42.129)
packet_recv=$(echo "${output}" | awk '/0 received/ {print 0}');
if [ -z $packet_recv ]; then
	mac_list=$(arp)
	mac_addr=$(echo "${mac_list}" | awk '/192.168.42.129/ {print $3} ')
	echo "${mac_addr}"
	ebtables -t nat -A PREROUTING -p arp --arp-opcode Request --arp-mac-src ${mac_addr} -j arpreply --arpreply-mac MAC
else
	echo "Network Unreachable"
fi


