output=$(ping -c 5 192.168.42.129)
packet_recv=$(echo "${output}" | awk '/0 received/ {print 0}');
if [ -z $packet_recv ]; then
	mac_list=$(arp)
	mac_addr=$(echo "${mac_list}" | awk '/192.168.42.129/ {print $3} ')
	echo "${mac_addr}"
	usb_ifconfig=$(ifconfig usb0)
	usb_mac_addr=$(echo "${usb_ifconfig}" | awk '/HWaddr/ {print $5} ')	
	echo ${usb_mac_addr}
	ebtables -t nat -P PREROUTING DROP
	ebtables -t nat -A PREROUTING -p arp --arp-opcode Request --arp-mac-src ${mac_addr} -j arpreply --arpreply-mac ${usb_mac_addr}
else
	echo "Network Unreachable"
fi


