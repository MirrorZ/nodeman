#!/bin/bash

if [ $# -ne 4 ]; then
    echo "Usage : # ./setbridge wlanX meshY <other-bridge-interface> <bridge> meshID"
    exit 1
fi

echo "Setting up the gate."
iw dev $1 interface add $2 type mp

ifconfig $3 down
echo "Creating bridge"
brctl addbr $4
brctl addif $4 $3 $2
ifconfig $3 up

echo "Waiting for IP Address assignment on bridge"
dhclient $4

echo "Joining mesh <ID> openmesh"
ifconfig $2 up
iw dev $2 mesh join $5
echo "Done."

#----------------------------Bridge Setup------------------------
echo "Flushing ip route"
ip route flush table 0
echo "Running bridge.click Script"
click bridge.click  & 
sleep 2
ip route add default via 10.0.0.1
echo "Added default via 10.0.0.1"

#-------------------------------BW-------------------------------
echo "Running speedtest-cli"
output=$(speedtest-cli --simple) 
#upload
upload=$(echo $output | awk '{print $8 " " $9}')
#download
download=$(echo $output | awk '{print $5 " " $6}')

#-----------------------------Refresh-------------------------
echo "Gettng Metrics"
servers_to_ping=(www.google.com www.yahoo.com www.nytimes.com)
ping_count=10
INTERVAL="1"  # update interval in seconds
while true 
do
#--Available-Bandwidth----
	#Gets the interface IP Address
	/sbin/ifconfig $4 | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}'
	IF=$4
        R1=`cat /sys/class/net/$3/statistics/rx_bytes`
    	sleep $INTERVAL
        R2=`cat /sys/class/net/$3/statistics/rx_bytes`
        RBPS=`expr $R2 - $R1`
        RKBPS=`expr $RBPS / 1024`
        echo "Current bandwidth usage: $RKBPS kB/s" 

#---Latency--

#This is a sequential ping to the servers.

	for i in ${servers_to_ping[*]}
	do
		output=$(ping -c $ping_count ${i})	
	        packetloss=$(echo "${output}" | awk '/packet loss/ {print $6} ')
		echo "Packetloss : ${packetloss}"
	        avgrtt=$(echo "${output}" | awk '/rtt/ {split($4,a,/\//);print a[2]}')
		echo "${i}: $avgrtt ms"
		host_unreachable_count=$(echo $output | grep -c -i 'unreachable');
		echo "host_unreachable_count: ${host_unreachable_count}"
	done
	#sleep $INTERVAL
done

exit
