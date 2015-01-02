#!/bin/bash

# This script prints out:
#	packet loss
#	avg-latency for every server
#	upload-speed
#	download-speed
#using ping ICMP responses	

servers_to_ping=(www.google.com www.yahoo.com www.nytimes.com)
ping_count=10
last_recorded_state=0
#-----------------------------Latency-----------------------------

#This is a sequential ping to the servers.

for i in ${servers_to_ping[*]}
do
	output=$(ping -c $ping_count ${i})	
        packetloss=$(echo "${output}" | awk '/packet loss/ {print $6} ')
        last_ping_state=$(echo $output | tail -5 | grep -i -c 'unreachable');
        last_recorded_state=$(($last_ping_state ^ 1))
	echo "Packetloss : ${packetloss}"
        avgrtt=$(echo "${output}" | awk '/rtt/ {split($4,a,/\//);print a[2]}')
	echo "${i}: $avgrtt ms"
		host_unreachable_count=$(echo $output | grep -c -i 'unreachable');
	echo "host_unreachable_count: ${host_unreachable_count}"
done

#-------------------------------BW-------------------------------

output=$(speedtest-cli --simple)

#upload
echo $output | awk '{print $8 " " $9}'

#download
echo $output | awk '{print $5 " " $6}'
 
#last recorded network state from ping. 0:down, 1:up
echo $last_recorded_state

exit
