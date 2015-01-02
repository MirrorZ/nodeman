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
	j=0
	packets_lost=0
	while [ $j -lt $ping_count ]
	do
		output=$(ping -c 1 ${i} 2>&1)
		packetloss=$(echo "${output}" | awk '/packet loss/ {print $6} ')
        last_ping_state_0=$(echo $output | grep -i -c 'unreachable');
        last_ping_state_1=$(echo $output | grep -i -c 'unknown');
        #echo output=$output
        last_recorded_state=$(( $(($last_ping_state_0 ^ 1)) & $(($last_ping_state_1 ^ 1)) ))
        if [ $last_recorded_state -eq 0 ]; then
        	packets_lost=$((packets_lost + 1))
        fi
        #echo $last_ping_state_0, $last_ping_state_1, $last_recorded_state
        #echo "-----------"
        j=$((j+1))
	done
	echo "Packetloss : ${packets_lost}/${ping_count}"
        avgrtt=$(echo "${output}" | awk '/rtt/ {split($4,a,/\//);print a[2]}')
	echo "${i}: $avgrtt ms"
		host_unreachable_count=$(echo $output | grep -c 'unreachable');
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
