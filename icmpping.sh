#!/bin/bash

# This script prints out:
#	packet loss
#	avg-latency for every server
#	upload-speed
#	download-speed
#using ping ICMP responses	

servers_to_ping=(www.google.com www.yahoo.com www.nytimes.com)
ping_count=10
#-----------------------------Latency-----------------------------

#This is a sequential ping to the servers.

for i in ${servers_to_ping[*]}
do
	output=$(ping -c $ping_count ${i})	
        packetloss=$(echo "${output}" | awk '/packet loss/ {print $6} ')
	echo "Packetloss : ${packetloss}"
        avgrtt=$(echo "${output}" | awk '/rtt/ {split($4,a,/\//);print a[2]}')
	echo "${i}: $avgrtt ms"
done

#-------------------------------BW-------------------------------

output=$(speedtest-cli --simple)

#upload
echo $output | awk '{print $8 " " $9}'
#download
echo $output | awk '{print $5 " " $6}'
 
exit
