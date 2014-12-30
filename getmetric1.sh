#!/bin/bash

# Need to decide which servers to ping around the world. (Doesn't seem so easy)
# This script prints out:
#	avg-latency
#	upload-speed
#	download-speed
# These 3 values could be piped to a file and nodeman can use that. (better)

tcpping_PATH=/usr/bin/tcpping

servers_to_ping=(www.google.com www.yahoo.com www.nytimes.com)

total=0
count=0
packetloss=0
ping_count=10
#-----------------------------Latency-----------------------------

#This is a sequential ping to the servers.

for i in ${servers_to_ping[*]}
do
	# Using tcpping
	totrtt=0

	for j in `seq 1 $ping_count`
	do
		output=$($tcpping_PATH -x 1 ${i})
		if echo "$output" | grep "(timeout)" >/dev/null 2>&1; then
			echo "PacketLoss"
			packetloss=$((packetloss+1))
			continue;
		fi
		value=$(echo $output | awk '{print $9}')				
		totrtt=$(bc <<< "scale=3; $totrtt + $value;")
	done
	
	avgrtt=$(bc <<< "scale = 3;$totrtt/$ping_count")
	echo ${i} ${avgrtt}


	total=$(bc <<< "scale=3;$total+$avgrtt")
	count=$((count+1))
done
echo "------"

#Take care of Divide by Zero error
if [ $count -ne 0 ]; then
	#PacketLoss
	#echo $(bc <<< "scale = 3;($packetloss*100)/($count*$ping_count)") #Error
	echo $(bc <<< "scale = 3; $total/$count")
fi

#--------------------------------------------------BW---------------------------------------------------
output=$(speedtest-cli --simple)
#echo $output

#upload
echo $output | awk '{print $8 " " $9}'
#download
echo $output | awk '{print $5 " " $6}'

exit


