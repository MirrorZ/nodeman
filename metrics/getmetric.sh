#!/bin/bash

# Need to decide which servers to ping around the world. (Doesn't seem so easy)
# This script prints out:
#	avg-latency
#	upload-speed
#	download-speed
# These 3 values could be piped to a file and nodeman can use that. (better)

tcpping_PATH=~/tcpping/tcpping

servers_to_ping=(
	www.google.com 
	www.yahoo.com
	www.nytimes.com
	)

total=0
count=0
#-----------------------------Latency-----------------------------

#This is a sequential ping to the servers.

for i in ${servers_to_ping[*]}
do
	# Using tcpping
	output=$($tcpping_PATH -x 1 ${i})
	
	# Using ping
	#output=$(ping -c 1 ${i})
	
	#echo $output
	#echo "------------------------------------"
	
	if [ "$output" == 'seq 0: no response (timeout)' ]; then
		echo ${i} "(timeout)"
		continue
	fi	

	# Using tcpping
	value=$(echo $output | awk '{print $9}')
	
	# Using ping
	#value=$(echo $output | awk -F '/' '{print $5}')
	
	echo ${i} $value
	#echo "------------------------------------"
	
	total=$(bc <<< "scale=3;$total+$value;")
	count=$((count+1))
done

echo "------"
echo $(bc <<< "scale = 3; $total/$count")

#-------------------------------BW-------------------------------

output=$(speedtest-cli --simple)
#echo $output

#upload
echo $output | awk '{print $8 " " $9}'
#download
echo $output | awk '{print $5 " " $6}'

exit
