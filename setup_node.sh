# Sets up a new mesh interface on a supported wlan interface.
# USAGE : # ./setup_gate wlanX meshY meshY_IP
#

#!/bin/bash

if [ $# -ne 3 ]; then
	echo "Usage : # ./setup_gate wlanX meshY meshY_IP"
	exit 1
fi

echo "Adding interface."

iw dev $1 interface add $2 type mp
ifconfig $1 down
ifconfig $2 up
iw dev $2 mesh join openmesh
ifconfig $2 $3

echo "Done."

