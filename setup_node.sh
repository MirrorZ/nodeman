# Sets up a new mesh interface on a supported wlan interface.
# USAGE : # ./setup_gate wlanX meshY 
#

#!/bin/bash

if [ $# -ne 2 ]; then
	echo "Usage : # ./setup_gate wlanX meshY"
	exit 1
fi

echo "Adding interface mesh0"

iw dev $1 interface add $2 type mp
ifconfig $1 down
ifconfig $2 up
iw dev $2 mesh join openmesh

echo "Done."

