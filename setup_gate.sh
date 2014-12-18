#!/bin/bash

if [ $# -ne 4 ]; then
    echo "Usage : # ./setup_gate wlanX meshY <other-bridge-interface> <bridge>"
    exit 1
fi

echo "Setting up the gate."
iw dev $1 interface add $2 type mp

#echo "Putting down $3 and $2"
ifconfig $2 down
ifconfig $3 down

#echo "Creating bridge"
brctl addbr $4
brctl addif $4 $3 $2
ifconfig $3 up

#echo "Waiting for IP Address assignment on bridge"
dhcpcd $4

#echo "Joining mesh <ID> openmesh"
ifconfig $1 down
ifconfig $2 up
iw dev $2 mesh join openmesh
echo "Done."
