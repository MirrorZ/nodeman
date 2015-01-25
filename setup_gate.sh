#!/bin/bash

# if [ $# -ne 4 ]; then
#     echo "Usage : # ./setup_gate wlanX meshY <other-bridge-interface> <bridge>"
#     exit 1
# fi

WLAN_IF=$1
MESH_IF=$2
OTHER_BR=$3
BR_IF=$4

echo "Setting up the gate."
iw dev $WLAN_IF interface add $MESH_IF type mp

ifconfig $WLAN_IF down
#echo "Putting down $3 and $2"
ifconfig $MESH_IF down
ifconfig $OTHER_BR down

#echo "Creating bridge"
brctl addbr $BR_IF
brctl addif $BR_IF $OTHER_BR $MESH_IF
ifconfig $OTHER_BR up

#echo "Waiting for IP Address assignment on bridge"
dhclient $BR_IF

#echo "Joining mesh <ID> openmesh"
ifconfig $WLAN_IF down
ifconfig $MESH_IF up
iw dev $MESH_IF mesh join openmesh
echo "Done."
