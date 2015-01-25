# Sets up a new mesh interface on a supported wlan interface.
# USAGE : # ./setup_gate wlanX meshY meshY_IP FAKE_IP FAKE_ETH
#

#!/bin/bash

# if [ $# -ne  ]; then
# 	echo "Usage : # ./setup_gate wlanX meshY meshY_IP FAKE_IP FAKE_ETH"
# 	exit 1
# fi

#List of the variables required.
WLAN_IF=${1-wlan0}
MESH_IF=${2-mesh0}
MESH_IP=${3-192.168.42.2}
TAP_IP=${4-10.0.0.1}
TAP_ETH=${5-1A-2B-3C-4D-5E-6F}
TAP_NW="${TAP_IP%.*}.0/24"
MESH_NW="${MESH_IP%.*}.0/24"

iw dev $1 interface add $2 type mp
ifconfig $1 down
ifconfig $2 up


iw dev $2 mesh join openmesh
ifconfig $2 $3

MESH_ETH_ADDR=$(cat /sys/class/net/$MESH_IF/address)

echo "Clearing the IP Route Table 0"
ip route flush table 0

#Scrape data for the input mesh interface.
echo "The details are : $MESH_IF -> $MESH_IP ($MESH_NW) -> $MESH_ETH_ADDR. $TAP_IP ($TAP_NW) -> $TAP_ETH."

echo "click node_gatewayselector.click \$MESH_IFNAME=$MESH_IF \$MESH_IP_ADDR=$MESH_IP \$MESH_ETH=$MESH_ETH_ADDR \$MESH_NETWORK=$MESH_NW \$FAKE_IP=$TAP_IP \$FAKE_ETH=$TAP_ETH \$FAKE_NETWORK=$TAP_NW &"

#ip route add default via $FAKE_IP

echo "Done. Opening click script for you : "

#fg
