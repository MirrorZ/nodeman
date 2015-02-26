# Sets up a new mesh interface on a supported wlan interface.
# USAGE : # ./setup_gate wlanX meshY meshY_IP FAKE_IP FAKE_ETH
#

#!/bin/bash

 if [ $# -lt 1 ]; then
 	echo "Usage : ./setup_node [<WLAN_IF> <MESH_IF> <MESH_IP> <TAP_IP> <TAP_ETH>]"
	echo "Usually, you only need the first three arguments."
	echo "Example : # ./setup_node wlan1 mesh0 192.168.42.55"
 	exit 1
 fi

#List of the variables required.
WLAN_IF=${1-wlan2}
MESH_IF=${2-mesh0}
MESH_IP=${3-192.168.42.11}
TAP_IP=${4-10.0.0.1}
TAP_ETH=${5-1A-2B-3C-4D-5E-6F}
TAP_NW="${TAP_IP}/24"
MESH_NW="${MESH_IP%.*}.0/24"
AP_IP=192.168.42.3

iw dev $WLAN_IF interface add $MESH_IF type mp
ifconfig $WLAN_IF down
ifconfig $MESH_IF up

iw dev $MESH_IF mesh join openmesh
ifconfig $MESH_IF $MESH_IP

sleep 5

MESH_ETH_ADDR=$(cat /sys/class/net/$MESH_IF/address)

echo -n "Clearing the IP Route Table 0"
#ip route flush table 0

#Scrape data for the input mesh interface.
echo -e "The details are : $MESH_IF -> $MESH_IP ($MESH_NW) -> $MESH_ETH_ADDR. $TAP_IP ($TAP_NW) -> $TAP_ETH."

echo -e "Running node_gatewayselector.click. Don't forget to set the default route!"

echo -e "click node_gatewayselector.click MESH_IFNAME=$MESH_IF MESH_IP_ADDR=$MESH_IP MESH_ETH=$MESH_ETH_ADDR MESH_NETWORK=$MESH_NW FAKE_IP=$TAP_IP FAKE_ETH=$TAP_ETH FAKE_NETWORK=$TAP_NW"

click ap_gw.click\
			MESH_IFNAME=$MESH_IF\
			MESH_IP_ADDR=$MESH_IP\
			MESH_ETH=$MESH_ETH_ADDR\
			MESH_NETWORK=$MESH_NW\
			FAKE_IP=$TAP_IP\
			FAKE_ETH=$TAP_ETH\
			FAKE_NETWORK=$TAP_NW\
			AP_IP_ADDR=$AP_IP

#ip route add default via $FAKE_IP
#echo -e "Done. Opening click script for you : "
