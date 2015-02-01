#!/bin/bash

if [ $# -ne 5 ]; then
     echo "Usage : # ./setup_gate wlanX meshY <other-bridge-interface> <bridge> IPv4_gateway"
     exit 1
fi

WLAN_IF=$1
MESH_IF=$2
OTHER_BR=$3
BR_IF=$4
GW_IP=$5
TAP_IP=10.0.0.1
TAP_NW="${TAP_IP}/8"

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

sleep 5
#echo "Waiting for IP Address assignment on bridge"
dhclient $BR_IF

#echo "Joining mesh <ID> openmesh"
ifconfig $WLAN_IF down
ifconfig $MESH_IF up

sleep 2
iw dev $MESH_IF mesh join openmesh
echo "Done joining openmesh."

sleep 2
BR_IP=$(ifconfig $BR_IF | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}')

BR_ETH=$(cat /sys/class/net/$BR_IF/address)

BR_NW="${BR_IP}/24"

ip route flush table 0

echo -e "Running click script now. Don't forget to add a default route!."

echo -e "click bridge.click BRIDGE_IF=$BR_IF BRIDGE_IP=$BR_IP BRIDGE_MAC=$BR_ETH BRIDGE_NETWORK=$BR_NW GATEWAY_IP=$GW_IP FAKE_IP=$TAP_IP FAKE_NETWORK=$TAP_NW"

click bridge.click BRIDGE_IF=$BR_IF\
		   BRIDGE_IP=$BR_IP\
		   BRIDGE_MAC=$BR_ETH\
		   BRIDGE_NETWORK=$BR_NW\
                   GATEWAY_IP=$GW_IP\
		   FAKE_IP=$TAP_IP\
                   FAKE_NETWORK=$TAP_NW
