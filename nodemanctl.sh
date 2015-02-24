#!/bin/bash

# nodemanctl - nodeman control

usage ()
{
	printf "Usage: ./nodemanctl mode-command [options]\n"
	printf "mode-command:\n"
	printf "\tnode [<WLAN_IF> <MESH_IF> <MESH_IP> <TAP_IP> <TAP_ETH>]\n"
	printf "\tgate <WLAN_IF> <MESH_IF> <other-bridge-interface> <bridge>\n"
	exit
}

# Need to add validations 
# valid_IF()
# {
# 	check here
# 	retval=1 or 0
# 	return "$retval"
# }

if [ "$1" != "node" ] && [ "$1" != "gate" ]; then
	usage
else mode="$1"
fi

echo "Mode: $mode"

if [ "$mode" == "node" ]; then
	# Node Mode
#--------------------------------------------		
	if [ ! -z $2 ] #&& valid_IF $2
		then WLAN_IF=$2
	fi
#--------------------------------------------	
	if [ ! -z $3 ]
		then MESH_IF=$3
	fi
#--------------------------------------------	
	if [ ! -z $4 ]
		then MESH_IP=$4
	fi
#--------------------------------------------	
	if [ ! -z $5 ]
		then TAP_IP=$5
	fi
#--------------------------------------------	
	if [ ! -z $6 ]
		then TAP_ETH=$6
	fi
#--------------------------------------------	
	./setup_node.sh $WLAN_IF $MESH_IF $MESH_IP $TAP_IP $TAP_ETH
#--------------------------------------------	
else # Gate Mode
#--------------------------------------------	
	if [ ! -z $2 ] #&& valid_IF $2
		then 
		echo "$2"
		WLAN_IF=$2
	else
		echo -e "WLAN_IF missing for gate"
		usage
	fi
#--------------------------------------------
	if [ ! -z $3 ]
		then MESH_IF=$3
	else
		echo -e "MESH_IF missing for gate"
		usage	
	fi
#--------------------------------------------	
	if [ ! -z $4 ]
		then OTHER_BR=$4
	else
		echo -e "<other-bridge-interface> missing for gate"
		usage
	fi
#--------------------------------------------	
	if [ ! -z $5 ]
		then BR_IF=$5
	else
		echo -e "<bridge> missing for gate"
		usage	
	fi
#--------------------------------------------	
	./setup_gate.sh $WLAN_IF $MESH_IF $OTHER_BR $BR_IF
fi
