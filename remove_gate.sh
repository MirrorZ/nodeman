#!/bin/bash

if [ $# -ne 2 ]; then
     echo "Usage : # ./remove_gate.sh bridge_interface mesh_interface."
     echo "Example : ./remove_gate.sh br0 mesh0"
     exit 1
fi

ifconfig $1 down
ifconfig $2 down
brctl delbr $1
iw dev $2 del
