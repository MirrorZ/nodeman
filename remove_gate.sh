ifconfig br0 down
ifconfig mesh0 down
brctl delbr br0
iw dev mesh0 del
