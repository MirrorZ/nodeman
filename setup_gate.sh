#echo "Putting wlan0 down"
#ifconfig wlan0 down

echo "Creating mesh0 mesh point from wlan1"
iw dev wlan1 interface add mesh0 type mp

echo "Putting down eth0 and mesh0"
ifconfig mesh0 down
ifconfig eth0 down

echo "Creating bridge"
brctl addbr br0
brctl addif br0 eth0 mesh0
ifconfig eth0 up

echo "Waiting for IP Address assignment on bridge"
dhcpcd br0

echo "Joining mesh <ID> openmesh"
ifconfig mesh0 up
iw dev mesh0 mesh join openmesh
echo "Done."
