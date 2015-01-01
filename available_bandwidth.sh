
#Gets the interface IP Address
#echo $1 
/sbin/ifconfig $1 | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}'

INTERVAL="1"  # update interval in seconds
 

IF=$1
 
while true
do
        R1=`cat /sys/class/net/$1/statistics/rx_bytes`
        sleep $INTERVAL
        R2=`cat /sys/class/net/$1/statistics/rx_bytes`
        RBPS=`expr $R2 - $R1`
        RKBPS=`expr $RBPS / 1024`
        echo "Current bandwidth usage: $RKBPS kB/s"
done
