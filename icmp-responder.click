/*

Click app to respond to peers sending ICMP echo requests to our device (eth0)
Works and responds with ICMP ECHO REPLY messages to the requesting peers.

This does not let the kernel process any packets while running and handles it in userspace 
instead of the kernel handling it.
*/


scheduler :: RoundRobinSched();
FromDevice(eth0, SNIFFER false) -> pingfilter :: Classifier(12/0800, 12/0806 20/0001, -);

//IP Packet found along with ethernet frame.
//ping filter[0] ICMP ECHO REQUEST [1] ARP Request [2] Otherwise

pingfilter[0] -> checker :: CheckIPHeader(14, VERBOSE true) -> responder :: ICMPPingResponder() -> EtherMirror() -> Queue -> [0]scheduler; //ToDevice(eth0); 
pingfilter[1] -> ARPResponder(192.168.42.7 eth0) -> Queue -> [1]scheduler; //ToDevice(eth0);
pingfilter[2] -> Discard;

scheduler -> ToDevice(eth0);

responder[1] -> Print(NONECHO) -> Discard;
checker[1] -> Print(INVALID, MAXLENGTH 200) -> Discard;