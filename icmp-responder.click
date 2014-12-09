/*

Click app to respond to peers sending ICMP echo requests to our device (eth0)
Works and responds with ICMP ECHO REPLY messages to the requesting peers.

This does not let the kernel process any packets while running and handles it in userspace 
instead of the kernel handling it.
*/

FromDevice(eth0, SNIFFER false) -> pingfilter :: Classifier(12/0800, -); 

//IP Packet found along with ethernet frame.
pingfilter[0] -> checker :: CheckIPHeader(14, VERBOSE true) -> responder :: ICMPPingResponder() -> EtherMirror() -> Queue -> ToDevice(eth0); 

pingfilter[1] -> Print("NON IP") ->  Discard;
responder[1] -> Print(NONECHO) -> Discard;
checker[1] -> Print(INVALID, MAXLENGTH 200) -> Discard;