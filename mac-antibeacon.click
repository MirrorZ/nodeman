/*
This will serve as a replacement for the Broadcasted RANN frames as listening on mon0 seems too intensive.
This script will broadcast on L2 with it's IP address embedded.

In the Ethernet Header, The first six bytes are ff:ff:ff:ff:ff:ff (broadcast)
The next 6 bytes are the sender's MAC Address
The next 2 bytes are the protocol code (0x0701 for now)
The next 4 bytes are the IP Address of the sender. [c0 -> 192, a8 -> 168, 2a -> 42, 05 -> 5]

This can be extended to include metrics when required.

NOTE : The MAC Address as well as the IP should be of the GATE. This GATE refers
to a router or an android phone and NOT THE SYSTEM HOUSING THE BRIDGE. This can also be the FAKE IP.
This script was written to fix the problem of constantly restarting a node because of advertised gates.

Also check out mac-ping.click. It helps you remove a gate from an associated client.
*/

InfiniteSource(DATA \<
  // Ethernet header
  ff:ff:ff:ff:ff:ff e0:2a:82:43:5b:e2 07 01 c0 a8 2a 80
>, LIMIT 1, STOP true) 
-> Print (Ping:)
-> Queue
-> ToDevice(mesh0);


