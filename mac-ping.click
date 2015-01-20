/*
This will serve as a replacement for the Broadcasted RANN frames as listening on mon0 seems too intensive.
This script will broadcast on L2 with it's IP address embedded.

In the Ethernet Header, The first six bytes are ff:ff:ff:ff:ff:ff (broadcast)
The next 6 bytes are the sender's MAC Address
The next 2 bytes are the protocol code (0x0700 for now)
The next 4 bytes are the IP Address of the sender. [c0 -> 192, a8 -> 168, 2a -> 42, 05 -> 5]

This can be extended to include metrics when required.
*/

InfiniteSource(DATA \<
  // Ethernet header
  ff:ff:ff:ff:ff:ff e0:2a:82:43:5b:e2 07 00 c0 a8 2a 05
>, LIMIT 6000, STOP true) 
-> Print (Ping:)
-> Queue
-> DelayShaper(2) 
-> ToDevice(wlan0);


