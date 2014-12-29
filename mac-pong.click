/*****************************************************************
0x0700 is our PROTOCOL code. This is embedded in the frame to 
distinguish from other types of packets.

Look into looping through the MAC Addresses received from GATE fetcher.
Hook this script up with the Gate MAC address fetcher.
Multicast using the list of MAC Addresses attained previously.
The nodes will reply with their IP addresses.
Maintain a table with the IP MAC Mapping (Preferable in Hash O(1)).

Currently works for wlan0.
Should be adopted to work on mesh0.

FIXME : Consider adding delay so that routers dont get overrun.
******************************************************************/

AddressInfo(
	MAC_SRC E8-DE-27-09-06-20,
	MAC_DST E0-2A-82-43-5B-E2)

FromDevice(wlan0, SNIFFER false)
-> Print(got)
-> Classifier(12/0700)
-> Queue
-> EtherMirror()
-> StoreIPAddress(192.168.42.5, 14)
-> Strip(14)
-> EtherEncap(0x0701, MAC_SRC, MAC_DST)
-> Print()
-> ToDevice(wlan0)