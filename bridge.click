/*
AddressInfo(
	FAKE_NETWORK 10.0.0.1/8,
	FAKE_IP 10.0.0.1,
	BRIDGE_IP 192.168.42.3,
	BRIDGE_MAC ac:72:89:25:05:30,
	BRIDGE_NETWORK 192.168.42.1/24,
	GATEWAY_IP 192.168.42.1
);
*/

elementclass FixChecksums {
    // fix the IP checksum, and any embedded checksums that include data
    // from the IP header (TCP and UDP in particular)
    input -> SetIPChecksum
        -> ipc :: IPClassifier(tcp, udp, -)
        -> SetTCPChecksum
        -> output;
    ipc[1] -> SetUDPChecksum -> output;
    ipc[2] -> output
}

rrs1::RoundRobinSched()

tun::KernelTun(FAKE_NETWORK)
fd_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
rrs::RoundRobinSched()

tun     -> MarkIPHeader(0)
        -> StoreIPAddress($BRIDGE_IP, 12)          // store real address as source
	-> FixChecksums                         // recalculate checksum
        -> gs :: IPClassifier(dst net $BRIDGE_NETWORK,- )
	-> GetIPAddress(16)
	-> Queue
	-> [0]rrs1

tun[1]  -> Queue -> ARPResponder(0/0 01:01:01:01:01:01) -> [2]rrs

gs[1]	-> SetIPAddress($GATEWAY_IP)             // route via gateway
	-> Queue
	//-> Print(here)
	-> [1]rrs1
        
pt::PullTee -> Discard

rrs1 -> pt[1]-> aq::ARPQuerier($BRIDGE_IP, $BRIDGE_MAC)
       // -> Queue
       // -> Print(here)
//	-> Print(AfterARPQ, MAXLENGTH 200)
  //      -> IPPrint()
        -> Queue 
	-> rrs
	-> ToDevice($BRIDGE_IF)

FromDevice($BRIDGE_IF, SNIFFER false) -> fd_cl

// ARP req from device
// ARPResponder to resolve requests for host's IP
// Replace it with host's IP address and MAC address(mesh)
fd_cl[0] -> ARPResponder($BRIDGE_IP $BRIDGE_MAC) -> Queue -> [1]rrs

//ARP response from device
//fd_cl[1] -> t :: Tee;
fd_cl[1] -> [1]aq;
//t[1] -> tun;

//IP from device
fd_cl[2] -> CheckIPHeader(14)
        // check for responses from the test network
	// Packets destined for the host
        -> ipc :: IPClassifier(dst $BRIDGE_IP)
        // replace the real destination address with the fake address
        -> StoreIPAddress(FAKE_IP, 30)
        -> FixChecksums
        -> Strip(14)
        -> tun

//Forward IP packet not meant for the host
//ipc[1] -> Queue -> Print(forwarding)-> Discard

//Anything else from device
//fd_cl[3] -> Print -> tun

