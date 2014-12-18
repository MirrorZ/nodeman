
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

tun::KernelTun(10.0.0.1/8)
fd_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
rrs::RoundRobinSched()

tun     -> MarkIPHeader(0)
        -> StoreIPAddress(192.168.42.4, 12)          // store real address as source
	-> FixChecksums                         // recalculate checksum
        -> gs :: IPClassifier(dst net 192.168.42.1/24,- )
	-> GetIPAddress(16)
	-> Queue
	-> [0]rrs1

tun[1]  -> Print() -> Queue -> ARPResponder(0/0 01:01:01:01:01:01) -> [3]rrs

gs[1]	-> SetIPAddress(192.168.42.129)             // route via gateway
	-> Queue
	//-> Print(here)
	-> [1]rrs1
        
pt::PullTee -> Discard

rrs1 -> pt[1]-> aq::ARPQuerier(192.168.42.4, br0)
       // -> Queue
       // -> Print(here)
//	-> Print(AfterARPQ, MAXLENGTH 200)
  //      -> IPPrint()
        -> Queue 
	-> rrs
	-> ToDevice(br0)

FromDevice(br0, SNIFFER false) -> fd_cl

// ARP req from device
// ARPResponder to resolve requests for host's IP
// Replace it with host's IP address and MAC address(mesh)
fd_cl[0] -> ARPResponder(192.168.42.4 e8:de:27:09:06:20) -> Queue -> [1]rrs

//ARP response from device
//fd_cl[1] -> t :: Tee;
fd_cl[1] -> [1]aq;
//t[1] -> tun;

//IP from device
fd_cl[2] -> CheckIPHeader(14)
        // check for responses from the test network
	// Packets destined for the host
        -> ipc :: IPClassifier(dst 192.168.42.4,-)
        // replace the real destination address with the fake address
        -> StoreIPAddress(10.0.0.1, 30)
        -> FixChecksums
        -> Strip(14)
        -> tun

//Forward IP packet not meant for the host
ipc[1] -> Queue -> Print(forwarding)->[2]rrs

//Anything else from device
fd_cl[3] -> tun

