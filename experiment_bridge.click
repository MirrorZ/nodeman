
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
fd_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
rrs::RoundRobinSched()

tun     -> MarkIPHeader(0)
        -> StoreIPAddress(192.168.42.195, 12)          // store real address as source
	-> FixChecksums                         // recalculate checksum
        -> gs :: IPClassifier(dst net 192.168.42.1/24,- )
	-> GetIPAddress(16)
	-> Queue
	-> [0]rrs1

tun[1]  -> Queue -> ARPResponder(0/0 01:01:01:01:01:01) -> [2]rrs

gs[1]	-> SetIPAddress(192.168.42.129)             // route via gateway
	-> Queue
	//-> Print(here)
	-> [1]rrs1
        
aq1:: ARPQuerier(192.168.42.195, br0)
pt ::PullTee
pt[0] -> Discard
rrs1 -> pt[1]
	-> aq::ARPQuerier(192.168.42.195, br0)
        -> Queue 
	-> rrs
	-> ToDevice(br0)

FromDevice(br0, SNIFFER false) -> fd_cl

// ARP req from device
// ARPResponder to resolve requests for host's IP
// Replace it with host's IP address and MAC address(mesh)
fd_cl[0] -> ARPResponder(192.168.42.195 192.168.42.1 c0:4a:00:23:ba:bd) -> Queue -> [1]rrs

//ARP response from device
fd_cl[1] -> t :: Tee;
t[0] -> [1]aq;
t[1] -> [1]aq1;
//t[1] -> tun;

//IP from device
fd_cl[2] -> CheckIPHeader(14)
        // check for responses from the test network
	// Packets destined for the host
        -> ipc :: IPClassifier(dst 192.168.42.195,-)
        // replace the real destination address with the fake address
        -> StoreIPAddress(10.0.0.1, 30)
        -> FixChecksums
        -> Strip(14)
        -> tun

//0e:66:9e:05:00:72

/*
ipc[1]-> Strip(14) 
      -> MarkIPHeader(0)
      -> Queue
      //-> StoreIPAddress(192.168.42.129,16)     // Destination
      -> SetIPAddress(192.168.42.129)
      -> EtherEncap(0x0800, c0:4a:00:23:ba:bd, 0e:66:9e:05:00:72)
      -> Print(1->129)
      -> [3]rrs
*/ 

//Forward IP packet not meant for the host
ipc[1] -> Queue 
       //-> Print(forwarding)
       -> Strip(14)
       //-> EtherEncap(0x0800, c0:4a:00:23:ba:bd, 4a:33:d2:07:28:f6)
       //-> Queue
       -> MarkIPHeader(0)
       -> pt1 :: PullTee
       -> Discard

       pt1[1]
       -> SetIPAddress(192.168.42.129)
       -> aq1
       -> Print
       -> Queue
      // -> Print(1->129)
       -> [3]rrs


//Anything else from device
//fd_cl[3] -> Print -> tun

