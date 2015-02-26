
rrs1::RoundRobinSched()
rrs::RoundRobinSched()

tun::KernelTun($FAKE_NETWORK)
fd::FromDevice($BRIDGE_IF, SNIFFER false)
fd_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)

aq::ARPQuerier($BRIDGE_IP, $BRIDGE_MAC)

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

		/****************************KERNEL*******************************/


// Traffic coming from Kernel 
tun     -> MarkIPHeader(0)
        -> StoreIPAddress($BRIDGE_IP, 12)          			// store bridge IP as the source address
	-> FixChecksums                         			// recalculate checksum
        -> gs :: IPClassifier(dst net $BRIDGE_NETWORK, -)		
	-> GetIPAddress(16)
	-> Queue
	-> [0]rrs1

//tun[1]  -> Queue -> ARPResponder(0/0 01:01:01:01:01:01) -> [2]rrs

// Traffic for external network
gs[1]	-> SetIPAddress($GATEWAY_IP)             // route via gateway
	-> Queue
	-> [1]rrs1
        
pt::PullTee -> Discard

rrs1    -> pt[1]
	-> aq  
        -> Queue 
	-> rrs
	-> ToDevice($BRIDGE_IF)


				/*****************BRIDGE***********************/

fd -> fd_cl

// ARP Responder for the host
fd_cl[0] -> ARPResponder($BRIDGE_IP $BRIDGE_MAC) 
	 -> Queue 
	 -> [1]rrs

// ARP response from device
fd_cl[1] -> [1]aq;

// IP from device
fd_cl[2] -> CheckIPHeader(14)
         -> ipc :: IPClassifier(dst $BRIDGE_IP)		// Packets destined for the host
         -> StoreIPAddress($FAKE_IP, 30)		// replace the dst addr with the KernelTun address
	 -> FixChecksums
         -> Strip(14)
         -> tun

//Anything else from device
//fd_cl[3] -> Print -> tun

