
//fh :: FromHost(fake0, 10.0.0.1/8)
//th :: ToHost(fake0)

tun :: KernelTap(10.0.0.1/8)
aq :: ARPQuerier(192.168.42.3, wlan0)
ar :: ARPResponder(0/0 1:1:1:1:1:1, 192.168.42.8/32 e0:2a:82:43:5b:e2)
fh_cl :: Classifier(12/0806, 12/0800)
fd_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
fd :: FromDevice(wlan0)
rrs :: RoundRobinSched()


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

tun -> fh_cl;


//ARP request from Host
fh_cl[0] -> ar -> tun;

//fh_cl[1] -> Discard



//IP from Host
fh_cl[1] -> IPPrint(HostIP) 
 	 -> Strip(14)                           // remove crap Ether header
         -> MarkIPHeader(0)
         -> StoreIPAddress(192.168.42.3, 12)          // store real address as source
         -> FixChecksums                         // recalculate checksum
         -> SetIPAddress(192.168.42.1)             // route via gateway
	 //-> IPPrint(IP)
         -> [0]aq
         -> Queue
	 -> [0]rrs;
	
rrs -> ToDevice(wlan0)

//Anything Else
//fh_cl[3] -> Discard;

//Idle -> [1]aq


//From Device to CLassifier
fd -> fd_cl;


// ARP req from device
// ARPResponder to resolve requests for host's IP 
fd_cl[0] -> ARPResponder(192.168.42.3 e0:2a:82:43:5b:e2) -> Queue -> [1]rrs


//ARP response from device
fd_cl[1] -> t :: Tee;
t[0] -> [1]aq;
t[1] -> tun;

//IP from device 
fd_cl[2] -> CheckIPHeader(14)
        // check for responses from the test network
        -> ipc :: IPClassifier(src net 192.168.42.1/24, -)
        // replace the real destination address with the fake address
        -> StoreIPAddress(10.0.0.1, 30)
        -> FixChecksums
	//-> Print(IPDEV)
	//-> IPPrint(sendingTH)
        -> tun

//Forward IP packet not meant for the host
ipc[1] -> Queue -> [2]rrs

//Anything else from device
fd_cl[3] -> tun

