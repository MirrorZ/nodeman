/** For mesh node (Do not make changes) **/

/* Make changes to this AddressInfo element and use it.
   Change REAL_* fields, the FAKE_* doesn't need to be changed usually

   CTRL+F and replace all occurences of eth0(or wlan0) with your own device

   Clear your routing table of all entries, then run this script.

   # ip route flush table 0

   While this script is running, add a route through the fake device using :
   	# ip route add default via FAKE_IP
	like
	# ip route add default via 10.0.0.1

*/

/*
$MESH_IFNAME	Name of the mesh interface
$MESH_IP_ADDR 	IP of the mesh interface
$MESH_NETWORK   Network of the mesh network (Assumed /24)
$MESH_ETH	ETH of the mesh interface 
$FAKE_IP	IP of the Fake Device (KernelTAP)
$FAKE_ETH	ETH of the Fake Device (KernelTAP)
$FAKE_NETWORK   Network of the Fake Device (Assumed /24)
$AP_IP_ADDR     IP of the AP interface
*/

kernel_tap :: KernelTap($FAKE_NETWORK, ETHER $FAKE_ETH)

real_arp_handler :: ARPQuerier($MESH_IP_ADDR, $MESH_ETH);
fake_arp_responder :: ARPResponder(0/0 01:01:01:01:01:01);
self_arp_responder :: ARPResponder($MESH_IP_ADDR $AP_IP_ADDR $MESH_ETH)

fh_cl :: Classifier(12/0806 20/0001, 12/0800, -)
fd_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, 12/0700, 12/0701, -)

fd :: FromDevice($MESH_IFNAME, SNIFFER false)
rrs :: RoundRobinSched()
rrs1::RoundRobinSched()
rrs2 :: RoundRobinSched()

gate_selector :: GatewaySelector()

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


			/**************************** KERNEL ************************************/

//Traffic coming from Kernel
kernel_tap //-> Print(ComingFromK) 
	   -> fh_cl;

//ARP request from Host
fh_cl[0]  -> fake_arp_responder
	  -> kernel_tap;
//IP from Host
fh_cl[1] -> Strip(14)						// remove crap Ether header
         -> MarkIPHeader(0)
	 //-> IPPrint(IPFromK)
         -> StoreIPAddress($MESH_IP_ADDR, src)			// store real address as source (Host's IP address)
         -> FixChecksums                        		// recalculate checksum
	 -> gs :: IPClassifier(dst net $MESH_NETWORK, -)  	// classify local network and external network traffic
	 -> GetIPAddress(16)					// set gateway annotation to dst addr in local network
	 -> Queue(1)
	 -> [0]rrs1
fh_cl[2] -> Discard;

//Sets the gateway to serve the request
gs[1] -> [0]gate_selector[0]
      -> Print(AfterGWS)
      -> Queue 
      -> [2]rrs

gate_selector[1]-> Discard;					// when no gates are present in the network, all the packets are discarded

rrs1 -> pt::PullTee -> Discard

pt[1]	 -> [0]real_arp_handler
	 -> Queue -> [0]rrs;

rrs -> IPPrint(IPToDevice)
    -> ToDevice($MESH_IFNAME);


				/***************************** AP **************************************/

apaq::ARPQuerier(192.168.12.1, ap0)
IPRewriterPatterns(to_world_pat $AP_IP_ADDR - - -,
		   to_server_pat - - - -);
rw :: IPRewriter(// internal traffic to outside world
		 pattern to_world_pat 0 1,
		 // external traffic redirected to 'intern_server'
		 pattern to_server_pat 1 0);

FromDevice(ap0 ,SNIFFER false) -> apcl::Classifier(12/0800, 12/0806 20/0002, 12/0806 20/0001)
			       -> Strip(14)
			       -> MarkIPHeader(0)	
		//	       -> IPPrint(BeforeNAT)		
			       -> rw
		//	       -> IPPrint(AfterNAT)
			       -> Queue		
			       -> [1]rrs1

apcl[1] -> [1]apaq			

apcl[2] -> ARPResponder(192.168.12.1 e8:94:f6:26:25:a6) 
	-> Queue
        -> [1]rrs2 

				/**************************** MESH *************************************/


//From Device to CLassifier
fd -> fd_cl;

// ARP responder for the host   
fd_cl[0] -> self_arp_responder 
	 -> Queue 
	 -> [1]rrs

self_arp_responder[1] ->  Discard;

// ARP response from device sent to ARPQuerier
fd_cl[1] ->  [1]real_arp_handler;

// IP from device 
fd_cl[2]  -> CheckIPHeader(14)
	  -> ipc :: IPClassifier(dst $MESH_IP_ADDR, dst $AP_IP_ADDR, -)// handle packets meant for the host		
          -> StoreIPAddress($FAKE_IP, 30)			// replace dst addr with KernelTap's IP addr
          -> FixChecksums
	  -> Strip(14)
	  -> EtherEncap(0x0800, $MESH_ETH, $FAKE_ETH)		
          -> kernel_tap						// send the traffic meant for the host to the kernel for processing

// IP packets for AP
ipc[1]    -> Strip(14)
	  -> MarkIPHeader(0)
	  -> [1]rw[1]
	  -> IPPrint(Received)
	  -> apaq
          -> Print(AfterAQ)     		 
	  -> Queue
	  -> rrs2

rrs2 -> ToDevice(ap0)

// Drop packets not meant for the host
ipc[2] -> Discard;

// Broadcast coming from the gates using mac-ping
fd_cl[3] -> [1]gate_selector;

// Broadcast coming from the gates using mac-antiping
fd_cl[4] -> [2]gate_selector;

// Anything else from device
fd_cl[5] -> kernel_tap


