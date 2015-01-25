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
AddressInfo(
	REAL_IP 192.168.42.99,
	REAL_NETWORK 192.168.42.1/24,
//	REAL_MAC AC-72-89-25-05-30,
//	REAL_MAC 00-18-F3-81-1A-B5,
//	REAL_MAC E8-94-F6-26-25-A5,
//	REAL_MAC 02-61-67-30-68-59,
//	REAL_MAC C0-4A-00-23-BA-BD,
//	REAL_MAC E8-DE-27-09-06-20,
	REAL_MAC C4-6E-1F-11-C1-E9,
	FAKE_IP 10.0.0.1,
	FAKE_MAC 1A-2B-3C-4D-5E-6F,
	FAKE_NETWORK 10.0.0.1/8)

// Takes traffic from kernel through Kernel tap and sends it to eth0

kernel_tap :: KernelTap(FAKE_NETWORK, ETHER FAKE_MAC)

//Add host's IP address

real_arp_handler :: ARPQuerier(REAL_IP, mesh0);
fake_arp_responder :: ARPResponder(0/0 01:01:01:01:01:01);
self_arp_responder :: ARPResponder(REAL_IP REAL_MAC)

fh_cl :: Classifier(12/0806 20/0001, 12/0800, -)
fd_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, 12/0700, -)

fd :: FromDevice(mesh0, SNIFFER false)
rrs :: RoundRobinSched()
gate_selector :: GatewaySelector()

//rrs2 :: RoundRobinSched()

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

kernel_tap -> 
//Print(ComingFromKernel_Tap) ->
fh_cl;

//ARP request from Host
fh_cl[0] //-> Print(ARPRequestFromKernel_Tap)
	 -> fake_arp_responder
	  //  -> Print(FakeARPResponseToKernel_Tap, MAXLENGTH 200)
	  -> kernel_tap;

rrs1::RoundRobinSched()

//IP from Host
fh_cl[1] //-> Print(IPFromHostPING?, MAXLENGTH 98)
 	 -> Strip(14)				// remove crap Ether header
         -> MarkIPHeader(0)
         -> StoreIPAddress(REAL_IP, src)	// store real address as source (Host's IP address)
         -> FixChecksums                        // recalculate checksum

/* 
	The IPClassifier (gs) does not seem to REALLY do something useful. The LOCAL and REMOTE IP Packets are split here. Annotations are set
	in both cases. Then they are combined back using a roundrobin and a pulltee. This seems like unnecessary overhead.
	A possibly better way seems to be that we pass both local and remote into the GatewaySelector (differnet input ports) and then
	let the selector set the appropriate annotation. Once annotations are set, both kinds of packets should be sent out on
	the output[0] which is directly connected to ToDevice(mesh0) element, thereby reducing a lot of unnecessary overhead.	
*/

	 -> gs :: IPClassifier(dst net REAL_NETWORK, -)
	 -> GetIPAddress(16)
	 -> Queue(1)
	 -> [0]rrs1

fh_cl[2] //-> Print(OtherPacketFromHost)
	 -> Discard;

/* gate_selector , for the case that no gates are present on the network. It should push the packets
out of output[1] (currently not implemented) right here which should then be discarded. This will reduce
the packet roaming in the network and then eventually dying as there are no gates. This will hopefully
reduce some unnecessary traffic. Also, this will relieve us of the ugly hack used in gatewayselector.cc
where we return 0.0.0.0 which messes up the arp querier later. So it makes sense to keep it here and
simply discard, after maybe printing a warning.
*/

gs[1] //-> Print("ToGateSelector")
      -> [0]gate_selector[0]
      //-> Print("AfterGateSelector")
      -> Queue -> [1]rrs1
gate_selector[1]
	//-> Print(DiscardedGateSelector)
	-> Discard;

rrs1 -> pt::PullTee -> Discard

/* This case of real_arp_handler can be avoided if gate_selector automatically frames the IP packet into
the correct L2 Frame. This will help in some gain as this element is going away. Since we already have
the correct IP EtH mapping inside the gatewaySelector element, it makes sense to just frame it there
and push it to ToDevice() and not use real_arp_handler
*/

pt[1]	 -> [0]real_arp_handler
//	 -> Print(AfterARPQ, MAXLENGTH 200)
//	 -> IPPrint() 
	 -> Queue -> [0]rrs;

rrs -> ToDevice(mesh0);
//rrs2 -> pt :: PullTee[1] ->[0]real_arp_handler -> Queue -> [0]rrs;
//pt[0] -> Discard;

//From Device to CLassifier
fd -> Print(FromDevice) -> fd_cl;

// ARP req from device
// ARPResponder to resolve requests for host's IP
// Replace it with host's IP address and MAC address  
fd_cl[0] -> self_arp_responder -> Print(ARPRequestForSelf) -> Queue -> [1]rrs
self_arp_responder[1] -> Print(ARPRequestNotForSelf) -> Discard;

//ARP response from device
fd_cl[1] ->  [1]real_arp_handler;

/* It doesn't make sense to send this ARP Response back to the kernel
Because we have already sent back the FAKE MAC (1:1:1:1:1:1) and the arp
table has an entry for that. This results in two entries for the same IP
CONFIRMED and FIXED. REMOVE THIS.
// t[1] -> kernel_tap;
*/

//IP from device 
fd_cl[2] -> Print(IPFromDevice, MAXLENGTH 200) 
	 -> CheckIPHeader(14)
         // check for responses from the test network
	 //        -> ipc :: IPClassifier(src net 192.168.42.1/24, -)
	 ->ipc :: IPClassifier(dst REAL_IP, -)
          // replace the real destination address with the fake address
         -> StoreIPAddress(FAKE_IP, 30)
         -> FixChecksums
	  //	-> Print(fd_cl2, MAXLENGTH 200)
	 -> Strip(14)
	 -> EtherEncap(0x0800, REAL_MAC, FAKE_MAC)
         -> kernel_tap

//Do not Forward IP packets not meant for the host
ipc[1] -> Discard;

//Broadcasts coming from Gate using mac-ping (Replacement for mon0 as too many packets)
fd_cl[3] //-> Print(GoingIntoGateSelector[1])
-> [1]gate_selector;

//Anything else from device
fd_cl[4] // -> Print(GoingToKernelTapDirectly)
	   -> kernel_tap
