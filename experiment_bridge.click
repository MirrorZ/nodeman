AddressInfo(
	REAL_IP 192.168.42.36,
	REAL_GATEWAY 192.168.42.129,
	FAKE_GATEWAY 192.168.42.128,
//	REAL_MESH_MAC C0-4A-00-23-BA-BD,
	REAL_GATEWAY_MAC 8e:e0:85:a4:67:02,
//	S4_MAC  8e:e0:85:a4:67:02	
//	REAL_NETWORK 192.168.42.1/24,
//	REAL_MAC AC-72-89-25-05-30,
//	REAL_MAC 00-18-F3-81-1A-B5,
//	REAL_MAC E8-94-F6-26-25-A5,
//	REAL_MAC 02-61-67-30-68-59,
//	REAL_MAC C0-4A-00-23-BA-BD,
	REAL_MESH_MAC E8-DE-27-09-06-20,
	REAL_MAC C4-6E-1F-11-C1-E9,
	FAKE_IP 10.0.0.1,
	FAKE_MAC 1A-2B-3C-4D-5E-6F,
	FAKE_NETWORK 10.0.0.1/8)


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
        -> StoreIPAddress(REAL_IP, 12)          // store real address as source
	-> FixChecksums                         // recalculate checksum
        -> gs :: IPClassifier(dst net 192.168.42.1/24,- )
	-> GetIPAddress(16)
	-> Queue    // fix the IP checksum, and any embedded checksums that include data
    // from the IP header (TCP and UDP in particular)

	-> [0]rrs1

tun[1]  -> Queue -> ARPResponder(0/0 01:01:01:01:01:01) -> [2]rrs

gs[1]	-> SetIPAddress(REAL_GATEWAY)             // route via gateway
	-> Queue
	//-> Print(here)
	-> [1]rrs1
        
aq1 :: ARPQuerier(REAL_IP, br0)
pt ::PullTee
pt[0] -> Discard
rrs1 -> pt[1]
	-> aq::ARPQuerier(REAL_IP, br0)
        -> Queue 
	-> rrs
	-> ToDevice(br0)

FromDevice(br0, SNIFFER false) -> fd_cl

// ARP req from device
// ARPResponder to resolve requests for host's IP
// Replace it with host's IP address and MAC address(mesh)
fd_cl[0] -> ARPResponder(REAL_IP FAKE_GATEWAY REAL_MESH_MAC) -> Queue -> [1]rrs

//ARP response from device
fd_cl[1] -> t :: Tee;
t[0] -> [1]aq;
t[1] -> [1]aq1;
//t[1] -> tun;

//IP from device
fd_cl[2] -> CheckIPHeader(14)
        // check for responses from the test network
	// Packets destined for the host
        -> ipc :: IPClassifier(dst REAL_IP, dst FAKE_GATEWAY, -)
        // replace the real destination address with the fake address
        -> StoreIPAddress(10.0.0.1, 30)
        -> FixChecksums
        -> Strip(14)
        -> tun

//0e:66:9e:05:00:72


ipc[1]-> Strip(14) 
      -> MarkIPHeader(0)
      //-> StoreIPAddress(REAL_GATEWAY,16)     // Destination
      -> StoreIPAddress(REAL_GATEWAY, dst)
      -> FixChecksums
      -> EtherEncap(0x0800, REAL_MESH_MAC, REAL_GATEWAY_MAC)
-> Queue
      -> Print(ReallyMeantForPhone)
      -> [3]rrs 

//Forward IP packet not meant for the host
ipc[2] -> Queue 
       -> Print(forwardingBEFORE, MAXLENGTH 200)
       -> Strip(14)
       //-> EtherEncap(0x0800, REAL_MESH_MAC, 4a:33:d2:07:28:f6)
       //-> Queue
       -> MarkIPHeader(0)
       -> pt1 :: PullTee
       -> Discard

       pt1[1]
        -> SetIPAddress(REAL_GATEWAY)
	-> aq1
	-> Print(forwardingAFTER)
       -> Queue
      // -> Print(1->129)
       -> [4]rrs


//Anything else from device
//fd_cl[3] -> Print -> tun

