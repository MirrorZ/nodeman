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
	REAL_IP 192.168.42.11,
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
tun :: KernelTap(FAKE_NETWORK, ETHER FAKE_MAC)

//Add host's IP address

aq :: ARPQuerier(REAL_IP, mesh0);
ar :: ARPResponder(0/0 1:1:1:1:1:1);
fh_cl :: Classifier(12/0806, 12/0800)
fd_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, 12/0700, -)
fd :: FromDevice(mesh0, SNIFFER false)
rrs :: RoundRobinSched()
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

tun -> fh_cl; //Print(ComingFromTun) -> fh_cl;

//ARP request from Host
fh_cl[0] -> ar -> tun;

rrs1::RoundRobinSched()

//IP from Host
fh_cl[1] //-> IPPrint(HostIP) 
 	 -> Strip(14)                           // remove crap Ether header
         -> MarkIPHeader(0)
         -> StoreIPAddress(REAL_IP, 12)		// store real address as source (Host's IP address)
         -> FixChecksums                        // recalculate checksum
	 -> gs :: IPClassifier(dst net REAL_NETWORK, -) 
	 -> GetIPAddress(16)
	 //-> IPPrint()
	 -> Queue
	 -> [0]rrs1	

gs[1]	 -> portclassifier :: IPClassifier(src port & 1 == 1, -)
//	 -> Print(Routing1, MAXLENGTH 200)
	 -> SetIPAddress(192.168.42.1)          // route via gateway (Router's address)
	 -> Queue
	 -> [1]rrs1

portclassifier[1] //-> Print(Routing129, MAXLENGTH 200)
		  -> SetIPAddress(192.168.42.129)
		  -> Queue
		  -> [2]rrs1

rrs1 -> pt::PullTee -> Discard

pt[1]	 -> [0]aq
//	 -> Print(AfterARPQ, MAXLENGTH 200)
//	 -> IPPrint() 
	 -> Queue -> [0]rrs;


rrs -> ToDevice(mesh0);
//rrs2 -> pt :: PullTee[1] ->[0]aq -> Queue -> [0]rrs;

//pt[0] -> Discard;

//From Device to CLassifier
fd -> fd_cl;

// ARP req from device
// ARPResponder to resolve requests for host's IP
// Replace it with host's IP address and MAC address  
fd_cl[0] -> ARPResponder(REAL_IP REAL_MAC) -> Queue -> [1]rrs


//ARP response from device
fd_cl[1] -> t :: Tee;
t[0] -> [1]aq;
t[1] -> tun;

//IP from device 
fd_cl[2] -> CheckIPHeader(14)
        // check for responses from the test network
//        -> ipc :: IPClassifier(src net 192.168.42.1/24, -)
	->ipc :: IPClassifier(dst REAL_IP, -)
         // replace the real destination address with the fake address
        -> StoreIPAddress(FAKE_IP, 30)
        -> FixChecksums
//	-> Print(fd_cl2, MAXLENGTH 200)
	-> Strip(14)
	-> EtherEncap(0x0800, REAL_MAC, FAKE_MAC)
        -> tun

//Forward IP packet not meant for the host

ipc[1] -> Discard;

//Broadcasts coming from Gate using mac-ping (Replacement for mon0 as too many packets)
fd_cl[3] -> Print("GateBroadcasted : ") -> Discard;

//Anything else from device
fd_cl[4] -> tun
