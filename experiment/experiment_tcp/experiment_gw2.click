/*
 *			              IP: 192.168.42.148
 *			             MAC: e8:de:27:09:06:20  
 *					|        |
 *			          ------| Gate 1 |-----------
 *			         |      |        |          |        |         |
 *		|	 |-------                           ---------|  Server |
 *		| Client |-------                           ---------|         |
 *		|	 |       |                          |
 *	   IP: 192.168.42.100	 -------|        |-----------    IP: 192.168.42.5
 *	  MAC: c4:6e:1f:11:c1:e9	| Gate 2 |              MAC: e8:94:f6:26:25:a5
 *					|        |
 *			           IP: 192.168.42.149
 *			          MAC: c0:4a:00:23:ba:bd 
 *
 *
 *
 *
 */


AddressInfo(
	GW1_IP 192.168.42.149,
	GW2_IP 192.168.42.149,
	GW1_MAC C0-4A-00-23-BA-BD,
//	GW2_MAC E8-DE-27-09-06-20,
	GW2_MAC C0-4A-00-23-BA-BD, 
//	GW1_MAC E8-DE-27-09-06-20,
	REAL_IP 192.168.42.100,
	REAL_NETWORK 192.168.42.1/24,
	SERVER_IP 192.168.42.5,
	REAL_MAC C4-6E-1F-11-C1-E9,
	FAKE_IP 10.0.0.1,
	FAKE_MAC 1A-2B-3C-4D-5E-6F,
	FAKE_NETWORK 10.0.0.1/8)

/*  
 * tap    - Traffic from kernel tap
 * ar     - Responds to ARP requests from the kernel with a fake MAC	
 * fh_cl  - Classify traffic from the host as ARP and IP	
 * fd_cl  - Classify traffic from device as ARP request, ARP response and IP	
 * fd     - Specify the interface on which traffic is to be captured
 */

tap	:: KernelTap(FAKE_NETWORK, ETHER FAKE_MAC)
ar 	:: ARPResponder(0/0 1:1:1:1:1:1);
fh_cl 	:: Classifier(12/0806, 12/0800)
fd_cl 	:: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
fd 	:: FromDevice(mesh0, SNIFFER false)
rrs 	:: RoundRobinSched()
rrs1 	:: RoundRobinSched()

/* fix the IP checksum, and any embedded checksums that include data
 * from the IP header (TCP and UDP in particular)
 */

elementclass FixChecksums {
    	input 	-> SetIPChecksum
        	-> ipc  :: IPClassifier(tcp, udp, -)
        	-> SetTCPChecksum
        	-> output;
    
	ipc[1] 	-> SetUDPChecksum -> output;

   	ipc[2] 	-> output
}

/* All the traffic from the host is classified 
 */
tap -> fh_cl; 

/* ARP requests from host are supplied with fake ARP responses 
 */
fh_cl[0]   -> ar
	   -> tap;

/* IP packets received from host are classified with respect to the 
 * dst IP. Packets destined for the server are routed via Gate1 or Gate2
 * depending upon it's source port, even src port packets via Gate2 
 * and odd via Gate1
 */

fh_cl[1]    -> Strip(14)                           		// Remove Fake Ether header appended by the host
            -> MarkIPHeader(0)
            -> StoreIPAddress(REAL_IP, 12)			// Store real address as source (Host's IP address)
            -> FixChecksums                       		// Recalculate checksum
	    -> gs :: IPClassifier(dst SERVER_IP, -) 

gs[0]  	    -> portclassifier :: IPClassifier(src port & 1 == 1, -)
  	    -> SetIPAddress(GW1_IP)                              // Route via Gate1 by setting it's annotation
	    -> Queue
	    -> EtherEncap(0x0800, REAL_MAC, GW1_MAC)
	    -> [0]rrs1

portclassifier[1] -> SetIPAddress(GW2_IP)			// Route via Gate2 by setting it's annotation
		  -> Queue
		  -> EtherEncap(0x0800, REAL_MAC, GW2_MAC)
		  -> [1]rrs1


gs[1]    -> Discard;

rrs1     -> pt::PullTee 
         -> Discard

pt[1]	 -> Queue 
         -> [0]rrs;

ptx :: PullTee;

rrs      -> ptx[1] 
         -> Queue  
         -> td::ToDevice(mesh0);

ptx[0] -> Discard;

fd -> fd_cl;						//From Device to CLassifier

/* ARP request from device for destined for the host's IP are 
 * responded with it's MAC address
 */
fd_cl[0]  -> ARPResponder(REAL_IP REAL_MAC) 
          -> Queue 
          -> EtherEncap(0x0800, c4:6e:1f:11:c1:e9, c0:4a:00:23:ba:bd)
          -> [1]rrs

fd_cl[1] -> t :: Tee;					//ARP response from device
t[0]     -> tap         

/*
 * IP packets for the host are send to the kernel for processing
 * while those meant for some other node and discarded
 */
fd_cl[2]  -> CheckIPHeader(14)        
	  -> ipc :: IPClassifier(dst REAL_IP, -)
          -> StoreIPAddress(FAKE_IP, 30)
          -> FixChecksums
	  -> Strip(14)
	  -> EtherEncap(0x0800, REAL_MAC, FAKE_MAC)
          -> tap         

ipc[1] -> Discard;					//Discard IP packet not meant for the host

fd_cl[3] -> tap         				//Any other traffic from device is sent to kernel for processing

