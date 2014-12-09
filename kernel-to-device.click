
fh :: FromHost(fake0, 10.0.0.1/8)
th :: ToHost(fake0)
aq :: ARPQuerier(192.168.42.8, wlan0)
ar :: ARPResponder(0/0 1:1:1:1:1:1, 192.168.42.8/32 e0:2a:82:43:5b:e2)
fh_cl :: Classifier(12/0806 , 12/0800, -)
fd_cl :: Classifier(12/0806 20/0002, 12/0800, -)
fd :: FromDevice(wlan0)


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


fh -> Print(FromHost) -> fh_cl;


//ARP request from Host
fh_cl[0] -> Print(HostARPReq) -> ar -> Print(HostARPReqafterAR) -> th;

//IP from Host
fh_cl[1] -> Print(HostIP) 
 	 -> Strip(14)                           // remove crap Ether header
         -> MarkIPHeader(0)
         -> StoreIPAddress(192.168.42.8, 12)          // store real address as source
         -> FixChecksums                         // recalculate checksum
         -> SetIPAddress(192.168.42.1)             // route via gateway
         -> Print(BeforeARPQuerierinIP)
         -> [0]aq
         -> Print(AfterARPQinIP)
         -> Queue
         -> td :: ToDevice(wlan0)

//Anything Else
fh_cl[2] -> Print(HostCrap) -> Discard;

//From Device to CLassifier
fd -> fd_cl;


// ARP req from device
//fd_cl[0] -> Print(DevARPResToHost) -> th;


//ARP response from device
fd_cl[0] -> Print(DevARPRes) -> t :: Tee;
t[0] -> [1]aq;
t[1] -> th;

//IP from device 

fd_cl[1] -> Print(DevIP) -> th
fd_cl[2] -> Print(DevCrap) -> th
