require(package "nodemanpkg");

// winfo :: WirelessInfo(SSID "", BSSID 00:00:00:00:00:00, CHANNEL 1);

// InfiniteSource(DATA \<

/*00 00 1a 00 2f 48 00 00  d1 30 1f d6 00 00 00 00
10 02 6c 09 c0 00 d6 01  00 00 d0 00 00 00 ff ff 
ff ff ff ff e8 de 27 09  06 20 e8 de 27 09 06 20 
d0 1f 0d 01 7e 15 01 02  1d a1 b1 c3 4d 5e 6f 2d 
04 00 00 88 13 00 00 99  20 00 00 2a b3 43 18*/


/*00 00 1a 00 2f 48 00 00 5e e0 97 b8 00 00 00 00 
10 02 6c 09 c0 00 d7 01 00 00 d0 00 00 00 ff ff 
ff ff ff ff c0 4a 00 23 ba bd c0 4a 00 23 ba bd 
10 fc 0d 01 7e 15 01 00 1f c0 4a 00 23 ba bd 06 
02 00 00 88 13 00 00 00 00 00 00 4a 54 3e 26*/

00 00 1a 00 2f 48 00 00 9c 99 ab 91 01 00 00 00
10 02 6c 09 c0 00 d6 01 00 00 d0 00 00 00 08 11
96 0c fb 68 28 c6 8e 3e 62 f4 28 c6 8e 3e 62 f4 
90 1b 03 00 1c 02 10 00 00 10 c2 2d f6 ee 5a

//00001a002f480000ca14ca410000000010026c09c000d50100

//00d0000000ffffffffffffe8de27090620e8de27090620601b0d017e1501001fe8de270906204a0100008813000000000000080d7507

//>, LIMIT 1, STOP true)

//-> MarkIPHeader(14) -> wifi_encap :: WifiEncap(0x01, 0:0:0:0:0:0) -> set_rate :: SetTXRate(RATE 2) ->  ExtraEncap()
//[0]RadiotapEncap() -> Print(MAXLENGTH 200)->  Queue -> ToDevice(mesh0);

-> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) 
-> q :: Queue()
-> encap :: WifiEncap(0x00, WIRELESS_INFO winfo)
-> set_power :: SetTXPower(63)
-> set_rate :: SetTXRate(2)
-> Print(BEFORE, MAXLENGTH 200)
-> radiotap_encap :: RadiotapEncap()
-> Print(AFTER, MAXLENGTH 200)
-> to_dev :: ToDevice(wlan0);



winfo :: WirelessInfo(SSID "", BSSID 00:00:00:00:00:00, CHANNEL 1);
rates :: AvailableRates(DEFAULT 2 4 11 22);

//from_dev :: FromDevice(mon0, PROMISC true)
FromDump(/home/sudipto/action1.pcap)
-> SetAnnoByte()
-> Print(BEFORE, MAXLENGTH 200)
-> RadiotapDecap()
-> Print(AFTER, MAXLENGTH 200)
//-> extra_decap :: ExtraDecap()
-> FilterPhyErr()
-> tx_filter :: FilterTX()
//-> HostEtherFilter(E0-2A-82-43-5B-E2, OFFSET 4)
-> dupe :: WifiDupeFilter()
//-> wep_decap :: WepDecap()
-> wifi_cl :: Classifier(0/00%0c, 0/08%0c);  // management and data 

// management
wifi_cl [0] -> management_cl :: Classifier(
					   0/d0%f0, //action
					   //0/00%f0, //assoc req
					   //0/10%f0, //assoc resp
					   0/80%f0, //beacon
					   -
					   );
wifi_cl[1] -> Discard;

// The IEEE 802.11 WLAN management frame will be 24 bytes away always
// The fixed parameters have the category code & mesh action code as 0d(13, MESH) and 0x01(HWMP) resp. at offset 24
// Now the tagged parameters have to be dissected. All root announcement frames we captured had just one tagged parameter, the RANN element.
// Assuming that every HWMP RANN frame will have the RANN element *first*, at offset 26, 0x7e tells that the RANN element is present.
// Once the above 2 conditions become true, at offset 28 will be the RANN Flags, which if 0x01, we found a gate.
// In case the tagged parameters can appear in any order (not RANN first always), unlikely though, we'll have to do the dissecting part in cpp.
management_cl [0] -> Print(ACTION)  -> Classifier(24/0d01)	-> Print(MESH-HWMP) 
				       -> Classifier(26/7e) 	-> Print(RANN-ELEMENT-PRESENT) 
				       -> Classifier(28/01) 	-> Print(RANN-FLAG-SET--GATE) 
				       -> GateData() 		-> Discard;

management_cl [1]  -> Discard;
//management_cl [2] -> bs :: BeaconScanner(RT rates, WIRELESS_INFO winfo) -> Print(MAXLENGTH 200) -> Discard;
management_cl [2] -> Print(Other) -> Discard;

