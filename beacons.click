winfo :: WirelessInfo(SSID "", BSSID 00:00:00:00:00:00, CHANNEL 1);
rates :: AvailableRates(DEFAULT 2 4 11 22);

//from_dev :: FromDevice(mon0, PROMISC true)
FromDump(~/nodeman/dumps/HWMPseendump.pcap)
-> RadiotapDecap()
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
management_cl [0] -> PrintWifi(Action) -> Classifier(24/0d01)	-> Print(MESH-HWMP) 
				       -> Classifier(26/7e) 	-> Print(RANN-ELEMENT-PRESENT) 
				       -> Classifier(28/01) 	-> Print(RANN-FLAG-SET--GATE) -> Discard;

management_cl [1] -> PrintWifi(Beacon) -> Discard;
//management_cl [2] -> bs :: BeaconScanner(RT rates, WIRELESS_INFO winfo) -> Print(MAXLENGTH 200) -> Discard;
management_cl [2] -> Print(Other) -> Discard;
