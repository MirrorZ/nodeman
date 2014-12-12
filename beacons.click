winfo :: WirelessInfo(SSID "", BSSID 00:00:00:00:00:00, CHANNEL 1);
rates :: AvailableRates(DEFAULT 2 4 11 22);

from_dev :: FromDevice(mon0, PROMISC true)
//-> RadiotapDecap()
//-> extra_decap :: ExtraDecap()
-> FilterPhyErr()
-> tx_filter :: FilterTX()
//-> HostEtherFilter(E0-2A-82-43-5B-E2, OFFSET 4)
-> dupe :: WifiDupeFilter()
//-> wep_decap :: WepDecap()
-> wifi_cl :: Classifier(0/00%0c, 0/08%0c);  // management and data 

// management
wifi_cl [0] -> management_cl :: Classifier(0/00%f0, //assoc req
					   0/10%f0, //assoc resp
					   0/80%f0, //beacon
					   );
wifi_cl[1] -> Discard;
	
management_cl [0] -> PrintWifi(AssocReq) -> Discard;
management_cl [1] -> PrintWifi(AssocRes) -> Discard;
management_cl [2] -> bs :: BeaconScanner(RT rates, WIRELESS_INFO winfo) -> Print(MAXLENGTH 200) -> Discard;
