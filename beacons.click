winfo :: WirelessInfo(SSID "", BSSID 00:00:00:00:00:00, CHANNEL 1);
rates :: AvailableRates(DEFAULT 2 4 11 22);

from_dev :: FromDevice(mesh0, PROMISC true)
-> prism2_decap :: Prism2Decap()
-> extra_decap :: ExtraDecap()
-> FilterPhyErr()
-> tx_filter :: FilterTX()
-> HostEtherFilter(00-18-F3-81-1A-B5, OFFSET 4)
-> dupe :: WifiDupeFilter()
-> wep_decap :: WepDecap()
-> wifi_cl :: Classifier(0/00%0c, 0/08%0c);

// management
wifi_cl [0] -> management_cl :: Classifier(0/00%f0, //assoc req
					   0/10%f0, //assoc resp
					   0/80%f0, //beacon
					   );
wifi_cl[1] -> Discard;
	
management_cl [0] -> PrintWifi() -> Discard;
management_cl [1] -> PrintWifi() -> Discard;
management_cl [2] -> beacon_t :: Tee(2) 
-> bs :: BeaconScanner(RT rates, WIRELESS_INFO winfo) ->  Discard;
beacon_t [1] -> tracker :: BeaconTracker(WIRELESS_INFO winfo, TRACK 10) -> PrintWifi(beacon) -> Discard;
