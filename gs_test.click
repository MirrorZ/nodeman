require(package "nodemanpkg");

winfo :: WirelessInfo(SSID "", BSSID 00:00:00:00:00:00, CHANNEL 1);
rates :: AvailableRates(DEFAULT 2 4 11 22);

//from_dev :: FromDevice(mon0, PROMISC true)
//FromDump(~/clk/single_pong_packet_dump.pcap)
FromDump(~/HWMPseendump.pcap)
-> RadiotapDecap()
-> FilterPhyErr()
-> tx_filter :: FilterTX()
-> dupe :: WifiDupeFilter()
-> input_cl :: Classifier(12/0701, 0/00%0c 0/d0%f0, -); //pong, action and others

gs::GatewaySelector();

input_cl [0] -> Print(PONG) 	-> [0]gs[0] -> Discard;
input_cl [1] -> Print(ACTION)	-> Classifier(24/0d01 26/7e 28/01)	-> Print(GATE-FOUND) -> [1]gs[1] -> Discard;
input_cl [2] -> Print(OTHER)	-> [2]gs[2] -> Discard;
