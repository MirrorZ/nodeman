td :: ToDevice(mesh0); 
rrs :: RoundRobinSched()

fd::FromDevice(mesh0, SNIFFER false) 
//-> Queue
//-> Print(X, MAXLENGTH 200)
//->Discard;
-> CheckIPHeader(14)
-> ipc :: IPClassifier(dst 192.168.42.5, dst 192.168.42.100, -) 
-> Strip(14) 
-> Queue() 
-> EtherEncap(0x0800, c4:6e:1f:11:c1:e9, e8:94:f6:26:25:a5) 
//-> Print(Y, MAXLENGTH 200)
-> [0]rrs

ipc[1] -> Queue
-> Print(before, MAXLENGTH 200) 
-> EtherEncap(0x0800, e8:94:f6:26:25:a5, c4:6e:1f:11:c1:e9) 
-> Print(after, MAXLENGTH 200) 
-> [1]rrs

rrs->td

ipc[2]->Discard

