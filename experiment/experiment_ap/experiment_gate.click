td :: ToDevice(mesh0); 
rrs :: RoundRobinSched()

fd::FromDevice(mesh0, SNIFFER false)
-> cl::Classifier(12/0806 20/0001, 12/0800)
-> Queue
-> ARPResponder(192.168.42.149 c0:4a:00:23:ba:bd)
-> [2]rrs 
//-> Print(X, MAXLENGTH 100)
//->Discard;

cl[1]
-> Print(X, MAXLENGTH 100)
-> Strip(14)
-> CheckIPHeader(0)
-> ipc :: IPClassifier(dst 192.168.42.5, dst 192.168.42.100 or 192.168.42.222, -) 
-> Queue() 
-> EtherEncap(0x0800, c0:4a:00:23:ba:bd, e8:94:f6:26:25:a5) 
-> Print(Y, MAXLENGTH 100)
-> [0]rrs

ipc[1] -> Queue 
-> EtherEncap(0x0800, c0:4a:00:23:ba:bd, c4:6e:1f:11:c1:e9) 
-> Print (Z,MAXLENGTH 100)
-> [1]rrs

rrs->td

ipc[2]->Discard

