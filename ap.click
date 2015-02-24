FromDevice(ap0) -> rw::IPRewriter(192.168.42.3 - - -)
		-> Print(Sending)
		-> aq::ARPQuerier(192.168.42.4, c4:6e:1f:11:c1:e9)
		-> ToDevice(mesh0);

FromDevice(mesh0) -> Classifier(12/0800)
		  -> Strip(14)
		  -> MarkIPHeader(0)
		  -> IPClassifier(dst 192.168.42.4)
		  -> [0]rw
		  -> Print(Received)
		  -> Discard;
