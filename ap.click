aq::ARPQuerier(192.168.12.1, ap0)
IPRewriterPatterns(to_world_pat 192.168.42.3 - - -,
		   to_server_pat - - - -);

rrs :: RoundRobinSched()
rw :: IPRewriter(// internal traffic to outside world
		 pattern to_world_pat 0 1,
		 // external traffic redirected to 'intern_server'
		 pattern to_server_pat 1 0);

FromDevice(ap0 ,SNIFFER false) -> cl::Classifier(12/0800, 12/0806 20/0002)
			       -> Strip(14)
				-> MarkIPHeader(0)
				-> IPClassifier(dst 192.168.42.11)	
		//		-> IPPrint(BeforeNAT)		
				-> rw
		//		-> IPPrint(AfterNAT)
				-> EtherEncap(0x0800,c4:6e:1f:11:c1:e9,e8:de:27:09:06:20)
				-> Queue()
				-> rrs

rrs -> td :: ToDevice(mesh0);

cl[1] -> [1]aq

FromDevice(mesh0) -> c::Classifier(12/0800, 12/0806 20/0001)
		  -> Strip(14)
		  -> MarkIPHeader(0)
		  -> IPClassifier(dst 192.168.42.3)
		  -> [1]rw[1]
		  -> IPPrint(Received)
		  -> aq
                  -> Print(AfterAQ)     		 
		  -> Queue
		  -> ToDevice(ap0)


c[1] -> ARPResponder(192.168.42.3 192.168.42.4 c4:6e:1f:11:c1:e9) -> Queue -> [1]rrs
