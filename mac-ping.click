//if :: InfiniteSource(DATA \<
  // Ethernet header
 // ff ff ff ff ff ff  e0 2a c0 46 b2 a7  08 01
//>, LIMIT 600000, STOP true)


//if -> Queue -> ToDevice(eth0)


InfiniteSource(DATA \<
  // Ethernet header
  e8 de 27 09 06 20  e0 2a 82 43 5b e2  07 00 11 11 11 11
  // IP header
//  45 00 00 28  00 00 00 00  40 11 77 c3  01 00 00 01  02 00 00 02
  // UDP header
  //13 69 13 69  00 14 d6 41
  // UDP payload
  //55 44 50 20  70 61 63 6b  65 74 21 0a  04 00 00 00  01 00 00 00
  //01 00 00 00  00 00 00 00  00 80 04 08  00 80 04 08  53 53 00 00
  //53 53 00 00  05 00 00 00  00 10 00 00  01 00 00 00  54 53 00 00
  //54 e3 04 08  54 e3 04 08  d8 01 00 00
>, LIMIT 60000, STOP true) 
//->  EtherEncap(0x0800, 00:00:c0:ae:67:ef, e0:2a:c0:46:b2:a7) 
-> Print () 
//-> WifiEncap(0x00, 00:00:00:00:00:00) 
-> ToDevice(wlan0)
