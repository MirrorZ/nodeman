//0700 : Prototype Type for MAC-PING

AddressInfo(
      MAC_SRC E0-2A-82-43-5B-E2,
      MAC_DST E8-DE-27-09-06-20)


InfiniteSource(DATA \<
  // Ethernet header
  e8:de:27:09:06:20 e0:2a:82:43:5b:e2 07 00 11 11 11 11
>, LIMIT 6000, STOP true) 
-> Print (Ping:)
-> Queue
-> DelayShaper(2) 
-> ToDevice(wlan0)

FromDevice(wlan0)
-> Classifier(12/0701)
-> Print(Pong:)
-> Discard
