#ifndef CLICK_GATEWAY_SELECTOR_HH
#define CLICK_GATEWAY_SELECTOR_HH
#include <click/element.hh>
#include <click/string.hh>
#include <click/timer.hh>

#include <time.h>

#include <set>
#include <vector>
#include <string>

CLICK_DECLS

/*
 * =c
 * GatewaySelector([TAG] [, KEYWORDS])
 * =s debugging
 * =d
 * Assumes input packets are Wifi packets (ie a wifi_pkt struct from
 * wifi.hh). Prints out a description of those packets.
 *
 * Keyword arguments are:
 *
 * =over 8
 *
 * =a
 * Print, Wifi
 */

#define WIFI_FC0_SUBTYPE_ACTION   0xd0

class GatewaySelector : public Element {

public:

    GatewaySelector();
    ~GatewaySelector();

    const char *class_name() const		{ return "GatewaySelector"; }
    const char *port_count() const		{ return "2/2"; }
    const char *processing() const		{ return PUSH; }

    int configure(Vector<String> &, ErrorHandler *);

		int initialize(ErrorHandler *errh);
		void run_timer(Timer *timer);
    void push(int port, Packet *p);

    bool _print_anno;
    bool _print_checksum;
    bool _timestamp;

private:
    String _label;

	struct GateInfo {
			std::string mac_address;
			std::string ip_address;
			time_t timestamp;
			// int metric;
	};

	struct PortCache {
        uint16_t src_port;
        IPAddress gate_ip;
        time_t timestamp;
    }; 
  
  std::vector<GateInfo> gates;
  std::vector<PortCache> port_cache_table;
  
  Timer _master_timer;
 
  std::string interface_mac_address;
		
  void process_pong(Packet *p);
 
  Packet * select_gate(Packet *p);
  IPAddress cache_lookup(uint16_t);
  Packet * set_ip_address(Packet *, IPAddress);
  IPAddress find_gate(uint16_t);
  void cache_update(uint16_t, IPAddress);
};

CLICK_ENDDECLS
#endif
