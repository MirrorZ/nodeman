#ifndef CLICK_GATEWAY_SELECTOR_HH
#define CLICK_GATEWAY_SELECTOR_HH
#include <click/element.hh>
#include <click/string.hh>

#include <set>
#include <map>
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
    const char *port_count() const		{ return "3/3"; }
    const char *processing() const		{ return AGNOSTIC; }

    int configure(Vector<String> &, ErrorHandler *);

    void push(int port, Packet *p);

    bool _print_anno;
    bool _print_checksum;
    bool _timestamp;

private:
    String _label;

    struct GateInfo {
        std::string mac_address;
        std::string ip_address;
        int age;
        // int metric;
    };

    typedef std::map< std::string, struct GateInfo > mapping_table;
    mapping_table resolved_gates, unresolved_gates;

    void process_rann(Packet *p);
    void process_pong(Packet *p);
};

CLICK_ENDDECLS
#endif
