#ifndef CLICK_GATE_DATA_HH
#define CLICK_GATE_DATA_HH
#include <click/element.hh>
#include <click/string.hh>
CLICK_DECLS

/*
 * =c
 * GateData([TAG] [, KEYWORDS])
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

class GateData : public Element {

  String _label;

 public:

  GateData();
  ~GateData();

  const char *class_name() const		{ return "GateData"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return AGNOSTIC; }

  int configure(Vector<String> &, ErrorHandler *);

  Packet *simple_action(Packet *);

  bool _print_anno;
  bool _print_checksum;
  bool _timestamp;
  
};

CLICK_ENDDECLS
#endif
