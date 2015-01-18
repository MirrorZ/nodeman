#include <click/config.h>
#include <click/ipaddress.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include "gatewayselector.hh"

#include <string>

CLICK_DECLS

//FILE * gate_data_file = fopen("/home/sudipto/clk/gate_data", "w");

//std::map< std::string, struct GateInfo > GatewaySelector::resolved_gates, GatewaySelector::unresolved_gates;

GatewaySelector::GatewaySelector()
    : _print_anno(false),
      _print_checksum(false)
{
    _label = "";
}

GatewaySelector::~GatewaySelector()
{
}

int
GatewaySelector::configure(Vector<String> &conf, ErrorHandler* errh)
{
  int ret;
  _timestamp = false;
  ret = Args(conf, this, errh)
      .read_p("LABEL", _label)
      .read("TIMESTAMP", _timestamp)
      .complete();
  return ret;
}

std::string mac_to_string(uint8_t address[])
{
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
         address[0], address[1], address[2], address[3], address[4], address[5]);
  return std::string(macStr);
}

std::string ip_to_string(uint8_t ip[])
{
	char ipStr[16];
	sprintf(ipStr, "%d.%d.%d.%d\n",ip[0],ip[1],ip[2],ip[3]);
	return std::string(ipStr);
}

/*
  Processes the rann frame and keeps mac addresses in the unresolved_gates map.
*/
void GatewaySelector::process_rann(Packet *p)
{
  uint8_t *ptr;
  uint8_t root_sta_address[6];
  struct GateInfo gate_info;

  struct click_wifi *w = (struct click_wifi *) p->data();
  StringAccum sa;

  // Skip the 24byte Action Frame. struct click_wifi is 24 bytes long.
  ptr = (uint8_t *) (w+1);

  //The IEEE 802.11 WLAN mgmt frame starts
  int category_code = *ptr;
  ptr++;

  sa << " category_code: " << category_code;
  sa << "\n";
  
  int mesh_action_code = *ptr;
  ptr++;

  sa << " mesh_action_code: "<< mesh_action_code;
  sa << "\n";

  // Tagged parameters
  int tag_number = *ptr;
  ptr++;
  
  sa << " tag_number: "<< tag_number;
  sa << "\n";

  int tag_length = *ptr;
  ptr++;

  sa << " tag_length: "<< tag_length;
  sa << "\n";

  int rann_flags = *ptr;
  ptr++;

  sa << " rann_flags: "<< rann_flags;
  sa << "\n";

  //printf("%s\n", sa.c_str());

  // skip HWMP hop count
  ptr++;

  //skip HWMP TTL
  ptr++;

  //fprintf(gate_data_file, "gate: ");

  for(int i=0; i<6; i++)
  {
    root_sta_address[i] = *ptr;
    ptr++;
  }

  gate_info.mac_address = mac_to_string(root_sta_address);

  unresolved_gates[gate_info.mac_address] = gate_info;
	
	mapping_table::iterator it;
	printf("unresolved_gates(%d):\n",unresolved_gates.size());
	for(it = unresolved_gates.begin(); it!=unresolved_gates.end(); ++it) {
		printf("%s\n",(it->first).c_str());
	}

  //fprintf(gate_data_file, "%s\n", s.c_str());

  // skipping the rest: ROOT STA seq number, RANN interval, HWMP metric

}

void GatewaySelector::process_pong(Packet * p)
{
  // process pong here
  // 1. extract mac, ip and metric in pong
  // 2. look for mac as key in unresolved_gates map
  // 3. update the corresponding gate_info structure.
  // 4. Remove the gate_info struct from unresolved and put it in resolved.
	uint8_t dest_mac[6], src_mac[6], ip[4];
	
	uint8_t *ptr = NULL;
	
	if(p->has_mac_header()) {
		ptr = (uint8_t *)p->mac_header();
		
		for(int i=0; i<6; i++) {
			dest_mac[i] = *ptr;
			ptr++;
		}
		
		for(int i=0; i<6; i++) {
			src_mac[i] = *ptr;
			ptr++;
		}

		//skip protocol code
		ptr+=2;
		
		for(int i=0; i<4; i++) {
			ip[i] = *ptr;
			ptr++;
		}
		
		std::string dest_mac_string = mac_to_string(src_mac);
		std::string src_mac_string = mac_to_string(dest_mac);
		std::string ip_string = ip_to_string(ip);
		
		printf("src_mac: %s\ndest_mac: %s\nip: %s\n",
					 dest_mac_string.c_str(),
					 src_mac_string.c_str(),
					 ip_string.c_str()
					);
		
		// Find this gate's entry using its mac address which is the source mac address
		mapping_table::iterator it = unresolved_gates.find(src_mac_string);
		
		if(it != unresolved_gates.end()) {
			struct GateInfo this_gate = it->second;
			this_gate.ip_address = ip_string;
			// put metrics and other stuff
			
			unresolved_gates.erase(it);
			resolved_gates[this_gate.mac_address] = this_gate;
		}
		
		printf("resolved_gates(%d):\n",resolved_gates.size());
		for(it = resolved_gates.begin(); it!=resolved_gates.end(); ++it) {
			printf("%s\n",(it->first).c_str());
		}
		
		printf("unresolved_gates(%d):\n",unresolved_gates.size());
		for(it = unresolved_gates.begin(); it!=unresolved_gates.end(); ++it) {
			printf("%s\n",(it->first).c_str());
		}
		
	}
	
}


void GatewaySelector::push(int port, Packet *p)
{
  switch(port)
  {
    case 0: /* Pong arrives here */
      process_pong(p);
      output(0).push(p);
      break;
    case 1: /* Rann arrives here */
      process_rann(p);
      output(1).push(p);
      break;
    case 2: /* Normal packets from this node arrive here*/
      // decide gateway for this packet, modify and push it out
      output(2).push(p);
      break;
  }
}


CLICK_ENDDECLS
EXPORT_ELEMENT(GatewaySelector)
