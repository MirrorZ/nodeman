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

#define MAC_PING_TIME_INTERVAL 5 // in seconds
std::string INTERFACE = "wlan0"; // TODO: pass this as a config parameter to the element

//FILE * gate_data_file = fopen("/home/sudipto/clk/gate_data", "w");

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
	sprintf(ipStr, "%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
	return std::string(ipStr);
}

void string_to_mac(std::string mac_string, uint8_t address[])
{
  sscanf(mac_string.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
					(unsigned int *)&address[0], (unsigned int *)&address[1], (unsigned int *)&address[2], 
				  (unsigned int *)&address[3], (unsigned int *)&address[4], (unsigned int *)&address[5]);
}


GatewaySelector::GatewaySelector()
    : _print_anno(false),
      _print_checksum(false),
      _macping_timer(this)
{
    _label = "";
		std::string path = "/sys/class/net/" + INTERFACE + "/address";
		FILE * fp = fopen(path.c_str(), "r");
		if(fp != NULL) {
			char interface_mac[18];
			if(fscanf(fp, "%s", interface_mac) == 1) {
				interface_mac_address = std::string(interface_mac);
			} else {
				printf("Address init failed. Error reading from %s\n", path.c_str());
			}
			fclose(fp);
		} else {
			printf("Address init failed!\n");
		}
		
		
		//Sample unresolved gate
		struct GateInfo gate_info;
		gate_info.mac_address = "ac:72:89:25:05:30";
		unresolved_gates[gate_info.mac_address] = gate_info;
		
		
		macping_packet = NULL;
}

GatewaySelector::~GatewaySelector()
{
}

int GatewaySelector::initialize(ErrorHandler *)
{
		_macping_timer.initialize(this);
		_macping_timer.schedule_now();
		return 0;
}

void GatewaySelector::run_timer(Timer *timer)
{
		assert(timer == &_macping_timer);
		Timestamp now = Timestamp::now_steady();
		
		mapping_table::iterator it;
		for(it = unresolved_gates.begin(); it != unresolved_gates.end(); ++it) {
			if(macping_packet) macping_packet->kill();
			if(macping_packet = make_macping_packet(it->second)) {
				output(3).push(macping_packet);
				printf("MacPinged gate: %s\n",(it->second).mac_address.c_str());
			} else {
				printf("Invalid macping packet\n");
			}
		}
		_macping_timer.reschedule_after_sec(MAC_PING_TIME_INTERVAL);
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

void GatewaySelector::process_pong(Packet * p)
{
  // process pong here
  // 1. extract mac, ip and metric in pong
  // 2. look for mac as key in unresolved_gates map
  // 3. update the corresponding gate_info structure.
  // 4. Remove the gate_info struct from unresolved and put it in resolved.
	uint8_t src_mac[6], ip[4];
	
	uint8_t *ptr = NULL;
	
	if(p->has_mac_header()) {
		ptr = (uint8_t *)p->mac_header();
		//Skip destination as it should be a broadcast address
		ptr+= 6;
		//Skip to source mac address
		for(int i=0; i<6; i++) {
			src_mac[i] = *ptr;
			ptr++;
		}

		//skip protocol code
		ptr+=2;
		//extract ipv4
		for(int i=0; i<4; i++) {
			ip[i] = *ptr;
			ptr++;
		}
		
		std::string src_mac_string = mac_to_string(dest_mac);
		std::string ip_string = ip_to_string(ip);
		
		printf("----Data from pong------\n");
		printf("src_mac: %s\nnip: %s\n",					
					 src_mac_string.c_str(),
					 ip_string.c_str()
					);
		printf("------------------------\n");
		
		// Find this gate's entry using its mac address which is the source mac address
		mapping_table::iterator it = gates.find(src_mac_string);
		
		if(it != gates.end()) {
		  
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
