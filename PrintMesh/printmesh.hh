#ifndef CLICK_PRINTMESH_HH
#define CLICK_PRINTMESH_HH
#include <click/element.hh>
#include <click/string.hh>
CLICK_DECLS

//Can add the following to wifi.h 

//SubType Action
#define WIFI_FC0_SUBTYPE_ACTION   0xd0

//Tag Params
enum {
  WIFI_ELEMID_MESHCONF     	= 113, 
  WIFI_ELEMID_MESHID		= 114,
  WIFI_ELEMID_MESH_PEERING_MGMT = 117,
  WIFI_ELEMID_MESH_PATH_REQ     = 130,
  WIFI_ELEMID_MESH_PATH_REP     = 131,
  WIFI_ELEMID_ROOT_ANNOUNCEMENT = 126,

};

//Capability Info
#define	WIFI_CAPINFO_SHORT_PREAMBLE	0x0020
#define	WIFI_CAPINFO_PBCC		0x0040
#define	WIFI_CAPINFO_CHANNEL_AGILITY	0x0080
#define	WIFI_CAPINFO_SPECTRUM_MGMT	0x0100
#define	WIFI_CAPINFO_SHORT_SLOT_TIME	0x0400
#define	WIFI_CAPINFO_AUTO_POWER_SAVE	0x0800
#define	WIFI_CAPINFO_RADIO_MEASUREMNT	0x1000
#define	WIFI_CAPINFO_DSS_OFDM		0x2000
#define	WIFI_CAPINFO_DELAYED_BLCK_ACK	0x4000
#define	WIFI_CAPINFO_IMMEDIATE_BLCK_ACK	0x8000

//Struct for Mesh Configuration
struct meshconf {
	uint16_t temp;
	uint8_t psel;
	uint8_t pmetric;
	uint8_t congest;
	uint8_t synch;
	uint8_t auth;
	uint8_t form;
	uint8_t cap;
};

#define	MESHCONF_CAPAB_ACCEPT_PLINKS		0x01
#define	MESHCONF_CAPAB_MCCA_SUPPORT		0x02
#define	MESHCONF_CAPAB_MCCA_ENABLED   		0x04
#define	MESHCONF_CAPAB_FORWARDING		0x08
#define	MESHCONF_CAPAB_MBCA_ENABLED		0x10
#define	MESHCONF_CAPAB_TBTT_ADJUSTING		0x20
#define	MESHCONF_CAPAB_POWER_SAVE_LEVEL		0x40

#define CAT_CODE_MESH				0x0d
#define CAT_CODE_SELF_PROTECTED			0x0f
#define HWMP_MESH_PATH_SELECTION		0x01
/* Self Protected Action codes */
enum ieee80211_self_protected_actioncode {
	WLAN_SP_RESERVED = 0,
	WLAN_SP_MESH_PEERING_OPEN = 1,
	WLAN_SP_MESH_PEERING_CONFIRM = 2,
	WLAN_SP_MESH_PEERING_CLOSE = 3,
	WLAN_SP_MGK_INFORM = 4,
	WLAN_SP_MGK_ACK = 5,
};

/* Check where this will be applicable*/
enum ieee80211_root_mode_identifier {
	IEEE80211_ROOTMODE_NO_ROOT = 0,
	IEEE80211_ROOTMODE_ROOT = 1,
	IEEE80211_PROACTIVE_PREQ_NO_PREP = 2,
	IEEE80211_PROACTIVE_PREQ_WITH_PREP = 3,
	IEEE80211_PROACTIVE_RANN = 4,
};

//RANN Flag
#define RANN_FLAG_SET 	0x01

struct root_sta_address {
	uint8_t addr[WIFI_ADDR_LEN];
};

class PrintMesh : public Element {

  String _label;

 public:

  PrintMesh();
  ~PrintMesh();

  const char *class_name() const		{ return "PrintMesh"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return AGNOSTIC; }

 
  Packet *simple_action(Packet *);

 
};

CLICK_ENDDECLS
#endif
