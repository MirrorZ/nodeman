/*
 * printWifi.{cc,hh} -- print Wifi packets, for debugging.
 * John Bicket
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/ipaddress.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include <string>
#include "printmesh.hh"
CLICK_DECLS

PrintMesh::PrintMesh()
{
}

PrintMesh::~PrintMesh()
{
}

String handle_mesh_code(uint8_t *mc, bool is_preq,bool is_prep, bool is_root)
{
  	StringAccum sa;
	struct root_sta_address *ra;

	if(is_root && *mc++ == RANN_FLAG_SET)
		sa << "is_gate=1 ";
	
	int hop_count= *mc;
	sa <<"Hop_Count:"<<hop_count;
	
	int hwmp_ttl =  *(++mc);
	sa<<" HWMP_TTL:"<<hwmp_ttl;
	
	if(is_preq)
	{
		mc++;
		uint32_t hwmp_path_dis_id =  *(uint32_t *)mc;;
		sa << " HWMP_Path_Discover_ID:"<< hwmp_path_dis_id;
		mc+=3;
	}

	mc++;
	ra = (struct root_sta_address *)mc;
	if(is_preq)
		sa<<" Originator";
	else if(is_prep)
		sa<<" Target";
	else if(is_root)
		sa<<" Root";

	sa << "_STA_Addr:"<<EtherAddress(ra->addr)<<" ";
	mc+=6;

	uint32_t seq = *mc;
	if(is_preq)
		sa<<"HWMP_Originator_";
	else if(is_prep)
		sa<<"Target_HWMP_";
	else if(is_root)
		sa<<"Root_STA_";
	sa << "Sequence_Number:"<< seq <<" ";

	mc+=4;
	uint32_t interval =  *(uint32_t *)mc;;
	
	if(is_root)
		sa << "RANN_Interval:";
	else
		sa << "HWMP_Lifetime:";
	sa << interval;

	mc+=4;

	uint32_t metric = *(uint32_t *)mc;
	sa << " HWMP_Metric:" << metric<<" ";
	
	mc+=4;

	if(is_preq)
		mc+=2;

	if(is_preq || is_prep){
		ra = (struct root_sta_address *)mc;
		if(is_preq)
			sa<<"Target";
		else if(is_prep)
			sa<<"Originator";

		sa << "_STA_Addr:"<<EtherAddress(ra->addr)<<" ";
		mc+=6;

		seq =  *(uint32_t *)mc;
		if(is_prep)
			sa<<"HWMP_Originator_";
		else if(is_preq)
			sa<<"Target_HWMP_";

		sa << "Sequence_Number:"<< seq <<" ";
	}
	

	return sa.take_string();
}

String mesh_unparse_action(Packet *p,struct click_wifi *w){
 StringAccum sa; 
 uint8_t *ptr = (uint8_t *) (w+1);
 uint8_t *end  = (uint8_t *) p->data() + p->length();
 
 uint8_t cat_code = *ptr;
 ptr++;
 switch(cat_code)
 {
	case CAT_CODE_MESH : 
		
		sa <<"Category:Mesh ";
		if(*ptr & HWMP_MESH_PATH_SELECTION)
			sa<<"Action:HWMP_Mesh_Path_Selection ";
		    ptr++;		    	
		    switch (*ptr) {
			case  WIFI_ELEMID_MESH_PATH_REQ :
				sa << "Tag:Mesh_Path_Request ";
				sa << handle_mesh_code(ptr+3,true,false,false);   
				break;
			case  WIFI_ELEMID_MESH_PATH_REP :
				sa << "Tag:Mesh_Path_Reply ";    
				sa << handle_mesh_code(ptr+3,false,true,false);   
				break;
			case  WIFI_ELEMID_ROOT_ANNOUNCEMENT :
				sa << "Tag:Root_Announcements ";
				sa << handle_mesh_code(ptr+2,false,false,true);
				break;
		    }
		break;
	case CAT_CODE_SELF_PROTECTED : 
		sa <<"Category: Self Protected ";
		switch(*ptr)
		{
			case	WLAN_SP_MESH_PEERING_OPEN : 
				sa<< "Action:Mesh_Peering_Open ";
				break; 
			case	WLAN_SP_MESH_PEERING_CONFIRM :
				sa<< "Action:Mesh_Peering_Confirm ";
				break;
			case	WLAN_SP_MESH_PEERING_CLOSE :
				sa<< "Action:Mesh_Peering_Close ";
				break;
			default : sa << "Unknown_Action:" << (*ptr);
		}
	break;
 }

	return sa.take_string();
}



String mesh_unparse_beacon(Packet *p,struct click_wifi *w) {
  uint8_t *ptr;
  //struct click_wifi *w = (struct click_wifi *) p->data();
  StringAccum sa;

  ptr = (uint8_t *) (w+1);

  //uint8_t *ts = ptr;
  ptr += 8;

  uint16_t beacon_int = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;

  uint16_t capability = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;


  uint8_t *end  = (uint8_t *) p->data() + p->length();

  uint8_t *ssid_l = NULL;
  uint8_t *rates_l = NULL;
  uint8_t *xrates_l = NULL;
  uint8_t *ds_l = NULL;
  uint8_t *mesh_id = NULL;
  uint8_t *mesh_conf = NULL;
  uint8_t *traffic_imap  = NULL;
  while (ptr < end) {
    switch (*ptr) {
    case WIFI_ELEMID_SSID:
      ssid_l = ptr;
      break;
    case WIFI_ELEMID_RATES:
      rates_l = ptr;
      break;
    case WIFI_ELEMID_XRATES:
      xrates_l = ptr;
      break;
    case WIFI_ELEMID_FHPARMS:
      break;
    case WIFI_ELEMID_DSPARMS:
      ds_l = ptr;
      break;
    case WIFI_ELEMID_IBSSPARMS:
      break;
    case WIFI_ELEMID_TIM:
	traffic_imap=ptr;
      break;
    case WIFI_ELEMID_ERP:
      break;
    case WIFI_ELEMID_VENDOR:
      break;
    case WIFI_ELEMID_MESHCONF:
	mesh_conf = ptr;
	break;     	 
    case  WIFI_ELEMID_MESHID:
	mesh_id=ptr;
	break;		
    }
    ptr += ptr[1] + 2;

  }

  EtherAddress bssid = EtherAddress(w->i_addr3);
  sa << bssid << " ";

  String ssid = "";
  if (ssid_l && ssid_l[1]) {
    ssid = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
  }

  int chan = (ds_l) ? ds_l[2] : 0;
  sa << " Channel:" << chan;
  sa << " Beacon_Interval:" << beacon_int << " ";

  Vector<int> basic_rates;
  Vector<int> rates;
  if (rates_l) {
    for (int x = 0; x < WIFI_MIN((int)rates_l[1], WIFI_RATE_SIZE); x++) {
      uint8_t rate = rates_l[x + 2];

      if (rate & WIFI_RATE_BASIC) {
	basic_rates.push_back((int)(rate & WIFI_RATE_VAL));
      } else {
	rates.push_back((int)(rate & WIFI_RATE_VAL));
      }
    }
  }


  if (xrates_l) {
    for (int x = 0; x < WIFI_MIN((int)xrates_l[1], WIFI_RATE_SIZE); x++) {
      uint8_t rate = xrates_l[x + 2];

      if (rate & WIFI_RATE_BASIC) {
	basic_rates.push_back((int)(rate & WIFI_RATE_VAL));
      } else {
	rates.push_back((int)(rate & WIFI_RATE_VAL));
      }
    }
  }


  sa << "Capabilities:[ ";
  if (capability & WIFI_CAPINFO_ESS) {
    sa << "ESS ";
  }
  if (capability & WIFI_CAPINFO_IBSS) {
    sa << "IBSS ";
  }
  if (capability & WIFI_CAPINFO_CF_POLLABLE) {
    sa << "CF_POLLABLE ";
  }
  if (capability & WIFI_CAPINFO_CF_POLLREQ) {
    sa << "CF_POLLREQ ";
  }
  if (capability & WIFI_CAPINFO_PRIVACY) {
    sa << "PRIVACY ";
  }
  if (capability & WIFI_CAPINFO_SHORT_PREAMBLE) {
    sa << "SHORT PREAMBLE ";
  }
  if (capability & WIFI_CAPINFO_PBCC) {
    sa << "PBCC ";
  }
  if (capability & WIFI_CAPINFO_CHANNEL_AGILITY) {
    sa << "CHANNEL_AGILITY ";
  }
  if (capability & WIFI_CAPINFO_SPECTRUM_MGMT) {
    sa << "SPECTRUM_MGMT ";
  }
  if (capability & WIFI_CAPINFO_SHORT_SLOT_TIME) {
    sa << "SHORT_SLOT_TIME ";
  }
  if (capability & WIFI_CAPINFO_AUTO_POWER_SAVE) {
    sa << "AUTO_POWER_SAVE ";
  }
  if (capability & WIFI_CAPINFO_RADIO_MEASUREMNT) {
    sa << "RADIO_MEASUREMENT ";
  }
  if (capability & WIFI_CAPINFO_DSS_OFDM) {
    sa << "DSS_OFDM ";
  }
  if (capability & WIFI_CAPINFO_DELAYED_BLCK_ACK) {
    sa << "DELAYED_BLOCK_ACK ";
  }
  if (capability & WIFI_CAPINFO_IMMEDIATE_BLCK_ACK) {
    sa << "IMMEDIATE_BLOCK_ACK ";
  }
  sa << "] ";

  sa << "Supported Rates : (";
  for (int x = 0; x < basic_rates.size(); x++) {
    sa << basic_rates[x]/2 << " ";
    if (x != basic_rates.size()-1) {
      sa << " ";
    }
  }
 
  for (int x = 0; x < rates.size(); x++) {
    sa << rates[x]/2;
    if (x != rates.size()-1 ) {
      sa << " ";
    }
  }

  sa << ")";
 
  sa<<" Mesh_ID : ";
  String meshid = "";
  if (mesh_id && mesh_id[1]) {
    meshid = String((char *) mesh_id + 2, (int)mesh_id[1]);
    sa<<meshid;
  }
  else
    sa<<"(none)";		

  sa<<" ";

//Not Working

 
 if(mesh_conf){
	 struct meshconf *mc = (struct meshconf *)mesh_conf; /*
	 switch(mc->psel)
	{
		case HWMP_PROTOCOL : 
			sa << "HWMP ";
			break;
	}
/*
	 if (hwmp == 1)
		sa<< "HWMP ";
  if (mc->pmetric == 0x01)
	sa << "Airtime ";
  if (mc->congest == 0x01)
	sa << "Congestion Control ";
  if (mc->synch == 0x01)
	sa << "Neighbour Offset Sync ";
  if (mc->auth == 0x01)
	sa << "Authentication Protocol ";
  /*if (mc->form <  IEEE80211_MAX_MESH_PEERINGS){    
	mconf->meshconf_form >> = 1;
	sa << "Number of Peering : "<< (mconf->meshconf_form & 0x3f);
  }*/
  sa << "Mesh_Capabilities:[";
  if(mc->cap & MESHCONF_CAPAB_ACCEPT_PLINKS)	
	sa <<"Accept_Mesh_Peering ";
  if(mc->cap & MESHCONF_CAPAB_MCCA_SUPPORT)	
	sa <<"MCCA_support ";
  if(mc->cap & MESHCONF_CAPAB_MCCA_ENABLED)	
	sa <<"MCCA_Enabled ";
  if(mc->cap & MESHCONF_CAPAB_FORWARDING)	
	sa <<"Mesh_Forwarding ";
  if(mc->cap & MESHCONF_CAPAB_MBCA_ENABLED)	
	sa <<"MBCA_Enabled ";
  if(mc->cap & MESHCONF_CAPAB_TBTT_ADJUSTING)	
	sa <<"TBTT_Adjustment ";
  if(mc->cap & MESHCONF_CAPAB_POWER_SAVE_LEVEL)	
	sa <<"Power_Save";
  sa<< "] ";
 }

  return sa.take_string();
}

String mesh_reason_string(int reason) {
  switch (reason) {
  case WIFI_REASON_UNSPECIFIED: return "unspecified";
  case WIFI_REASON_AUTH_EXPIRE:	return "auth_expire";
  case WIFI_REASON_AUTH_LEAVE:	return "auth_leave";
  case WIFI_REASON_ASSOC_EXPIRE: return "assoc_expire/inactive";
  case WIFI_REASON_ASSOC_TOOMANY: return "assoc_toomany";
  case WIFI_REASON_NOT_AUTHED:  return "not_authed";
  case WIFI_REASON_NOT_ASSOCED: return "not_assoced";
  case WIFI_REASON_ASSOC_LEAVE: return "assoc_leave";
  case WIFI_REASON_ASSOC_NOT_AUTHED: return "assoc_not_authed";
  default: return "unknown reason " + String(reason);
  }

}

String mesh_status_string(int status) {
  switch (status) {

  case WIFI_STATUS_SUCCESS: return "success";
  case WIFI_STATUS_UNSPECIFIED: return "unspecified";
  case WIFI_STATUS_CAPINFO: return "capinfo";
  case WIFI_STATUS_NOT_ASSOCED: return "not_assoced";
  case WIFI_STATUS_OTHER: return "other";
  case WIFI_STATUS_ALG: return "alg";
  case WIFI_STATUS_SEQUENCE: return "seq";
  case WIFI_STATUS_CHALLENGE: return "challenge";
  case WIFI_STATUS_TIMEOUT: return "timeout";
  case WIFI_STATUS_BASIC_RATES: return "basic_rates";
  case WIFI_STATUS_TOO_MANY_STATIONS: return "too_many_stations";
  case WIFI_STATUS_RATES: return "rates";
  case WIFI_STATUS_SHORTSLOT_REQUIRED: return "shortslot_required";
  default: return "unknown status " + String(status);
  }
}
String mesh_capability_string(int capability) {
  StringAccum sa;
  sa << "[";
  bool any = false;
  if (capability & WIFI_CAPINFO_ESS) {
    sa << "ESS";
    any = true;
  }
  if (capability & WIFI_CAPINFO_IBSS) {
    if (any) { sa << " ";}
    sa << "IBSS";
    any = true;
  }
  if (capability & WIFI_CAPINFO_CF_POLLABLE) {
    if (any) { sa << " ";}
    sa << "CF_POLLABLE";
    any = true;
  }
  if (capability & WIFI_CAPINFO_CF_POLLREQ) {
    if (any) { sa << " ";}
    sa << "CF_POLLREQ";
    any = true;
  }
  if (capability & WIFI_CAPINFO_PRIVACY) {
    if (any) { sa << " ";}
    sa << "PRIVACY";
    any = true;
  }
 if (capability & WIFI_CAPINFO_SHORT_PREAMBLE) {
    if (any) { sa << " ";} 
    sa << "SHORT PREAMBLE";
  }
  if (capability & WIFI_CAPINFO_PBCC) {
    if (any) { sa << " ";}
    sa << "PBCC";
    any = true;
  }
  if (capability & WIFI_CAPINFO_CHANNEL_AGILITY) {
    if (any) { sa << " ";}
    sa << "CHANNEL_AGILITY";
    any = true;
  }
  if (capability & WIFI_CAPINFO_SPECTRUM_MGMT) {
    if (any) { sa << " ";}
    sa << "SPECTRUM_MGMT";
    any = true;
  }
  if (capability & WIFI_CAPINFO_SHORT_SLOT_TIME) {
    if (any) { sa << " ";}
    sa << "SHORT_SLOT_TIME";
    any = true;
  }
  if (capability & WIFI_CAPINFO_AUTO_POWER_SAVE) {
    if (any) { sa << " ";}
    sa << "AUTO_POWER_SAVE";
    any = true;
  }
  if (capability & WIFI_CAPINFO_RADIO_MEASUREMNT) {
    if (any) { sa << " ";}
    sa << "RADIO_MEASUREMENT";
    any = true;
  }
  if (capability & WIFI_CAPINFO_DSS_OFDM) {
    if (any) { sa << " ";}
    sa << "DSS_OFDM";
    any = true;
  }
  if (capability & WIFI_CAPINFO_DELAYED_BLCK_ACK) {
    if (any) { sa << " ";}
    sa << "DELAYED_BLOCK_ACK";
    any = true;
  }
  if (capability & WIFI_CAPINFO_IMMEDIATE_BLCK_ACK) {
    if (any) { sa << " ";}
    sa << "IMMEDIATE_BLOCK_ACK";
    any = true;
  }
  sa << "]";
  return sa.take_string();
}

String mesh_get_ssid(u_int8_t *ptr) {
  if (ptr[0] != WIFI_ELEMID_SSID) {
    return "(invalid ssid)";
  }
  return String((char *) ptr + 2, WIFI_MIN((int)ptr[1], WIFI_NWID_MAXSIZE));
}

Vector<int> mesh_get_rates(u_int8_t *ptr) {
  Vector<int> rates;
  for (int x = 0; x < WIFI_MIN((int)ptr[1], WIFI_RATES_MAXSIZE); x++) {
    uint8_t rate = ptr[x + 2];
    rates.push_back(rate);
  }
  return rates;
}

String mesh_rates_string(Vector<int> rates) {
  Vector<int> basic_rates;
  Vector<int> other_rates;
  StringAccum sa;
  for (int x = 0; x < rates.size(); x++) {
    if (rates[x] & WIFI_RATE_BASIC) {
      basic_rates.push_back(rates[x]);
    } else {
      other_rates.push_back(rates[x]);
    }
  }
  sa << "({";
  for (int x = 0; x < basic_rates.size(); x++) {
    sa << (basic_rates[x] & WIFI_RATE_VAL);
    if (x != basic_rates.size()-1) {
      sa << " ";
    }
  }
  sa << "} ";
  for (int x = 0; x < other_rates.size(); x++) {
    sa << other_rates[x];
    if (x != other_rates.size()-1) {
      sa << " ";
    }
  }
  sa << ")";
  return sa.take_string();
}
Packet *
PrintMesh::simple_action(Packet *p)
{
  //Intial bytes contain RadioTap Header
  uint8_t *ptr1 = (uint8_t *)p->data();	
  ptr1+=2;
  ptr1+=*ptr1-2;		
  struct click_wifi *wh = (struct click_wifi *) ptr1;
  struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
  int type = wh->i_fc[0] & WIFI_FC0_TYPE_MASK;
  int subtype = wh->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;
  int duration = cpu_to_le16(wh->i_dur);
  EtherAddress src;
  EtherAddress dst;
  EtherAddress bssid;




  StringAccum sa;
 
  int len;
  len = sprintf(sa.reserve(9), "%4d | ", p->length());
  sa.adjust_length(len);

 /* if (ceh->rate == 11) {
    sa << " 5.5";
  } else {
    len = sprintf(sa.reserve(2), "%2d", ceh->rate/2);
    sa.adjust_length(len);
  }
  sa << "Mb ";

  len = sprintf(sa.reserve(9), "+%2d/", ceh->rssi);
  sa.adjust_length(len);

  len = sprintf(sa.reserve(9), "%2d | ", ceh->silence);
  sa.adjust_length(len);*/



  switch (wh->i_fc[1] & WIFI_FC1_DIR_MASK) {
  case WIFI_FC1_DIR_NODS:
    dst = EtherAddress(wh->i_addr1);
    src = EtherAddress(wh->i_addr2);
    bssid = EtherAddress(wh->i_addr3);
    break;
  case WIFI_FC1_DIR_TODS:
    bssid = EtherAddress(wh->i_addr1);
    src = EtherAddress(wh->i_addr2);
    dst = EtherAddress(wh->i_addr3);
    break;
  case WIFI_FC1_DIR_FROMDS:
    dst = EtherAddress(wh->i_addr1);
    bssid = EtherAddress(wh->i_addr2);
    src = EtherAddress(wh->i_addr3);
    break;
  case WIFI_FC1_DIR_DSTODS:
    dst = EtherAddress(wh->i_addr1);
    src = EtherAddress(wh->i_addr2);
    bssid = EtherAddress(wh->i_addr3);
    break;
  default:
    sa << "??? ";
  }

  uint8_t *ptr = ptr1 + sizeof(click_wifi);
  switch (type) {
  case WIFI_FC0_TYPE_MGT:
    sa << "mgmt ";

    switch (subtype) {
    case WIFI_FC0_SUBTYPE_ASSOC_REQ: {
      uint16_t capability = le16_to_cpu(*(uint16_t *) ptr);
      ptr += 2;

      uint16_t l_int = le16_to_cpu(*(uint16_t *) ptr);
      ptr += 2;

      String ssid = mesh_get_ssid(ptr);
      ptr += ptr[1] + 2;

      Vector<int> rates = mesh_get_rates(ptr);
      String rates_s = mesh_rates_string(rates);

      sa << "assoc_req ";
      sa << "listen_int " << l_int << " ";
      sa << mesh_capability_string(capability);
      sa << " ssid " << ssid;
      sa << " rates " << rates_s;
      sa << " ";
      break;

    }
    case WIFI_FC0_SUBTYPE_ASSOC_RESP: {
      uint16_t capability = le16_to_cpu(*(uint16_t *) ptr);
      ptr += 2;

      uint16_t status = le16_to_cpu(*(uint16_t *) ptr);
      ptr += 2;

      uint16_t associd = le16_to_cpu(*(uint16_t *) ptr);
      ptr += 2;
      sa << "assoc_resp ";
      sa << mesh_capability_string(capability);
      sa << " status " << (int) status << " " << mesh_status_string(status);
      sa << " associd " << associd << " ";
      break;
    }
    case WIFI_FC0_SUBTYPE_REASSOC_REQ:    sa << "reassoc_req "; break;
    case WIFI_FC0_SUBTYPE_REASSOC_RESP:   sa << "reassoc_resp "; break;
    case WIFI_FC0_SUBTYPE_PROBE_REQ:      {
      sa << "probe_req ";
      String ssid = mesh_get_ssid(ptr);
      ptr += ptr[1] + 2;

      Vector<int> rates = mesh_get_rates(ptr);
      String rates_s = mesh_rates_string(rates);
      sa << "ssid " << ssid;
      sa << " " << rates_s << " ";
      break;

    }
    case WIFI_FC0_SUBTYPE_PROBE_RESP:
      sa << "probe_resp ";
      sa << mesh_unparse_beacon(p,wh);
      break;
      //goto done;
    case WIFI_FC0_SUBTYPE_BEACON:
      sa << "beacon ";
      sa << mesh_unparse_beacon(p,wh);
      break;
      //goto done;
    case WIFI_FC0_SUBTYPE_ATIM:           sa << "atim "; break;
    case WIFI_FC0_SUBTYPE_DISASSOC:       {
      uint16_t reason = le16_to_cpu(*(uint16_t *) ptr);
      sa << "disassoc " << mesh_reason_string(reason) << " ";
      break;
    }
    case WIFI_FC0_SUBTYPE_AUTH: {
      sa << "auth ";
      uint16_t algo = le16_to_cpu(*(uint16_t *) ptr);
      ptr += 2;

      uint16_t seq = le16_to_cpu(*(uint16_t *) ptr);
      ptr += 2;

      uint16_t status =le16_to_cpu(*(uint16_t *) ptr);
      ptr += 2;
      sa << "alg " << (int)  algo;
      sa << " auth_seq " << (int) seq;
      sa << " status " << mesh_status_string(status) << " ";
      break;

    }
    case WIFI_FC0_SUBTYPE_DEAUTH:         sa << "deauth "; break;
    case WIFI_FC0_SUBTYPE_ACTION:    
     sa << "action "; 
     sa << mesh_unparse_action(p,wh);
     break;
    default:
      sa << "unknown-subtype-" << (int) (wh->i_fc[0] & WIFI_FC0_SUBTYPE_MASK) << " ";
      break;
    }
    break;
  case WIFI_FC0_TYPE_CTL:
    sa << "cntl ";
    switch (wh->i_fc[0] & WIFI_FC0_SUBTYPE_MASK) {
    case WIFI_FC0_SUBTYPE_PS_POLL:    sa << "psp  "; break;
    case WIFI_FC0_SUBTYPE_RTS:        sa << "rts  "; break;
    case WIFI_FC0_SUBTYPE_CTS:	      sa << "cts  "; break;
    case WIFI_FC0_SUBTYPE_ACK:	      sa << "ack  " << duration << " "; break;
    case WIFI_FC0_SUBTYPE_CF_END:     sa << "cfe  "; break;
    case WIFI_FC0_SUBTYPE_CF_END_ACK: sa << "cfea "; break;
    default:
    sa << "unknown-subtype-" << (int) (wh->i_fc[0] & WIFI_FC0_SUBTYPE_MASK) << " ";
    }
    break;
  case WIFI_FC0_TYPE_DATA:
    sa << "data ";
    switch (wh->i_fc[1] & WIFI_FC1_DIR_MASK) {
    case WIFI_FC1_DIR_NODS:   sa << "nods "; break;
    case WIFI_FC1_DIR_TODS:   sa << "tods "; break;
    case WIFI_FC1_DIR_FROMDS: sa << "frds "; break;
    case WIFI_FC1_DIR_DSTODS: sa << "dsds "; break;
    }
    break;
  default:
    sa << "unknown-type-" << (int) (wh->i_fc[0] & WIFI_FC0_TYPE_MASK) << " ";
  }



  if (subtype == WIFI_FC0_SUBTYPE_BEACON || subtype == WIFI_FC0_SUBTYPE_PROBE_RESP) {

    click_chatter("%s\n", sa.c_str());
    return p;
  }


  sa << EtherAddress(wh->i_addr1);
  if (p->length() >= 16) {
    sa << " " << EtherAddress(wh->i_addr2);
  }
  if (p->length() > 22) {
    sa << " " << EtherAddress(wh->i_addr3);
  }
  sa << " ";

  if (p->length() >= sizeof(click_wifi)) {
    uint16_t seq = le16_to_cpu(wh->i_seq) >> WIFI_SEQ_SEQ_SHIFT;
    uint8_t frag = le16_to_cpu(wh->i_seq) & WIFI_SEQ_FRAG_MASK;
    sa << "seq " << (int) seq;
    if (frag || wh->i_fc[1] & WIFI_FC1_MORE_FRAG) {
      sa << " frag " << (int) frag;
    }
    sa << " ";
  }
/*
  sa << "[";
  if (ceh->flags & WIFI_EXTRA_TX) {
    sa << " tx";
  }
  if (ceh->flags & WIFI_EXTRA_TX_FAIL) {
    sa << " fail";
  }
  if (ceh->flags & WIFI_EXTRA_TX_USED_ALT_RATE) {
    sa << " alt_rate";
  }
  if (ceh->flags & WIFI_EXTRA_RX_ERR) {
    sa << " err";
  }
  if (ceh->flags & WIFI_EXTRA_RX_MORE) {
    sa << " more";
  }
  if (wh->i_fc[1] & WIFI_FC1_RETRY) {
    sa << " retry";
  }
  if (wh->i_fc[1] & WIFI_FC1_WEP) {
    sa << " wep";
  }
  sa << " ] ";

  if (ceh->flags & WIFI_EXTRA_TX) {
	  sa << " retries " << (int) ceh->retries;
  }

 */
  click_chatter("%s\n", sa.c_str());
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PrintMesh)
