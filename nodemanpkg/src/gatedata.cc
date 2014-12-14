/*
 * GateData.{cc,hh} -- print Wifi packets, for debugging.
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
#include "gatedata.hh"

#include <set>
#include <string>

CLICK_DECLS

FILE * gate_data_file = fopen("/home/sudipto/clk/gate_data", "w");
std::set <std::string> gate_set;

GateData::GateData()
    : _print_anno(false),
      _print_checksum(false)
{
    _label = "";
}

GateData::~GateData()
{
}

int
GateData::configure(Vector<String> &conf, ErrorHandler* errh)
{
  int ret;
  _timestamp = false;
  ret = Args(conf, this, errh)
      .read_p("LABEL", _label)
      .read("TIMESTAMP", _timestamp)
      .complete();
  return ret;
}

std::string address_to_string(uint8_t address[])
{
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
         address[0], address[1], address[2], address[3], address[4], address[5]);
  return std::string(macStr);

}


// --------------------------------------- action ----------------------------------------
void GateData_unparse_action(Packet *p)
{
  uint8_t *ptr;
  uint8_t root_sta_address[6];

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

  fprintf(gate_data_file, "gate: ");

  //Root STA address
  root_sta_address[0] = *ptr;
  //fprintf(gate_data_file, "%x:", *ptr);
  ptr++;
  root_sta_address[1] = *ptr;
  //fprintf(gate_data_file, "%x:", *ptr);
  ptr++;
  root_sta_address[2] = *ptr;
  //fprintf(gate_data_file, "%x:", *ptr);
  ptr++;
  root_sta_address[3] = *ptr;
  //fprintf(gate_data_file, "%x:", *ptr);
  ptr++;
  root_sta_address[4] = *ptr;
  //fprintf(gate_data_file, "%x:", *ptr);
  ptr++;
  root_sta_address[5] = *ptr;
  //fprintf(gate_data_file, "%x", *ptr);
  ptr++;

  std::string s = address_to_string(root_sta_address);

  gate_set.insert(s);

  fprintf(gate_data_file, "%s\n", s.c_str());

  //fprintf(gate_data_file, "%s\n", sa.c_str());

  // skipping the rest: ROOT STA seq number, RANN interval, HWMP metric

}


Packet *
GateData::simple_action(Packet *p)
{
  struct click_wifi *wh = (struct click_wifi *) p->data();
  struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
  int type = wh->i_fc[0] & WIFI_FC0_TYPE_MASK;
  int subtype = wh->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;
  int duration = cpu_to_le16(wh->i_dur);
  EtherAddress src;
  EtherAddress dst;
  EtherAddress bssid;

  StringAccum sa;
  StringAccum my_sa;

  if (_label[0] != 0) {
    sa << _label << ": ";
  }
  if (_timestamp)
    sa << p->timestamp_anno() << ": ";

  int len;
  len = sprintf(sa.reserve(9), "%4d | ", p->length());
  sa.adjust_length(len);

  if (ceh->rate == 11) {
    sa << " 5.5";
  } else {
    len = sprintf(sa.reserve(2), "%2d", ceh->rate/2);
    sa.adjust_length(len);
  }
  sa << "Mb ";

  len = sprintf(sa.reserve(9), "+%2d/", ceh->rssi);
  sa.adjust_length(len);

  len = sprintf(sa.reserve(9), "%2d | ", ceh->silence);
  sa.adjust_length(len);



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

  uint8_t *ptr = (uint8_t *) p->data() + sizeof(click_wifi);
  switch (type) {
  case WIFI_FC0_TYPE_MGT:
    sa << "mgmt ";

    switch (subtype) {
    case WIFI_FC0_SUBTYPE_ASSOC_REQ: {
      break;

    }
    case WIFI_FC0_SUBTYPE_ASSOC_RESP: {
      break;
    }
    case WIFI_FC0_SUBTYPE_REASSOC_REQ:    sa << "reassoc_req "; break;
    case WIFI_FC0_SUBTYPE_REASSOC_RESP:   sa << "reassoc_resp "; break;
    case WIFI_FC0_SUBTYPE_PROBE_REQ:      {
      break;
    }
    case WIFI_FC0_SUBTYPE_PROBE_RESP:
      goto done;
    case WIFI_FC0_SUBTYPE_BEACON:
      goto done;
    case WIFI_FC0_SUBTYPE_ATIM:           sa << "atim "; break;
    case WIFI_FC0_SUBTYPE_DISASSOC:       {
      break;
    }
    case WIFI_FC0_SUBTYPE_AUTH: {
      break;
    }
    case WIFI_FC0_SUBTYPE_DEAUTH:         sa << "deauth "; break;

    // ------------------------ACTION (HWMP RANN frames would fall here because of the classifiers used)-------------
    case WIFI_FC0_SUBTYPE_ACTION:
      GateData_unparse_action(p);
      break;
    default:
      sa << "unknown-subtype-" << (int) (wh->i_fc[0] & WIFI_FC0_SUBTYPE_MASK) << " ";
      break;
    }
    break;
  case WIFI_FC0_TYPE_CTL:
    break;
  case WIFI_FC0_TYPE_DATA:
    break;
  default:
    sa << "unknown-type-" << (int) (wh->i_fc[0] & WIFI_FC0_TYPE_MASK) << " ";
  }



  if (subtype == WIFI_FC0_SUBTYPE_BEACON || subtype == WIFI_FC0_SUBTYPE_PROBE_RESP) {

    //click_chatter("%s\n", sa.c_str());
    return p;
  }



  sa << EtherAddress(wh->i_addr1);

  my_sa << " i_addr1: " <<EtherAddress(wh->i_addr1);
  
  if (p->length() >= 16) {
    sa << " " << EtherAddress(wh->i_addr2);
    my_sa << " i_addr2: " << EtherAddress(wh->i_addr2);
  }
  if (p->length() > 22) {
    sa << " " << EtherAddress(wh->i_addr3);
    my_sa << " i_addr3: " << EtherAddress(wh->i_addr3);
  }
  sa << " ";

  // fprintf(gate_data_file, "gate: %s\n", my_sa.c_str()); 
  // my_sa.clear();

  if (p->length() >= sizeof(click_wifi)) {
    uint16_t seq = le16_to_cpu(wh->i_seq) >> WIFI_SEQ_SEQ_SHIFT;
    uint8_t frag = le16_to_cpu(wh->i_seq) & WIFI_SEQ_FRAG_MASK;
    sa << "seq " << (int) seq;
    if (frag || wh->i_fc[1] & WIFI_FC1_MORE_FRAG) {
      sa << " frag " << (int) frag;
    }
    sa << " ";
  }

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

 done:
  //click_chatter("%s\n", sa.c_str());
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GateData)
