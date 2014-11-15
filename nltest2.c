//NEXT STEP : Understand the parser functions and capture the attributes we need

// compile : gcc nltest2.c -I/usr/include/libnl3 -lnl-genl-3 -lnl-3
// execute : NLCB=debug ./a.out

#include "netlink/netlink.h"
#include "netlink/genl/genl.h"
#include "netlink/genl/ctrl.h"
#include "netlink/genl/family.h"
#include "netlink/socket.h"
#include <net/if.h>
#include "netlink/errno.h"

//copy this from iw
#include "nl80211.h"

#define IEEE80211_FTYPE_MGMT		0x0000
#define IEEE80211_STYPE_ACTION		0x00D0

#define ETH_ALEN 6

static int expectedId;

static int nlCallback(struct nl_msg* msg, void* arg)
{
    struct nlmsghdr* ret_hdr = nlmsg_hdr(msg);
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];


    // *** dump msg to file ***
    FILE * fp = fopen("/home/sudipto/nodeman/dump","w");

    printf("Dumping msg\n");

    nl_msg_dump(msg, fp);
    fclose(fp);

    fprintf(stderr, "Inside the nlCallback Function\n");
    return NL_SKIP;
    
    printf("in cb ret_hdr->msg_type : %d\n",ret_hdr->nlmsg_type);
    printf("in cb expectedID : %d\n", expectedId);

    int payloadlen = nlmsg_datalen(ret_hdr);
    printf("Length of the payload = %d\n", payloadlen);

    /*if (ret_hdr->nlmsg_type != expectedId) 
    { 
        // what is this??
	    printf("Returning NL_STOP\n");
        return NL_STOP;
    }*/

    struct genlmsghdr *gnlh = (struct genlmsghdr*) nlmsg_data(ret_hdr);


    char * ptr = (char *)gnlh;
    int i = 0;
    while(i < payloadlen)
    {
        printf("%x\n",*ptr);
        ptr++;
        i++;
    }


    printf("Attr len = %d\n",genlmsg_attrlen(gnlh, 0));

    if( genlmsg_attrdata(gnlh, 0) == NULL) printf("attrdata error ");

    printf("\nDoing something\n");


    int validateresult  = nla_validate ( genlmsg_attrdata(gnlh, 0),genlmsg_attrlen(gnlh, 0),NL80211_ATTR_MAX,NULL);
    printf("Validation result = %d\n", validateresult);

    if(nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
	genlmsg_attrlen(gnlh, 0), NULL) < 0) 
        printf("parse error\n");
    else
        printf("parsing done\n");

    if (tb_msg[NL80211_ATTR_IFTYPE]) {
        int type = nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE]);	
	fprintf(stdout, "Type: %d", type);
    }

    /* printf("Leaving callback"); */
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;
	*err = 0;

	printf("inside ack_handler\n");
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	
	printf("In finish_handler\n");
	return NL_SKIP;
}


static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
printf("Error occured! code : %d\n", err->error);
printf("%s\n",nl_geterror(err->error));

int *ret = arg;
*ret = err->error;
return NL_SKIP;
}

/*****************************************************************************************************
 
 Taken from iw-3.17/station.c
 This is part is currently being used to parse the msg received from the command CMD_GET_STATION
 The command is: iw dev wlan0 station dump
 NEXT STEP : Understand the parser functions and capture the attributes we need
*****************************************************************************************************/

#define BIT(x) (1ULL<<(x))

enum plink_state {
    LISTEN,
    OPN_SNT,
    OPN_RCVD,
    CNF_RCVD,
    ESTAB,
    HOLDING,
    BLOCKED
};

static void print_power_mode(struct nlattr *a)
{
    enum nl80211_mesh_power_mode pm = nla_get_u32(a);

    switch (pm) {
    case NL80211_MESH_POWER_ACTIVE:
        printf("ACTIVE");
        break;
    case NL80211_MESH_POWER_LIGHT_SLEEP:
        printf("LIGHT SLEEP");
        break;
    case NL80211_MESH_POWER_DEEP_SLEEP:
        printf("DEEP SLEEP");
        break;
    default:
        printf("UNKNOWN");
        break;
    }
}

static char *get_chain_signal(struct nlattr *attr_list)
{
    struct nlattr *attr;
    static char buf[64];
    char *cur = buf;
    int i = 0, rem;
    const char *prefix;

    if (!attr_list)
        return "";

    nla_for_each_nested(attr, attr_list, rem) {
        if (i++ > 0)
            prefix = ", ";
        else
            prefix = "[";

        cur += snprintf(cur, sizeof(buf) - (cur - buf), "%s%d", prefix,
                (int8_t) nla_get_u8(attr));
    }

    if (i)
        snprintf(cur, sizeof(buf) - (cur - buf), "] ");

    return buf;
}

void parse_bitrate(struct nlattr *bitrate_attr, char *buf, int buflen)
{
    int rate = 0;
    char *pos = buf;
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
        [NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 },
        [NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
        [NL80211_RATE_INFO_MCS] = { .type = NLA_U8 },
        [NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
        [NL80211_RATE_INFO_SHORT_GI] = { .type = NLA_FLAG },
    };

    if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
                 bitrate_attr, rate_policy)) {
        snprintf(buf, buflen, "failed to parse nested rate attributes!");
        return;
    }

    if (rinfo[NL80211_RATE_INFO_BITRATE32])
        rate = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]);
    else if (rinfo[NL80211_RATE_INFO_BITRATE])
        rate = nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
    if (rate > 0)
        pos += snprintf(pos, buflen - (pos - buf),
                "%d.%d MBit/s", rate / 10, rate % 10);

    if (rinfo[NL80211_RATE_INFO_MCS])
        pos += snprintf(pos, buflen - (pos - buf),
                " MCS %d", nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]));
    if (rinfo[NL80211_RATE_INFO_VHT_MCS])
        pos += snprintf(pos, buflen - (pos - buf),
                " VHT-MCS %d", nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_MCS]));
    if (rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
        pos += snprintf(pos, buflen - (pos - buf), " 40MHz");
    if (rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
        pos += snprintf(pos, buflen - (pos - buf), " 80MHz");
    if (rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
        pos += snprintf(pos, buflen - (pos - buf), " 80P80MHz");
    if (rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
        pos += snprintf(pos, buflen - (pos - buf), " 160MHz");
    if (rinfo[NL80211_RATE_INFO_SHORT_GI])
        pos += snprintf(pos, buflen - (pos - buf), " short GI");
    if (rinfo[NL80211_RATE_INFO_VHT_NSS])
        pos += snprintf(pos, buflen - (pos - buf),
                " VHT-NSS %d", nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]));
}

void mac_addr_n2a(char *mac_addr, unsigned char *arg)
{
    int i, l;

    l = 0;
    for (i = 0; i < ETH_ALEN ; i++) {
        if (i == 0) {
            sprintf(mac_addr+l, "%02x", arg[i]);
            l += 2;
        } else {
            sprintf(mac_addr+l, ":%02x", arg[i]);
            l += 3;
        }
    }
}


static int print_sta_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    char mac_addr[20], state_name[10], dev[20];
    struct nl80211_sta_flag_update *sta_flags;
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
        [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
        [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
        [NL80211_STA_INFO_T_OFFSET] = { .type = NLA_U64 },
        [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
        [NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
        [NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
        [NL80211_STA_INFO_TX_RETRIES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
        [NL80211_STA_INFO_STA_FLAGS] =
            { .minlen = sizeof(struct nl80211_sta_flag_update) },
        [NL80211_STA_INFO_LOCAL_PM] = { .type = NLA_U32},
        [NL80211_STA_INFO_PEER_PM] = { .type = NLA_U32},
        [NL80211_STA_INFO_NONPEER_PM] = { .type = NLA_U32},
        [NL80211_STA_INFO_CHAIN_SIGNAL] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_CHAIN_SIGNAL_AVG] = { .type = NLA_NESTED },
    };
    char *chain;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);

    /*
     * TODO: validate the interface and mac address!
     * Otherwise, there's a race condition as soon as
     * the kernel starts sending station notifications.
     */

    if (!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }
    if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                 tb[NL80211_ATTR_STA_INFO],
                 stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    mac_addr_n2a(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));
    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
    printf("Station %s (on %s)", mac_addr, dev);

    if (sinfo[NL80211_STA_INFO_INACTIVE_TIME])
        printf("\n\tinactive time:\t%u ms",
            nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME]));
    if (sinfo[NL80211_STA_INFO_RX_BYTES])
        printf("\n\trx bytes:\t%u",
            nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]));
    if (sinfo[NL80211_STA_INFO_RX_PACKETS])
        printf("\n\trx packets:\t%u",
            nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]));
    if (sinfo[NL80211_STA_INFO_TX_BYTES])
        printf("\n\ttx bytes:\t%u",
            nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]));
    if (sinfo[NL80211_STA_INFO_TX_PACKETS])
        printf("\n\ttx packets:\t%u",
            nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]));
    if (sinfo[NL80211_STA_INFO_TX_RETRIES])
        printf("\n\ttx retries:\t%u",
            nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]));
    if (sinfo[NL80211_STA_INFO_TX_FAILED])
        printf("\n\ttx failed:\t%u",
            nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]));

    chain = get_chain_signal(sinfo[NL80211_STA_INFO_CHAIN_SIGNAL]);
    if (sinfo[NL80211_STA_INFO_SIGNAL])
        printf("\n\tsignal:  \t%d %sdBm",
            (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]),
            chain);

    chain = get_chain_signal(sinfo[NL80211_STA_INFO_CHAIN_SIGNAL_AVG]);
    if (sinfo[NL80211_STA_INFO_SIGNAL_AVG])
        printf("\n\tsignal avg:\t%d %sdBm",
            (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]),
            chain);

    if (sinfo[NL80211_STA_INFO_T_OFFSET])
        printf("\n\tToffset:\t%lld us",
            (unsigned long long)nla_get_u64(sinfo[NL80211_STA_INFO_T_OFFSET]));

    if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {
        char buf[100];

        parse_bitrate(sinfo[NL80211_STA_INFO_TX_BITRATE], buf, sizeof(buf));
        printf("\n\ttx bitrate:\t%s", buf);
    }

    if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {
        char buf[100];

        parse_bitrate(sinfo[NL80211_STA_INFO_RX_BITRATE], buf, sizeof(buf));
        printf("\n\trx bitrate:\t%s", buf);
    }

    if (sinfo[NL80211_STA_INFO_EXPECTED_THROUGHPUT]) {
        uint32_t thr;

        thr = nla_get_u32(sinfo[NL80211_STA_INFO_EXPECTED_THROUGHPUT]);
        /* convert in Mbps but scale by 1000 to save kbps units */
        thr = thr * 1000 / 1024;

        printf("\n\texpected throughput:\t%u.%uMbps",
               thr / 1000, thr % 1000);
    }

    if (sinfo[NL80211_STA_INFO_LLID])
        printf("\n\tmesh llid:\t%d",
            nla_get_u16(sinfo[NL80211_STA_INFO_LLID]));
    if (sinfo[NL80211_STA_INFO_PLID])
        printf("\n\tmesh plid:\t%d",
            nla_get_u16(sinfo[NL80211_STA_INFO_PLID]));
    if (sinfo[NL80211_STA_INFO_PLINK_STATE]) {
        switch (nla_get_u8(sinfo[NL80211_STA_INFO_PLINK_STATE])) {
        case LISTEN:
            strcpy(state_name, "LISTEN");
            break;
        case OPN_SNT:
            strcpy(state_name, "OPN_SNT");
            break;
        case OPN_RCVD:
            strcpy(state_name, "OPN_RCVD");
            break;
        case CNF_RCVD:
            strcpy(state_name, "CNF_RCVD");
            break;
        case ESTAB:
            strcpy(state_name, "ESTAB");
            break;
        case HOLDING:
            strcpy(state_name, "HOLDING");
            break;
        case BLOCKED:
            strcpy(state_name, "BLOCKED");
            break;
        default:
            strcpy(state_name, "UNKNOWN");
            break;
        }
        printf("\n\tmesh plink:\t%s", state_name);
    }
    if (sinfo[NL80211_STA_INFO_LOCAL_PM]) {
        printf("\n\tmesh local PS mode:\t");
        print_power_mode(sinfo[NL80211_STA_INFO_LOCAL_PM]);
    }
    if (sinfo[NL80211_STA_INFO_PEER_PM]) {
        printf("\n\tmesh peer PS mode:\t");
        print_power_mode(sinfo[NL80211_STA_INFO_PEER_PM]);
    }
    if (sinfo[NL80211_STA_INFO_NONPEER_PM]) {
        printf("\n\tmesh non-peer PS mode:\t");
        print_power_mode(sinfo[NL80211_STA_INFO_NONPEER_PM]);
    }

    if (sinfo[NL80211_STA_INFO_STA_FLAGS]) {
        sta_flags = (struct nl80211_sta_flag_update *)
                nla_data(sinfo[NL80211_STA_INFO_STA_FLAGS]);

        if (sta_flags->mask & BIT(NL80211_STA_FLAG_AUTHORIZED)) {
            printf("\n\tauthorized:\t");
            if (sta_flags->set & BIT(NL80211_STA_FLAG_AUTHORIZED))
                printf("yes");
            else
                printf("no");
        }

        if (sta_flags->mask & BIT(NL80211_STA_FLAG_AUTHENTICATED)) {
            printf("\n\tauthenticated:\t");
            if (sta_flags->set & BIT(NL80211_STA_FLAG_AUTHENTICATED))
                printf("yes");
            else
                printf("no");
        }

        if (sta_flags->mask & BIT(NL80211_STA_FLAG_SHORT_PREAMBLE)) {
            printf("\n\tpreamble:\t");
            if (sta_flags->set & BIT(NL80211_STA_FLAG_SHORT_PREAMBLE))
                printf("short");
            else
                printf("long");
        }

        if (sta_flags->mask & BIT(NL80211_STA_FLAG_WME)) {
            printf("\n\tWMM/WME:\t");
            if (sta_flags->set & BIT(NL80211_STA_FLAG_WME))
                printf("yes");
            else
                printf("no");
        }

        if (sta_flags->mask & BIT(NL80211_STA_FLAG_MFP)) {
            printf("\n\tMFP:\t\t");
            if (sta_flags->set & BIT(NL80211_STA_FLAG_MFP))
                printf("yes");
            else
                printf("no");
        }

        if (sta_flags->mask & BIT(NL80211_STA_FLAG_TDLS_PEER)) {
            printf("\n\tTDLS peer:\t");
            if (sta_flags->set & BIT(NL80211_STA_FLAG_TDLS_PEER))
                printf("yes");
            else
                printf("no");
        }
    }

    printf("\n");
    return NL_SKIP;
}

// Part from station.c ends
/*****************************************************************************************************/


int main(int argc, char** argv)
{
    int ret;
    int err = 1;

    unsigned char macAddrAttrb[ETH_ALEN];

    //allocate socket
    struct nl_sock* sk = nl_socket_alloc();

    unsigned short int type = 0x00D0;   // For action (IEEE80211_FTYPE_MGMT << 2) | (IEEE80211_STYPE_ACTION << 4);
                     //type = 0x0080;   // For beacons

    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEBUG);
    
    //connect to generic netlink
    genl_connect(sk);

    printf("Before ctrl_resolve\n");

    //find the nl80211 driver ID
    expectedId = genl_ctrl_resolve(sk, "nl80211");

    printf("expectedID : %d\n", expectedId);

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    

    //attach a callback

    //nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, nlCallback, NULL);
    
    // This is the old cb_set
    //nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM,  nlCallback, NULL);
    
    // New cb_set: Used print_sta_handler here from station.c (see above) to parse and print the msg
    nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM,  print_sta_handler, NULL);

    nl_socket_set_cb(sk, cb);
    
    // allocate a message
    struct nl_msg* msg = nlmsg_alloc();

    /* enum nl80211_commands cmd = NL80211_CMD_GET_INTERFACE; */
    int ifIndex = if_nametoindex("wlan0"); 
    int flags = 0; 
    
    // Current command
    enum nl80211_commands cmd = NL80211_CMD_GET_STATION;


 /* * @NL80211_ATTR_FRAME_MATCH: A binary attribute which typically must contain */
 /* *	at least one byte, currently used with @NL80211_CMD_REGISTER_FRAME. */
 /* * @NL80211_ATTR_FRAME_TYPE: A u16 indicating the frame type/subtype for the */
 /* *	@NL80211_CMD_REGISTER_FRAME command. */
   
    
// * @NL80211_CMD_GET_STATION: Get station attributes for station identified by
// *  %NL80211_ATTR_MAC on the interface identified by %NL80211_ATTR_IFINDEX.


    // setup the message
    genlmsg_put(msg, 0, 0, expectedId, 0, flags, cmd, 0);

    printf("ifindex : %d\n", ifIndex);

    //add message attributes

    // Attributes for CMD_REGISTER_FRAME
    /*
        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifIndex);
        NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, type);//IEEE80211_FTYPE_MGMT); //or 0x0008?
        NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, 0, NULL);
    */


    // Attributes for CMD_GET_STATION
    /*
        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifIndex);
        NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, macAddrAttrb);
    */


    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifIndex);
    // This mac address is what you see when you run iw dev wlan0 station dump
    // Not the mac address you see when you do ifconfig wlan0
    // Change the values accordingly!
    // 00:1d:0f:e8:a1:b0
    macAddrAttrb[0] = 0x00;
    macAddrAttrb[1] = 0x1d;
    macAddrAttrb[2] = 0x0f;
    macAddrAttrb[3] = 0xe8;
    macAddrAttrb[4] = 0xa1;
    macAddrAttrb[5] = 0xb0;
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, macAddrAttrb);

    fprintf(stderr,"Before send_auto_complete\n");

    ret = nl_send_auto_complete(sk, msg);
    fprintf(stderr, "called auto_complete\n");

    //block for message to return

     // while (err > 0) { 
     //    printf("waiting for recvmsgs");
     //     int res = nl_recvmsgs(sk, cb); 
     //     if(res < 0) 
     // 	printf("NL RECVMSG FAILED!\n"); 
     // } 


    // Not sure whether we need the while loop here!
    //while(1)
        nl_recvmsgs_default(sk);

    fprintf(stderr, "nl_recvmsg_default ended\n");

    return 0;

nla_put_failure:
        printf("failure\n");
        nlmsg_free(msg);
    return 1;
}
