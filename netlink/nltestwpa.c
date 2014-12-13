//NEXT STEP : Understand the parser functions and capture the attributes we need

// compile : gcc nltestwpa.c -I/usr/include/libnl3 -lnl-genl-3 -lnl-3
// execute : NLCB=debug ./a.out

// RANN frame category 13(mesh) subtype 1

#include "netlink/netlink.h"
#include "netlink/genl/genl.h"
#include "netlink/genl/ctrl.h"
#include "netlink/genl/family.h"
#include "netlink/socket.h"
#include <net/if.h>
#include "netlink/errno.h"

#include <stdarg.h>

//copy this from iw
#include "nl80211.h"

#define IEEE80211_FTYPE_MGMT		0x0000
#define IEEE80211_STYPE_ACTION		0x00D0

#define ETH_ALEN 6

static int expectedId;



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


#define nl_handle nl_sock
#define ENOMEM 1337
#define u8 unsigned char
#define u16 unsigned int
#define WLAN_FC_TYPE_MGMT           0
#define WLAN_FC_STYPE_ACTION        13
#define WLAN_FC_STYPE_ASSOC_RESP    1
#define WLAN_FC_STYPE_AUTH      11


static int send_and_recv( // removed global
             struct nl_handle *nl_handle, struct nl_msg *msg,
             int (*valid_handler)(struct nl_msg *, void *),
             void *valid_data)
{
    struct nl_cb *cb;
    int err = -ENOMEM;

    // driver_nl80211.c 4162: global->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    
    //cb = nl_cb_clone(global->nl_cb);
    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb)
        goto out;

    err = nl_send_auto_complete(nl_handle, msg);
    if (err < 0)
        goto out;

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    if (valid_handler)
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
              valid_handler, valid_data);

    while (err > 0) {
        int res = nl_recvmsgs(nl_handle, cb);
        printf("res is %d, err is %d\n",res,err);
        //printf("RES: %s\n",nl_geterror(res));
        //printf("ERR: %s\n",nl_geterror(err));
        if (res < 0) {
            // wpa_printf(MSG_INFO,
            //        "nl80211: %s->nl_recvmsgs failed: %d",
            //        __func__, res);
            printf("nl_recvmsgs failed.");
        }
    }
 out:
    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;
}


static void * nl80211_cmd(int expectedId,
              struct nl_msg *msg, int flags, uint8_t cmd)
{
    return genlmsg_put(msg, 0, 0, expectedId,
               0, flags, cmd, 0);
}

static int nl80211_set_iface_id(struct nl_msg *msg,
                                // removed bss
                                int ifindex
                                )
{
    //if (bss->wdev_id_set)
    //    NLA_PUT_U64(msg, NL80211_ATTR_WDEV, bss->wdev_id);
    //else
        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
    return 0;

nla_put_failure:
    return -1;
}

int os_snprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int ret;

    /* See http://www.ijs.si/software/snprintf/ for portable
     * implementation of snprintf.
     */

    va_start(ap, format);
    ret = vsnprintf(str, size, format, ap);
    va_end(ap);
    if (size > 0)
        str[size - 1] = '\0';
    return ret;
}


static inline int _wpa_snprintf_hex(char *buf, size_t buf_size, const u8 *data,
                    size_t len, int uppercase)
{
    size_t i;
    char *pos = buf, *end = buf + buf_size;
    int ret;
    if (buf_size == 0)
        return 0;
    for (i = 0; i < len; i++) {
        ret = os_snprintf(pos, end - pos, uppercase ? "%02X" : "%02x",
                  data[i]);
        if (ret < 0 || ret >= end - pos) {
            end[-1] = '\0';
            return pos - buf;
        }
        pos += ret;
    }
    end[-1] = '\0';
    return pos - buf;
}

int wpa_snprintf_hex(char *buf, size_t buf_size, const u8 *data, size_t len)
{
    return _wpa_snprintf_hex(buf, buf_size, data, len, 0);
}




static int nl80211_register_frame(  int ifIndex, /* removed struct i802_bss *bss*/
                  struct nl_handle *nl_handle,
                  u16 type, const u8 *match, size_t match_len)
{
    //struct wpa_driver_nl80211_data *drv = bss->drv;

    struct nl_msg *msg;
    int ret = -1;
    char buf[30];
    unsigned char macAddrAttrb[ETH_ALEN];

    msg = nlmsg_alloc();
    if (!msg)
        return -1;

    buf[0] = '\0';
    wpa_snprintf_hex(buf, sizeof(buf), match, match_len);
    // wpa_printf(MSG_DEBUG, "nl80211: Register frame type=0x%x (%s) nl_handle=%p match=%s",
    //        type, fc2str(type), nl_handle, buf);

    //nl80211_cmd(expectedId, msg, NLM_F_DUMP, NL80211_CMD_GET_SCAN);// NL80211_CMD_REGISTER_ACTION);
    
    nl80211_cmd(expectedId, msg, 0, NL80211_CMD_PROBE_CLIENT);// NL80211_CMD_REGISTER_ACTION);
    
    if (nl80211_set_iface_id(msg, ifIndex) < 0) {
        printf("going to nla_put_failure because of nl80211_set_iface_id failing\n");
        goto nla_put_failure;
    }

    //NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, type);
    //NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, match_len, match);

    // //00:1d:0f:e8:a1:b0
    // macAddrAttrb[0] = 0x00;
    // macAddrAttrb[1] = 0x1d;
    // macAddrAttrb[2] = 0x0f;
    // macAddrAttrb[3] = 0xe8;
    // macAddrAttrb[4] = 0xa1;
    // macAddrAttrb[5] = 0xb0;
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, macAddrAttrb);

    ret = send_and_recv(nl_handle, msg, NULL, NULL);
    msg = NULL;
    if (ret) {
        // wpa_printf(MSG_DEBUG, "nl80211: Register frame command "
        //        "failed (type=%u): ret=%d (%s)",
        //        type, ret, strerror(-ret));
        // wpa_hexdump(MSG_DEBUG, "nl80211: Register frame match",
        //         match, match_len);
        printf("register frame command failed.");
        goto nla_put_failure;
    }
    ret = 0;
nla_put_failure:
    nlmsg_free(msg);
    return ret;
}


static int nl80211_register_action_frame( int ifindex, /*struct i802_bss *bss,*/
                    struct nl_handle * handle,
                     const u8 *match, size_t match_len)
{
    u16 type = (WLAN_FC_TYPE_MGMT << 2) | (WLAN_FC_STYPE_ACTION << 4);
    //type = (WLAN_FC_TYPE_MGMT << 2) | (WLAN_FC_STYPE_AUTH<< 4);
    
    printf("type is %x\n",type);
    return nl80211_register_frame(ifindex, handle,
                      type, match, match_len);
}

static const char * nl80211_command_to_string(enum nl80211_commands cmd)
{
#define C2S(x) case x: return #x;
    switch (cmd) {
    C2S(NL80211_CMD_UNSPEC)
    C2S(NL80211_CMD_GET_WIPHY)
    C2S(NL80211_CMD_SET_WIPHY)
    C2S(NL80211_CMD_NEW_WIPHY)
    C2S(NL80211_CMD_DEL_WIPHY)
    C2S(NL80211_CMD_GET_INTERFACE)
    C2S(NL80211_CMD_SET_INTERFACE)
    C2S(NL80211_CMD_NEW_INTERFACE)
    C2S(NL80211_CMD_DEL_INTERFACE)
    C2S(NL80211_CMD_GET_KEY)
    C2S(NL80211_CMD_SET_KEY)
    C2S(NL80211_CMD_NEW_KEY)
    C2S(NL80211_CMD_DEL_KEY)
    C2S(NL80211_CMD_GET_BEACON)
    C2S(NL80211_CMD_SET_BEACON)
    C2S(NL80211_CMD_START_AP)
    C2S(NL80211_CMD_STOP_AP)
    C2S(NL80211_CMD_GET_STATION)
    C2S(NL80211_CMD_SET_STATION)
    C2S(NL80211_CMD_NEW_STATION)
    C2S(NL80211_CMD_DEL_STATION)
    C2S(NL80211_CMD_GET_MPATH)
    C2S(NL80211_CMD_SET_MPATH)
    C2S(NL80211_CMD_NEW_MPATH)
    C2S(NL80211_CMD_DEL_MPATH)
    C2S(NL80211_CMD_SET_BSS)
    C2S(NL80211_CMD_SET_REG)
    C2S(NL80211_CMD_REQ_SET_REG)
    C2S(NL80211_CMD_GET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MGMT_EXTRA_IE)
    C2S(NL80211_CMD_GET_REG)
    C2S(NL80211_CMD_GET_SCAN)
    C2S(NL80211_CMD_TRIGGER_SCAN)
    C2S(NL80211_CMD_NEW_SCAN_RESULTS)
    C2S(NL80211_CMD_SCAN_ABORTED)
    C2S(NL80211_CMD_REG_CHANGE)
    C2S(NL80211_CMD_AUTHENTICATE)
    C2S(NL80211_CMD_ASSOCIATE)
    C2S(NL80211_CMD_DEAUTHENTICATE)
    C2S(NL80211_CMD_DISASSOCIATE)
    C2S(NL80211_CMD_MICHAEL_MIC_FAILURE)
    C2S(NL80211_CMD_REG_BEACON_HINT)
    C2S(NL80211_CMD_JOIN_IBSS)
    C2S(NL80211_CMD_LEAVE_IBSS)
    C2S(NL80211_CMD_TESTMODE)
    C2S(NL80211_CMD_CONNECT)
    C2S(NL80211_CMD_ROAM)
    C2S(NL80211_CMD_DISCONNECT)
    C2S(NL80211_CMD_SET_WIPHY_NETNS)
    C2S(NL80211_CMD_GET_SURVEY)
    C2S(NL80211_CMD_NEW_SURVEY_RESULTS)
    C2S(NL80211_CMD_SET_PMKSA)
    C2S(NL80211_CMD_DEL_PMKSA)
    C2S(NL80211_CMD_FLUSH_PMKSA)
    C2S(NL80211_CMD_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_SET_TX_BITRATE_MASK)
    C2S(NL80211_CMD_REGISTER_FRAME)
    C2S(NL80211_CMD_FRAME)
    C2S(NL80211_CMD_FRAME_TX_STATUS)
    C2S(NL80211_CMD_SET_POWER_SAVE)
    C2S(NL80211_CMD_GET_POWER_SAVE)
    C2S(NL80211_CMD_SET_CQM)
    C2S(NL80211_CMD_NOTIFY_CQM)
    C2S(NL80211_CMD_SET_CHANNEL)
    C2S(NL80211_CMD_SET_WDS_PEER)
    C2S(NL80211_CMD_FRAME_WAIT_CANCEL)
    C2S(NL80211_CMD_JOIN_MESH)
    C2S(NL80211_CMD_LEAVE_MESH)
    C2S(NL80211_CMD_UNPROT_DEAUTHENTICATE)
    C2S(NL80211_CMD_UNPROT_DISASSOCIATE)
    C2S(NL80211_CMD_NEW_PEER_CANDIDATE)
    C2S(NL80211_CMD_GET_WOWLAN)
    C2S(NL80211_CMD_SET_WOWLAN)
    C2S(NL80211_CMD_START_SCHED_SCAN)
    C2S(NL80211_CMD_STOP_SCHED_SCAN)
    C2S(NL80211_CMD_SCHED_SCAN_RESULTS)
    C2S(NL80211_CMD_SCHED_SCAN_STOPPED)
    C2S(NL80211_CMD_SET_REKEY_OFFLOAD)
    C2S(NL80211_CMD_PMKSA_CANDIDATE)
    C2S(NL80211_CMD_TDLS_OPER)
    C2S(NL80211_CMD_TDLS_MGMT)
    C2S(NL80211_CMD_UNEXPECTED_FRAME)
    C2S(NL80211_CMD_PROBE_CLIENT)
    C2S(NL80211_CMD_REGISTER_BEACONS)
    C2S(NL80211_CMD_UNEXPECTED_4ADDR_FRAME)
    C2S(NL80211_CMD_SET_NOACK_MAP)
    C2S(NL80211_CMD_CH_SWITCH_NOTIFY)
    C2S(NL80211_CMD_START_P2P_DEVICE)
    C2S(NL80211_CMD_STOP_P2P_DEVICE)
    C2S(NL80211_CMD_CONN_FAILED)
    C2S(NL80211_CMD_SET_MCAST_RATE)
    C2S(NL80211_CMD_SET_MAC_ACL)
    C2S(NL80211_CMD_RADAR_DETECT)
    C2S(NL80211_CMD_GET_PROTOCOL_FEATURES)
    C2S(NL80211_CMD_UPDATE_FT_IES)
    C2S(NL80211_CMD_FT_EVENT)
    C2S(NL80211_CMD_CRIT_PROTOCOL_START)
    C2S(NL80211_CMD_CRIT_PROTOCOL_STOP)
    C2S(NL80211_CMD_GET_COALESCE)
    C2S(NL80211_CMD_SET_COALESCE)
    C2S(NL80211_CMD_CHANNEL_SWITCH)
    C2S(NL80211_CMD_VENDOR)
    C2S(NL80211_CMD_SET_QOS_MAP)
    default:
        return "NL80211_CMD_UNKNOWN";
    }
#undef C2S
}


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


static int wpacb(struct nl_msg* msg, void* arg)
{
    struct nlmsghdr* ret_hdr = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(ret_hdr);
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    int ifidx; 

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (tb[NL80211_ATTR_IFINDEX]) {
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
        printf("IFINDEX is present, it is %d\n", ifidx);
    } else {
        printf("IFINDEX is NOT present\n");
    }

    printf("gnlh->cmd is %d\n",gnlh->cmd);

    printf("The command is %s\n",nl80211_command_to_string(gnlh->cmd));


    int payloadlen = nlmsg_datalen(ret_hdr);


    printf("wpa cb RUNNING!\n");

    return NL_SKIP;
}

int main(int argc, char** argv)
{
    int ret;
    int err = 1;

    unsigned char macAddrAttrb[ETH_ALEN];

    struct nl_cb *cb1 = nl_cb_alloc(NL_CB_DEBUG);


    //allocate socket
    struct nl_sock* sk = nl_socket_alloc_cb(cb1); //nl_socket_alloc(); 

    unsigned short int type = 0x00D0;   // For action (IEEE80211_FTYPE_MGMT << 2) | (IEEE80211_STYPE_ACTION << 4);
                     //type = 0x0080;   // For beacons

    int ifIndex = if_nametoindex("wlan0"); 

    //connect to generic netlink
    genl_connect(sk);

    //find the nl80211 driver ID
    printf("Before ctrl_resolve\n");
    expectedId = genl_ctrl_resolve(sk, "nl80211");
    printf("expectedID : %d\n", expectedId);


    nl_cb_set(cb1, NL_CB_MSG_IN, NL_CB_CUSTOM, wpacb, NULL);

    nl_socket_set_cb(sk, cb1);
    
  

    // if(nl80211_register_action_frame(ifIndex, sk, (u8 *) "\x06", 1) < 0) {
    //     printf("Error while register_action_frame\n");
    //     return 0;
    // } 
    // else
    // {
    //     printf("Registered for action frames.\n");
    // //    return 0;
    // }

    // //while(1)
    // printf("Waiting for action frames to arrive...\n");
    
    // int x = nl_recvmsgs(sk, cb1);
    // printf("x = %d\n", x);

    // return 0;

    /********************************************************************************/


    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEBUG);
        
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    

    //attach a callback

    //nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, nlCallback, NULL);
    
    // This is the old cb_set
    //nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM,  nlCallback, NULL);
    
    // New cb_set: Used print_sta_handler here  to parse and print the msg
    //nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM,  print_sta_handler, NULL);
    nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM,  wpacb, NULL);

    nl_socket_set_cb(sk, cb);
    
    // allocate a message
    struct nl_msg* msg = nlmsg_alloc();

    /* enum nl80211_commands cmd = NL80211_CMD_GET_INTERFACE; */
    int flags = 0; 
    
    // Current command
    enum nl80211_commands cmd = NL80211_CMD_PROBE_CLIENT; //NL80211_CMD_REGISTER_FRAME;//NL80211_CMD_GET_STATION; //; 


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
    //e8:94:f6:26:25:a5
    //90:68:c3:23:07:a4
    macAddrAttrb[0] = 0x90;
    macAddrAttrb[1] = 0x68;
    macAddrAttrb[2] = 0xc3;
    macAddrAttrb[3] = 0x23;
    macAddrAttrb[4] = 0x07;
    macAddrAttrb[5] = 0xa4;
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, macAddrAttrb);


    //while(1) {
        fprintf(stderr,"Before send_auto_complete\n");
        ret = nl_send_auto_complete(sk, msg);
        fprintf(stderr, "called auto_complete\n");
        nl_recvmsgs_default(sk);
    //}

    //block for message to return

     // while (err > 0) { 
     //    printf("waiting for recvmsgs");
     //     int res = nl_recvmsgs(sk, cb); 
     //     if(res < 0) 
     // 	printf("NL RECVMSG FAILED!\n"); 
     // } 


    // Not sure whether we need the while loop here!
    //while(1)


    fprintf(stderr, "nl_recvmsg_default ended\n");

    return 0;

nla_put_failure:
        printf("failure\n");
        nlmsg_free(msg);
    return 1;
}
