// compile : gcc nltestaction.c -I/usr/include/libnl3 -lnl-genl-3 -lnl-3
// execute : NLCB=debug ./a.out

// RANN frame category 13(mesh) subtype 1
// RANN is an element inside an HWMP path selection action frame.

#include "netlink/netlink.h"
#include "netlink/genl/genl.h"
#include "netlink/genl/ctrl.h"
#include "netlink/genl/family.h"
#include "netlink/socket.h"
#include <net/if.h>
#include "netlink/errno.h"

#include "nl80211.h"

#include <stdarg.h>

#define IEEE80211_FTYPE_MGMT		0x0000
#define IEEE80211_STYPE_ACTION		0x00D0
#define ETH_ALEN                    6

#define nl_handle                   nl_sock
#define ENOMEM                      1337
#define u8                          unsigned char
#define u16                         unsigned int
#define WLAN_FC_TYPE_MGMT           0
#define WLAN_FC_STYPE_ACTION        13
#define WLAN_FC_STYPE_ASSOC_RESP    1
#define WLAN_FC_STYPE_AUTH          11

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
    printf("In error_handler. Error occured! code : %d\n", err->error);
    printf("%s\n",nl_geterror(err->error));

    int *ret = arg;
    *ret = err->error;
    return NL_SKIP;
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


static int send_and_recv( // removed global
             struct nl_handle *nl_handle, struct nl_msg *msg,
             int (*valid_handler)(struct nl_msg *, void *),
             void *valid_data)
{
    struct nl_cb *cb;
    int err = -ENOMEM;

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
        printf("RES: %s\n",nl_geterror(res));
        printf("ERR: %s\n",nl_geterror(err));
        if (res < 0) {
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
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
    return 0;

nla_put_failure:
    return -1;
}


static int nl80211_register_frame(  int ifIndex, /* removed struct i802_bss *bss*/
                  struct nl_handle *nl_handle,
                  u16 type, const u8 *match, size_t match_len)
{
    struct nl_msg *msg;
    int ret = -1;
    char buf[30];
    unsigned char macAddrAttrb[ETH_ALEN];

    msg = nlmsg_alloc();
    if (!msg)
        return -1;

    buf[0] = '\0';
    wpa_snprintf_hex(buf, sizeof(buf), match, match_len);
    
    nl80211_cmd(expectedId, msg, 0, NL80211_CMD_REGISTER_ACTION);
    
    if (nl80211_set_iface_id(msg, ifIndex) < 0) {
        printf("going to nla_put_failure because of nl80211_set_iface_id failing\n");
        goto nla_put_failure;
    }

    NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, type);
    NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, match_len, match);

    ret = send_and_recv(nl_handle, msg, NULL, NULL);
    msg = NULL;
    if (ret) {
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
    
    printf("type is %x\n",type);
    return nl80211_register_frame(ifindex, handle,
                      type, match, match_len);
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


    printf("WPA CB RUNNING!\n");

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

    int ifIndex = if_nametoindex("mesh0"); 

    //connect to generic netlink
    genl_connect(sk);

    //find the nl80211 driver ID
    printf("Before ctrl_resolve\n");
    expectedId = genl_ctrl_resolve(sk, "nl80211");
    printf("expectedID : %d\n", expectedId);

    nl_cb_set(cb1, NL_CB_MSG_IN, NL_CB_CUSTOM, wpacb, NULL);

    nl_socket_set_cb(sk, cb1);
    
    if(nl80211_register_action_frame(ifIndex, sk, NULL, 0) < 0) {
        printf("Error while register_action_frame\n");
        return 0;
    } 
    else
    {
        printf("Registered for action frames.\n");
    }

    //while(1)
    printf("Waiting for action frames to arrive...\n");
    
    int x = nl_recvmsgs(sk, cb1);

    printf("x = %d\n", x);

    return 0;
}


