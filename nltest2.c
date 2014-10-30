// compile : gcc nltest2.c -I/usr/include/libnl3 -lnl-genl-3 -lnl-3
//execute : NLCB=debug ./a.out

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

int main(int argc, char** argv)
{
    int ret;
    int err = 1;
    //allocate socket
    struct nl_sock* sk = nl_socket_alloc();
    unsigned short int type = 0x00D0;//(IEEE80211_FTYPE_MGMT << 2) | (IEEE80211_STYPE_ACTION << 4);
    

    //type = 0x0080; // For beacons



    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEBUG);
    //connect to generic netlink
    genl_connect(sk);

    printf("Before ctrl_resolve\n");

    //find the nl80211 driver ID
    expectedId = genl_ctrl_resolve(sk, "nl80211");

    printf("expectedID : %d\n", expectedId);

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    //attach a callback

    /* nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, */
    /* 	nlCallback, NULL); */
    nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM,  nlCallback, NULL);
    nl_socket_set_cb(sk, cb);
    //allocate a message
    struct nl_msg* msg = nlmsg_alloc();

    /* enum nl80211_commands cmd = NL80211_CMD_GET_INTERFACE; */
    int ifIndex = if_nametoindex("wlan0"); 
    int flags = 0; 
    enum nl80211_commands cmd = NL80211_CMD_REGISTER_FRAME;

 /*     * @NL80211_ATTR_FRAME_MATCH: A binary attribute which typically must contain */
 /* *	at least one byte, currently used with @NL80211_CMD_REGISTER_FRAME. */
 /* * @NL80211_ATTR_FRAME_TYPE: A u16 indicating the frame type/subtype for the */
 /* *	@NL80211_CMD_REGISTER_FRAME command. */
   
    
// setup the message
genlmsg_put(msg, 0, 0, expectedId, 0, flags, cmd, 0);

printf("ifindex : %d\n", ifIndex);
//add message attributes
NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifIndex);
NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, type);//IEEE80211_FTYPE_MGMT); //or 0x0008?
NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, 0, NULL);
//send the messge (this frees it)

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

while(1)
    nl_recvmsgs_default(sk);

fprintf(stderr, "nl_recvmsg_default ended\n");

return 0;

nla_put_failure:
printf("failure\n");
nlmsg_free(msg);
return 1;
}
