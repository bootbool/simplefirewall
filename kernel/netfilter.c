#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/ip.h>
#include <net/net_namespace.h>
#include <linux/types.h>
#include "log.h"
#include "ip.h"

extern int ip_in_whitelist( u32 ip );
extern int ip_in_blacklist( u32 ip );
extern int ip_in_cidr_whitelist( u32 ip );
extern int ip_in_cidr_blacklist( u32 ip );

static unsigned int
fw_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct;
    struct iphdr *ip_header;
    u32 ip;
    int ret;

    ip_header = ip_hdr(skb);
	ct = nf_ct_get(skb, &ctinfo);
    if( ct ){
        return NF_ACCEPT;
    }
    ip_header = ip_hdr(skb);
    //ip = ip_header->saddr;
    ip = ntohl( ip_header->saddr );
    ret = ip_in_cidr_blacklist(ip);
    if( unlikely( ret ) ){
        return NF_DROP;
    }
    ret = ip_in_blacklist(ip);
    if( unlikely( ret ) ){
        return NF_DROP;
    }
    ret = ip_in_cidr_whitelist(ip);
    if( likely( ret ) ){
        return NF_ACCEPT;
    }
    ret = ip_in_whitelist(ip);
    if( likely( ret ) ){
        return NF_ACCEPT;
    }
    return NF_DROP;
    
}

static const struct nf_hook_ops fw_ops = {
	.hook = fw_filter,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_CONNTRACK + 1,
};

void fw_net_init( void  )
{
    nf_register_net_hook(&init_net, &fw_ops);
}

void fw_net_exit ( void )
{
    nf_unregister_net_hook(&init_net, &fw_ops);
}
