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
#include "port.h"

extern int ip_in_whitelist( u32 ip );
extern int ip_in_blacklist( u32 ip );
extern int ip_in_cidr_whitelist( u32 ip );
extern int ip_in_cidr_blacklist( u32 ip );

static inline int is_new_connection(struct sk_buff *skb)
{
    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;

    ct = nf_ct_get(skb, &ctinfo);
    return !((ctinfo % IP_CT_IS_REPLY) == IP_CT_ESTABLISHED ||
             (ctinfo % IP_CT_IS_REPLY) == IP_CT_RELATED);
}

static unsigned int
fw_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    enum ip_conntrack_info ctinfo;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    __be16 dst_port;
    u32 ip;
    int ret;

    ip_header = ip_hdr(skb);
    ret = is_new_connection(skb);
    if( ret ){
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

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        dst_port = ntohs(tcp_header->dest);
    }else if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = udp_hdr(skb);
        dst_port = ntohs(udp_header->dest);
    }else{
        return NF_ACCEPT;
    }
    if( port_in_whitelist( dst_port ) )
        return NF_ACCEPT;
    if( port_in_blacklist( dst_port ) )
        return NF_DROP;
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
