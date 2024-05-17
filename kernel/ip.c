/*
 * For filter IP addresses.
 * single IP is inserted into radix tree.
 * CIDR IP is indexed by hash function.
 * */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "log.h"
#include "ip.h"

/* The tree to insert ip address, 
 * key: ip address
 * value: ip_desc
 * */
struct radix_tree_root ip_tree;

int ip_in_whitelist( u32 ip )
{
    ip_desc *desc;
    desc = radix_tree_lookup(&ip_tree, ip);
    if( !desc ) return 0;
    if( desc->flags & IP_WHITELIST_MASK ) return 1;
    return 0;
}

int ip_in_blacklist( u32 ip )
{
    ip_desc *desc;
    desc = radix_tree_lookup(&ip_tree, ip);
    if( !desc ) return 0;
    if( desc->flags & IP_BLACKLIST_MASK ) return 1;
    return 0;
}

/*
 * Create a node to the tree if new ip comes,
 * or add mark to the ip_desc of existing node
 */
int insert_ip( u32 ip, ip_desc *desc )
{
    int error = 0;
    ip_desc *res;
    res = radix_tree_lookup(&ip_tree, ip);
    logs("Add ip %x", ip)
    if( !res){
        res = kmalloc(sizeof(*res), GFP_KERNEL);
        *res = *desc;
        error = radix_tree_insert( &ip_tree, ip, res);
        if( error ) logs("fail insert: ip %u error %d", ip, error);
    }else{
        res->flags |= desc->flags;
    }
    return error;
}


/*
 * Delete ip from ip whiltelist or blacklist specified by [index].
 * Notice that a tree node may contain multi status, 
 * so only when the flag is marked by no status, the node can be delete from the tree.
 * */
void delete_ip( u32 ip, ip_desc *desc )
{
    f_type flag = 0;
    ip_desc *res;
    res = radix_tree_lookup(&ip_tree, ip);
    if( !res){
        logs("fail delete: no ip %u", ip);
        return;
    }
    logs("Delete %x\n", ip);
    res->flags &= (~desc->flags);
    flag = (1 << F_MAX) - 1;
    if( (res->flags & flag) == 0) {
        radix_tree_delete(&ip_tree, ip);
        synchronize_rcu();
        kfree(res);
    }
    return;
}


struct ip_list{
    enum F_IP_LIST_TYPE type;   // whitelist or blacklist?
    int num;   // number of ip in list
    int maxnum;
    u32 ip[0];
};

#define IPLISTNUM 1000
/*
 * malloc a ip_list for given size [num], 
 * resize [list] if it is not NULL
 * */

static struct ip_list* build_ip_list( struct ip_list* list, int num )
{
    struct ip_list *old;
    int realnum = ( num/IPLISTNUM + 1 ) * IPLISTNUM;
    if( !list ){
        list = kmalloc( sizeof(struct ip_list) + realnum * sizeof(u32), GFP_KERNEL);
        list->maxnum = realnum;
        list->num = 0;
        return list;
    }
    if( num > list->maxnum ) {
        old = list;
        list = kmalloc( sizeof(struct ip_list) + realnum * sizeof(u32), GFP_KERNEL);

        memcpy(list, old, sizeof(struct ip_list) + old->num * sizeof(u32));
        list->maxnum = realnum;
        kfree(old);
        return list;
    }
    return list;
}

static struct ip_list *blacklist ;
static struct ip_list *whitelist ;

void get_ip_list(void)
{
    struct radix_tree_iter iter;
    void **slot;
    whitelist = build_ip_list( NULL, IPLISTNUM );
    whitelist->type = F_IP_WHITELIST;
    blacklist = build_ip_list( NULL, IPLISTNUM );
    blacklist->type = F_IP_BLACKLIST;
    rcu_read_lock();
    radix_tree_for_each_slot(slot, &ip_tree, &iter, 0) {
        if( (*(ip_desc **)slot)->flags & IP_WHITELIST_MASK ) {
            whitelist->ip[whitelist->num++] = iter.index;
        } 
        if( (*(ip_desc **)slot)->flags & IP_BLACKLIST_MASK ) {
            blacklist->ip[blacklist->num++] = iter.index;
        }
    }
    rcu_read_unlock();
}

void print_ip_list(void)
{
    int i;
    get_ip_list();
    logs("----------IP whitelist----------");
    for(i=0; i<whitelist->num; i++){
        logs("%d %x", i, whitelist->ip[i]);
    }
    logs("----------IP blacklist----------");
    for(i=0; i<blacklist->num; i++){
        logs("%d %x", i, blacklist->ip[i]);
    }
    kfree(blacklist);
    kfree(whitelist);
    blacklist = NULL;
    whitelist = NULL;
}

/*
 * the length of str should be enough
 * */
int get_ip_whitelist(char* str, int len) 
{   
    int index = 0;
    int i;
    char *end = str + len;
    get_ip_list();
    for(i=0; i<whitelist->num; i++){
        index = sprintf(str, "%x\n", whitelist->ip[i]);
        if( index > 0 ) str+= index;
        if( str > end ){
            logs("str lengh is not enough");
            return i;
        }
    }
    return i;
}

int get_ip_blacklist(char* str, int len) 
{   
    int index = 0;
    int i;
    char *end = str + len;
    get_ip_list();
    for(i=0; i<blacklist->num; i++){
        index = sprintf(str, "%x\n", blacklist->ip[i]);
        if( index > 0 ) str+= index;
        if( str > end ){
            logs("str lengh is not enough");
            return i;
        }
    }
    return i;
}

void destroy_iptree( void )
{
    struct radix_tree_iter iter;
    void **slot;
    radix_tree_for_each_slot(slot, &ip_tree, &iter, 0) {
        radix_tree_delete(&ip_tree, iter.index);
        synchronize_rcu();
        kfree(*slot);
    }
}

void init_iptree(void )
{
	INIT_RADIX_TREE(&ip_tree, GFP_KERNEL);
    whitelist = NULL;
    blacklist = NULL;
}
