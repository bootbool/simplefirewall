#include <linux/inet.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/percpu-defs.h>
#include "ip.h"
#include "log.h"


/*
 * CIDR address is organized in hlist, the head is indexed by hash function. 
 * Format: 192.168.1.0/24
 * */
struct hlist_head *cidr_hash = NULL;
static DEFINE_PER_CPU(cidr_desc *, cidrcache) = NULL;

#define bucketshift 16
#define bucket_num (1<<bucketshift)


static inline u16 hashfn( u32 ip )
{
    return jhash(&ip, 4, 0);
}

static unsigned char cidr_mask_array[32] = {0};

/* 
 * cidr masks are stored in descend order in array
 * */
static inline void insert_mask_array( u8 mask )
{
    int i = 0;
    int pos = 0;
    while( cidr_mask_array[pos] > mask ){ pos++; } /* find the position to insert */
    if(cidr_mask_array[pos] == mask ) return;
    i = pos;
    while(cidr_mask_array[i] > 0 ) { i++; } /* find the last valid value */
    while( i > pos ) {
        cidr_mask_array[i] = cidr_mask_array[i-1];
        i--;
    } /* find the last valid value */
    cidr_mask_array[pos] = mask;
}

static inline void remove_mask_array( u8 mask )
{
    int pos;
    while( cidr_mask_array[pos] > mask ){ pos++; } /* find the position to insert */
    if(cidr_mask_array[pos] == mask ) {
        while(cidr_mask_array[pos] != 0 ) {
            cidr_mask_array[pos] = cidr_mask_array[pos+1];
            pos++;
        } /* find the last valid value */
    }

    cidr_mask_array[pos] = mask;
}

/* *
 * Insert a cide address to hash list, 
 * format: 3.3.3.0/24
 * */
int insert_cidr( void *_p)
{
    u16 hash;
    cidr_desc *desc;
    cidr_desc *p = _p;
    p->__mask = (1<<p->mask) -1;
    p->ip &= ~p->__mask; 
    hash = hashfn(p->ip);
    logs("insert cidr ip %x mask %d hash %d", p->ip, p->mask, hash);
    rcu_read_lock();
    hlist_for_each_entry_rcu( desc, &cidr_hash[hash], node) {
        if( (desc->ip == p->ip) && (desc->mask == p->mask)){
            desc->flags |= p->flags;
            rcu_read_unlock();
            return 0;
        }
    }
    rcu_read_unlock();
    if( desc == NULL ) {
        desc = kmalloc(sizeof(*desc), GFP_KERNEL);
        desc->ip = p->ip;
        desc->mask = p->mask;
        desc->__mask = p->__mask;
        desc->flags = p->flags;
		hlist_add_head_rcu(&desc->node, &cidr_hash[hash]);
        insert_mask_array(p->mask);
    }
    return 0;
}

int delete_cidr( void *_p)
{
    u16 hash;
    cidr_desc *desc;
    cidr_desc *p = _p;
    p->ip &= ~( (1<<p->mask) -1 ); 
    hash = hashfn(p->ip);
    logs("delete cidr ip %x mask %d hash %d", p->ip, p->mask, hash);
    rcu_read_lock();
    hlist_for_each_entry_rcu( desc, &cidr_hash[hash], node) {
        if( (desc->ip == p->ip) && (desc->mask == p->mask)){
            desc->flags &= ~p->flags;
            if(desc->flags == 0) {
                hlist_del_rcu(&desc->node);
                synchronize_rcu();
                remove_mask_array(desc->mask);
                kfree(desc);
                logs("Success delete cidr ip %x mask %d hash %d", p->ip, p->mask, hash);
            }
        }
    }
    rcu_read_unlock();
    return 0;
}


int ip_in_cidr_whitelist( u32 ip )
{
    int i;
    u16 hash;
    cidr_desc *desc;
    desc = this_cpu_read( cidrcache);
    if( desc && (desc->flags & CIDR_WHITELIST_MASK)) {
        if( desc->ip == (ip & desc->__mask) ) return 1;
    }
    for( i=0; i<32; i++ ){
        if(cidr_mask_array[i] != 0) {
            ip &= ~( (1<<cidr_mask_array[i]) -1 ); 
            hash = hashfn(ip);
            rcu_read_lock();
            hlist_for_each_entry_rcu( desc, &cidr_hash[hash], node) {
                if( desc->ip == ip ){
                    this_cpu_write( cidrcache, desc);
                    if( desc->flags & CIDR_WHITELIST_MASK) {
                        rcu_read_unlock();
                        return 1;
                    }
                }
            }
            rcu_read_unlock();
        }
    }
    return 0;
}

int ip_in_cidr_blacklist( u32 ip )
{
    int i;
    u16 hash;
    cidr_desc *desc;
    desc = this_cpu_read( cidrcache);
    if( desc && (desc->flags & CIDR_BLACKLIST_MASK)) {
        if( desc->ip == (ip & desc->__mask) ) return 1;
    }
    for( i=0; i<32; i++ ){
        if(cidr_mask_array[i] != 0) {
            ip &= ~( (1<<cidr_mask_array[i]) -1 ); 
            hash = hashfn(ip);
            rcu_read_lock();
            hlist_for_each_entry_rcu( desc, &cidr_hash[hash], node) {
                if( desc->ip == ip ){
                    this_cpu_write( cidrcache, desc);
                    if( desc->flags & CIDR_BLACKLIST_MASK) {
                        rcu_read_unlock();
                        return 1;
                    }
                }
            }
            rcu_read_unlock();
        }
    }
    return 0;
}

int get_cidr_whitelist( char *str, int len )
{
    cidr_desc *desc;
    char *end = str + len;
    int i;
    int index;
    str[0] = 0;
    for(i=0; i<bucket_num; i++) {
        rcu_read_lock();
        hlist_for_each_entry_rcu( desc, &cidr_hash[i], node) {
            if( desc->flags & CIDR_WHITELIST_MASK) {
                index = sprintf(str, "%x/%d\n", desc->ip, desc->mask); /*!! maybe out of bound*/
                if( index > 0 ) str+= index;
                if( str > end ){
                    logs("str lengh is not enough");
                    return i;
                }
            }
        }
        rcu_read_unlock();
    }
    return i;
}

int get_cidr_blacklist( char *str, int len )
{
    cidr_desc *desc;
    char *end = str + len;
    int i;
    int index;
    str[0] = 0;
    for(i=0; i<bucket_num; i++) {
        rcu_read_lock();
        hlist_for_each_entry_rcu( desc, &cidr_hash[i], node) {
            if( desc->flags & CIDR_BLACKLIST_MASK) {
                index = sprintf(str, "%x/%d\n", desc->ip, desc->mask); /*!! maybe out of bound*/
                if( index > 0 ) str+= index;
                if( str > end ){
                    logs("str lengh is not enough");
                    return i;
                }
            }
        }
        rcu_read_unlock();
    }
    return i;
}

void fw_cidr_init(void)
{
    int i;
    cidr_hash = kmalloc(bucket_num * sizeof(*cidr_hash), GFP_KERNEL);
    if( !cidr_hash ){
        logs("Fails to kmalloc cidr hash");
        return;
    }
    for (i = 0; i < bucket_num; i++)
        INIT_HLIST_HEAD(&cidr_hash[i]);
}

void fw_cidr_exit(void)
{
    int i;
    cidr_desc *desc;
    struct hlist_node *tmp;
    for(i=0; i<bucket_num; i++) {
        hlist_for_each_entry_safe( desc, tmp, &cidr_hash[i], node) {
            hlist_del_rcu(&desc->node);
            synchronize_rcu();
            logs("Success delete cidr ip %x mask %d hash %d", desc->ip, desc->mask, i);
            kfree(desc);
        }
    }
    kfree(cidr_hash);
}

