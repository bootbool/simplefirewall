/*
 * For filter IP addresses.
 * single IP is inserted into radix tree.
 * CIDR IP is indexed by hash function.
 * */

#ifndef _IP_H
#define _IP_H

enum F_IP_LIST_TYPE{
    F_IP_WHITELIST,
    F_IP_BLACKLIST,
    F_MAX
};

#define IP_WHITELIST_MASK ( 1 << F_IP_WHITELIST)
#define IP_BLACKLIST_MASK ( 1 << F_IP_BLACKLIST)

#define f_type u8

/*
 * single IP indexed by radix tree
 */
typedef struct {
    u8 flags;    
} ip_desc;


/*
 * CIDR IP indexed by hash
 */
typedef struct  {
    u8 flags;
    u8 bits;
    u32 ip;
} cidr_desc;

int ip_in_whitelist( u32 ip );
int ip_in_blacklist( u32 ip );
int get_ip_whitelist(char* str, int len) ;
int get_ip_blacklist(char* str, int len) ;
int insert_ip( u32 ip, ip_desc *desc );
void delete_ip( u32 ip, ip_desc *desc );

void init_iptree(void);
void destroy_iptree( void );

#endif
