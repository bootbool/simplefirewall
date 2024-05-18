/*
 * For filter IP addresses.
 * single IP is inserted into radix tree.
 * CIDR IP is indexed by hash function.
 * */

#ifndef _IP_H
#define _IP_H

#define IP_NAME ("ip")
#define CIDR_NAME ("cidr")

enum F_IP_LIST_TYPE{
    F_IP_WHITELIST,
    F_IP_BLACKLIST,
    F_CIDR_WHITELIST,
    F_CIDR_BLACKLIST,
    F_MAX
};

#define IP_WHITELIST_MASK ( 1 << F_IP_WHITELIST)
#define IP_BLACKLIST_MASK ( 1 << F_IP_BLACKLIST)
#define CIDR_WHITELIST_MASK ( 1 << F_CIDR_WHITELIST)
#define CIDR_BLACKLIST_MASK ( 1 << F_CIDR_BLACKLIST)

#define f_type u8

/*
 * single IP indexed by radix tree
 */
typedef struct {
    u8 flags;    
    u32 ip;
} ip_desc;


/*
 * CIDR IP indexed by hash
 */
typedef struct  {
    struct hlist_node node;
    u8 flags;
    u8 mask;
    u32 __mask;   /* 1<<mask -1*/
    u32 ip;
} cidr_desc;

int ip_in_whitelist( u32 ip );
int ip_in_blacklist( u32 ip );
int get_ip_whitelist(char* str, int len) ;
int get_ip_blacklist(char* str, int len) ;
int insert_ip( void *desc );
int delete_ip( void *desc );

int ip_in_cidr_whitelist( u32 ip );
int ip_in_cidr_blacklist( u32 ip );
int insert_cidr( void *p);
int delete_cidr( void *p);
int get_cidr_whitelist( char *str, int len );
int get_cidr_blacklist( char *str, int len );
int ip_in_cidr_whitelist( u32 ip );
int ip_in_cidr_blacklist( u32 ip );

void fw_cidr_init(void );
void fw_cidr_exit(void );
void fw_ip_init(void );
void fw_ip_exit(void );

#endif
