#ifndef _PORT_H
#define _PORT_H
/*
 * For filter network L4 port
 *
 * 
 *
 */

#include "common.h"

typedef struct{
    struct list_head node; 
    u16 flags;
    u16 start;
    u16 end;  /* set to 0 if a single port, not range.*/
} port_desc;




int insert_port( void *p );
int delete_port( void *p );
int port_in_whitelist( u16 port );
int port_in_blacklist( u16 port );
int get_port_whitelist(char* str, int len);
int get_port_blacklist(char* str, int len);
int insert_port( void *p );
int delete_port( void *p );
void fw_port_exit(void);
void fw_port_init(void);

#endif
