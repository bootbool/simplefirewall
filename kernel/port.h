/*
 * For filter network L4 port
 *
 * 
 *
 */


typedef struct{
    struct list_head node; 
    __be8 flags;
    __be16 start;
    __be16 end;
} port_range;




