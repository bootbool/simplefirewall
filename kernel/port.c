#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/slab.h>
#include "port.h"
#include "log.h"


static long unsigned int *port_bitmap;
static struct list_head port_lists;

int insert_port( void *p )
{
    port_desc *desc = p;
    port_desc *desc_new;
    port_desc *desc_iter;
    u16 end = desc->end;

    int i;
    if( desc->end == 0) {
        end = desc->start;
    }
    else if( desc->end < desc->start ) {
        logs("Wrong port %d %d", desc->start, desc->end);
        return 0;
    }
    if( desc->flags & PORT_WHITELIST_MASK ){
        for( i=desc->start; i<= end; i++) {
            set_bit( i<<1, port_bitmap);
        }
    }else if( desc->flags & PORT_BLACKLIST_MASK ){
        for( i=desc->start; i<= end; i++) {
            set_bit( (i<<1) + 1, port_bitmap);
        }
    }
    list_for_each_entry( desc_iter, &port_lists, node){
        if( desc_iter->start == desc->start ) {
            if (desc_iter->end == desc->end){
                desc_iter->flags |= desc->flags;
                return 1;
            }else if (desc_iter->end < desc->end){
                desc_new = kmalloc(sizeof(port_desc), GFP_KERNEL);
                *desc_new = *desc;
                list_add(&desc_new->node, &desc_iter->node);
            }else{
                desc_new = kmalloc(sizeof(port_desc), GFP_KERNEL);
                *desc_new = *desc;
                list_add(&desc_new->node, desc_iter->node.prev);
            }
            return 1;
        }else if( desc_iter->start < desc->start ){
            continue;
        }else{
                desc_new = kmalloc(sizeof(port_desc), GFP_KERNEL);
                *desc_new = *desc;
                list_add(&desc_new->node, desc_iter->node.prev);
                return 1;
        }
    }
    desc_new = kmalloc(sizeof(port_desc), GFP_KERNEL);
    *desc_new = *desc;
    list_add_tail(&desc_new->node, &port_lists);
    return 1;
}


int delete_port( void *p )
{
    port_desc *desc = p;
    int i = 0;
    port_desc *desc_iter;
    list_for_each_entry( desc_iter, &port_lists, node){
        if( (desc_iter->start == desc->start) && (desc_iter->end == desc->end)) {
            desc_iter->flags &= ~desc->flags;
            if( desc_iter->flags == 0){
                list_del(&desc_iter->node);
                kfree(desc_iter);
            }
            i = 1;
            break;
        }
        continue;
    }
    if( i != 1) {
        logs("Fails to delete port %d-%d", desc->start, desc->end);
        return 0;
    }
    if( desc->flags & PORT_WHITELIST_MASK ){
        for( i=desc->start; i<= desc->end; i++) {
            clear_bit( (i<<1) , port_bitmap);
        }
    }else if( desc->flags & PORT_BLACKLIST_MASK ){
        for( i=desc->start; i<= desc->end; i++) {
            clear_bit( (i<<1) + 1, port_bitmap);
        }
    }
    return 1;
}

int port_in_whitelist( u16 port )
{
    return  test_bit( (port<<1), port_bitmap);
}

int port_in_blacklist( u16 port )
{
    return  test_bit( (port<<1)+1, port_bitmap);
}


int get_port_whitelist(char* str, int len) 
{   
    int i;
    int index;
    port_desc *desc;
    char *end = str+len;
    list_for_each_entry( desc, &port_lists, node){
        if( desc->flags & PORT_WHITELIST_MASK ){
            index = sprintf(str, "%d-%d\n", desc->start, desc->end);
            if( index > 0 ) str+= index;
            if( str > end ){
                logs("str lengh is not enough");
                return index;
            }
        }
    }
    index = sprintf(str, "==============\n");
    if( index > 0 ) str+= index;
    for( i=0; i< 65535; i++) {
        if( test_bit( (i<<1), port_bitmap) ){
            index = sprintf(str, "%d\n", i);
            if( index > 0 ) str+= index;
            if( str > end ){  /* bugs here */
                logs("str lengh is not enough");
                return i;
            }
        }
    }
    return 0;
}

int get_port_blacklist(char* str, int len) 
{   
    int i;
    int index;
    port_desc *desc ;
    char *end = str+len;
    list_for_each_entry( desc, &port_lists, node){
        if( desc->flags & PORT_BLACKLIST_MASK ){
            index = sprintf(str, "%d-%d\n", desc->start, desc->end);
            if( index > 0 ) str+= index;
            if( str > end ){
                logs("str lengh is not enough");
                return index;
            }
        }
    }
    index = sprintf(str, "==============\n");
    if( index > 0 ) str+= index;
    for( i=0; i< 65535; i++) {
        if( test_bit( (i<<1)+1, port_bitmap) ){
            index = sprintf(str, "%d\n", i);
            if( index > 0 ) str+= index;
            if( str > end ){  /* bugs here */
                logs("str lengh is not enough");
                return i;
            }
        }
    }
    return 0;
}

void fw_port_init(void)
{
    port_bitmap = bitmap_zalloc(1<<17, GFP_KERNEL); /* 2 bits represent two list, so use 17 */
    INIT_LIST_HEAD( &port_lists );
}

void fw_port_exit(void)
{
    port_desc *desc_iter, *tmp ;
    bitmap_free(port_bitmap);
    list_for_each_entry_safe( desc_iter, tmp, &port_lists, node){
            list_del(&desc_iter->node);
            kfree(desc_iter);
    }
}
