#include <linux/proc_fs.h>
#include <linux/uaccess.h> 
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include "log.h"
#include "ip.h"
#include "port.h"


enum proc_type{
    add,
    delete,
    show
};

struct mutex proc_mutex;

static void get_path_type(struct file *file, enum F_LIST_TYPE *listtype, enum proc_type *proctype)
{
    char *opsname;
    char *listname;
    char *ipname;
    opsname = file->f_path.dentry->d_iname;
    if( strcmp( opsname, "add") == 0) *proctype = add;
    else if( strcmp( opsname, "delete") == 0) *proctype = delete;
    else if( strcmp( opsname, "show") == 0) *proctype = show;

    listname = file->f_path.dentry->d_parent->d_iname;
    ipname = file->f_path.dentry->d_parent->d_parent->d_iname;
    if( strcmp( ipname, IP_NAME) == 0){
        if( strcmp( listname, "whitelist") == 0) *listtype= F_IP_WHITELIST;
        else if( strcmp( listname, "blacklist") == 0) *listtype= F_IP_BLACKLIST;
    } else if( strcmp( ipname, CIDR_NAME) == 0){
        if( strcmp( listname, "whitelist") == 0) *listtype= F_CIDR_WHITELIST;
        else if( strcmp( listname, "blacklist") == 0) *listtype= F_CIDR_BLACKLIST;
    }else if( strcmp( ipname, PORT_NAME) == 0){
        if( strcmp( listname, "whitelist") == 0) *listtype= F_PORT_WHITELIST;
        else if( strcmp( listname, "blacklist") == 0) *listtype= F_PORT_BLACKLIST;
    }

    logs("%s %s %s", ipname, listname, opsname);
}


static ssize_t str_read(struct file *file, char __user *user_buffer, size_t count, loff_t *ppos)
{
    ssize_t ret;
    enum F_LIST_TYPE listtype;
    enum proc_type proctype;
    struct page *pages;
    void *data;
    int pagenum = 4;
    int len;
    if(file->private_data == 0 ) {
        file->private_data = (void *)1;
    }else{
        file->private_data = 0;
        return 0;
    }
    get_path_type(file, &listtype, &proctype);
    if( proctype != show ){
        logs("Not allowed to read");
        return -EFAULT;
    }
    pages = alloc_pages(GFP_KERNEL, pagenum);
    if( !pages ){
        logs("Fails to alloc pages");
        return -EFAULT;
    }
    data = page_address(pages);
    if( (listtype == F_IP_WHITELIST) && (proctype == show) ){
        get_ip_whitelist(data, 4096<<pagenum);
    } else if( (listtype == F_IP_BLACKLIST) && (proctype == show) ){
        get_ip_blacklist(data, 4096<<pagenum);
    }else if( (listtype == F_CIDR_WHITELIST) && (proctype == show) ){
        get_cidr_whitelist(data, 4096<<pagenum);
    }else if( (listtype == F_CIDR_BLACKLIST) && (proctype == show) ){
        get_cidr_blacklist(data, 4096<<pagenum);
    }else if( (listtype == F_PORT_WHITELIST) && (proctype == show) ){
        get_port_whitelist(data, 4096<<pagenum);
    }else if( (listtype == F_PORT_BLACKLIST) && (proctype == show) ){
        get_port_blacklist(data, 4096<<pagenum);
    }

    len = strlen(data);
    if(len >= count ) {
        logs("length is not enough");
        len = count;
    } 
    ret = copy_to_user(user_buffer, data, len);
    free_pages((unsigned long)data, pagenum);
    if (ret == 0) {
        // Successful copy
        *ppos += len;
        return len;
    } else {
        // Error copying data to user space
        return -EFAULT;
    }
}

int parse_str_ip( char *str, void *p)
{
    ip_desc *desc = p;
    if(in4_pton(str, -1, (u8 *)&desc->ip, -1, NULL) == 0){
        return 0;
    }
    desc->ip = ntohl( desc->ip);
    return 1;
}

int parse_str_cidr( char *str, void *_desc)
{
    cidr_desc *desc = _desc;
    char *p = str;
    if(strlen(str) == 0) return 0;
    while( *p != '/' ){
        p++;
        if( (p-str) > 18 ) return 0; /* out of bound */
    }
    *p = 0;
    p++;
    if(in4_pton(str, -1, (u8 *)&desc->ip, -1, NULL) == 0){
        return 0;
    }
    desc->ip = ntohl( desc->ip);
    if( kstrtou8( p, 10, &desc->mask) == 1 ){
        logs("Failt to parse ip/mask %d", p);
        return 0;
    }
    return 1;
}

int parse_str_port( char *str, void *_desc)
{
    port_desc *desc = _desc;
    char *p = str;
    int isrange = 0;
    if(strlen(str) == 0) return 0;
    while( (*p != '-') && (*p != 0) ){
        p++;
    }
    if( *p == '-' ){
        *p = 0;
        p++;
        isrange = 1;
    }
    desc->start = desc->end = 0;
    if( kstrtou16( str, 10, &desc->start) == 1 ){
        logs("Failt to parse port %d", str);
        return 0;
    }
    if( isrange ){
        if( kstrtou16( p, 10, &desc->end) == 1 ){
            logs("Failt to parse port %d", p);
            return 0;
        }
    }
    return 1;
}

static ssize_t str_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos)
{
    char *buffer;
    ssize_t ret;
    char *p;
    void *desc;
    ip_desc ipdesc;
    cidr_desc cidrdesc;
    port_desc portdesc;
    int size;
    enum F_LIST_TYPE listtype;
    enum proc_type proctype;
    int (*parse)( char*,  void *);
    int (*work)( void *);
    get_path_type(file, &listtype, &proctype);
    if( proctype >= show ){
        logs("Not allowed to write");
        return -EFAULT;
    }
    size = 4096*16;
    buffer = kmalloc(size, GFP_KERNEL);
    if (count > size) {
        // Limit the write count to the size of the buffer
        count = size;
    }

    ret = copy_from_user(buffer, user_buffer, count);
    if (ret != 0) {
        return -EFAULT;
    } 
    buffer[count] = 0;
    *ppos = count;
    switch( listtype ){
        case F_IP_WHITELIST:
           ipdesc.flags = IP_WHITELIST_MASK; 
           desc = &ipdesc;
           parse = parse_str_ip;
           break;
        case F_IP_BLACKLIST :
           ipdesc.flags = IP_BLACKLIST_MASK;
           desc = &ipdesc;
           parse = parse_str_ip;
           break;
        case F_CIDR_WHITELIST:
           cidrdesc.flags = CIDR_WHITELIST_MASK;
           desc = &cidrdesc;
           parse = parse_str_cidr;
           break;
        case F_CIDR_BLACKLIST:
           cidrdesc.flags = CIDR_BLACKLIST_MASK;
           desc = &cidrdesc;
           parse = parse_str_cidr;
           break;
        case F_PORT_WHITELIST:
           portdesc.flags = PORT_WHITELIST_MASK;
           desc = &portdesc;
           parse = parse_str_port;
           break;
        case F_PORT_BLACKLIST:
           portdesc.flags = PORT_BLACKLIST_MASK;
           desc = &portdesc;
           parse = parse_str_port;
           break;
        default:
           logs("Wrong list type");
    }
    switch( proctype ){
        case add:
            if((listtype == F_IP_WHITELIST) || (listtype == F_IP_BLACKLIST))
                work = insert_ip;
            else if((listtype == F_CIDR_WHITELIST) || (listtype == F_CIDR_BLACKLIST))
                work = insert_cidr;
            else if((listtype == F_PORT_WHITELIST) || (listtype == F_PORT_BLACKLIST))
                work = insert_port;
            break;
        case delete:
            if((listtype == F_IP_WHITELIST) || (listtype == F_IP_BLACKLIST))
                work = delete_ip;
            else if((listtype == F_CIDR_WHITELIST) || (listtype == F_CIDR_BLACKLIST))
                work = delete_cidr;
            else if((listtype == F_PORT_WHITELIST) || (listtype == F_PORT_BLACKLIST))
                work = delete_port;
            break;
        case show:
            break;
    }

    mutex_lock(&proc_mutex);
	while ((p = strsep(&buffer, " |\n|\t|,")) != NULL) {

        if(parse(p, desc) == 0){
            if( strlen( p ) > 0 )
                logs("Fails to parse %s", p);
            continue;
        }
        work(desc);
	}
    kfree(buffer);
    mutex_unlock(&proc_mutex);
    return count;
}

static const struct file_operations str_add_fops = {
    .owner = THIS_MODULE,
    .write = str_write,
};

static const struct file_operations str_delete_fops = {
    .owner = THIS_MODULE,
    .write = str_write,
};

static const struct file_operations str_show_fops = {
    .owner = THIS_MODULE,
    .read = str_read,
};

struct fw_procfs_ops {
    char name[64];
    const struct file_operations add ;
    const struct file_operations delete;
    const struct file_operations show;
};

struct fw_procfs_ops ip_ops = {
    .name = IP_NAME,
    .add = str_add_fops,
    .delete = str_delete_fops,
    .show = str_show_fops,
};

struct fw_procfs_ops cidr_ops = {
    .name = CIDR_NAME,
    .add = str_add_fops,
    .delete = str_delete_fops,
    .show = str_show_fops,
};

struct fw_procfs_ops port_ops = {
    .name = PORT_NAME,
    .add = str_add_fops,
    .delete = str_delete_fops,
    .show = str_show_fops,
};

static void create_proc_tree( struct fw_procfs_ops *ops )
{
    struct proc_dir_entry *folder;
    char path[100];
    sprintf(path, "%s/%s", FW_PROC, ops->name);
    folder= proc_mkdir(path, NULL);

    sprintf(path, "%s/%s/whitelist", FW_PROC, ops->name);
    folder= proc_mkdir(path, NULL);
    /* /proc/simplefirewall/???/whitelist/[add/delete/show] */
    proc_create("add", 0222, folder, &ops->add);
    proc_create("delete", 0222, folder, &ops->delete);
    proc_create("show", 0111, folder, &ops->show);

    /* /proc/simplefirewall/???/blacklist */
    sprintf(path, "%s/%s/blacklist", FW_PROC, ops->name);
    folder= proc_mkdir(path, NULL);
    proc_create("add", 0222, folder, &ops->add);
    proc_create("delete", 0222, folder, &ops->delete);
    proc_create("show", 0111, folder, &ops->show);

}

static void destroy_proc_tree( char *tree )
{
    char path[100];
    sprintf(path, "%s/%s", FW_PROC, tree);
    remove_proc_subtree(path, NULL);
}


int fw_proc_init( void )
{
    mutex_init(&proc_mutex);
    proc_mkdir(FW_PROC, NULL);
    create_proc_tree( &ip_ops );
    create_proc_tree( &cidr_ops );
    create_proc_tree( &port_ops );
    return 0;
}

void fw_proc_exit( void )
{
    destroy_proc_tree( IP_NAME );
    destroy_proc_tree( CIDR_NAME );
    destroy_proc_tree( PORT_NAME );
    remove_proc_subtree(FW_PROC, NULL);
}

