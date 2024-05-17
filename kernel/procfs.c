#include <linux/proc_fs.h>
#include <linux/uaccess.h> 
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include "log.h"
#include "ip.h"

#define FW_PROC "simplefirewall"

enum proc_type{
    add,
    delete,
    show
};

struct mutex proc_mutex;

static void get_path_type(struct file *file, enum F_IP_LIST_TYPE *listtype, enum proc_type *proctype)
{
    char *opsname;
    char *listname;
    opsname = file->f_path.dentry->d_iname;
    if( strcmp( opsname, "add") == 0) *proctype = add;
    else if( strcmp( opsname, "delete") == 0) *proctype = delete;
    else if( strcmp( opsname, "show") == 0) *proctype = show;

    listname = file->f_path.dentry->d_parent->d_iname;
    if( strcmp( listname, "whitelist") == 0) *listtype= F_IP_WHITELIST;
    else if( strcmp( listname, "blacklist") == 0) *listtype= F_IP_BLACKLIST;
    logs("%s %s", listname, opsname);
}


static ssize_t ip_read(struct file *file, char __user *user_buffer, size_t count, loff_t *ppos)
{
    ssize_t ret;
    enum F_IP_LIST_TYPE listtype;
    enum proc_type proctype;
    struct page *pages;
    void *data;
    int pagenum = 3;
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

static ssize_t ip_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos)
{
    char *buffer;
    ssize_t ret;
    u32 ip;
    char *p;
    ip_desc desc;
    enum F_IP_LIST_TYPE listtype;
    enum proc_type proctype;

    get_path_type(file, &listtype, &proctype);
    if( proctype >= show ){
        logs("Not allowed to write");
        return -EFAULT;
    }
    buffer = kmalloc(4096, GFP_KERNEL);
    if (count > 4096) {
        // Limit the write count to the size of the buffer
        count = 4095;
    }

    ret = copy_from_user(buffer, user_buffer, count);
    if (ret != 0) {
        return -EFAULT;
    } 
    buffer[count] = 0;
    *ppos = count;

    mutex_lock(&proc_mutex);
	while ((p = strsep(&buffer, " |\n|\t|,")) != NULL) {
        if(in4_pton(p, -1, (u8 *)&ip, -1, NULL) == 0){
            if( strlen( p ) > 0 )
                logs("Fails to parse %s", p);
            continue;
        }
        desc.flags = 0;
        if( listtype == F_IP_WHITELIST ) desc.flags |= IP_WHITELIST_MASK;
        else if( listtype == F_IP_BLACKLIST ) desc.flags |= IP_BLACKLIST_MASK;
        else {
            logs("Wrong list type");
            continue;
        }
        switch( proctype ){
            case add:
                insert_ip( ip, &desc);
                break;
            case delete:
                delete_ip( ip, &desc);
                break;
            case show:
                break;
        }
	}
    kfree(buffer);
    mutex_unlock(&proc_mutex);
    return count;
}

static const struct file_operations ip_add_fops = {
    .owner = THIS_MODULE,
    .write = ip_write,
};

static const struct file_operations ip_delete_fops = {
    .owner = THIS_MODULE,
    .write = ip_write,
};

static const struct file_operations ip_show_fops = {
    .owner = THIS_MODULE,
    .read = ip_read,
};

struct fw_procfs_ops {
    char name[64];
    const struct file_operations add ;
    const struct file_operations delete;
    const struct file_operations show;
};

struct fw_procfs_ops ip_ops = {
    .name = "ip",
    .add = ip_add_fops,
    .delete = ip_delete_fops,
    .show = ip_show_fops,
};

static void create_proc_tree( struct fw_procfs_ops *ops )
{
    struct proc_dir_entry *folder;
    char path[100];
    folder= proc_mkdir(FW_PROC, NULL);
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
    create_proc_tree( &ip_ops );
    return 0;
}

void fw_proc_exit( void )
{
    destroy_proc_tree( "ip" );
    remove_proc_subtree(FW_PROC, NULL);
}

