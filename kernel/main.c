#include <linux/module.h>
#include "ip.h" 
#include "procfs.h" 
#include "netfilter.h" 


static int __init fw_module_init(void)
{
    init_iptree();
    fw_proc_init();
    fw_net_init();
    printk(KERN_INFO "simplefirewall initialized\n");
    return 0;
}

static void __exit fw_module_exit(void)
{   
    fw_net_exit();
    fw_proc_exit();
    destroy_iptree();
    printk(KERN_INFO "simplefirewall exited\n");
}

module_init(fw_module_init);
module_exit(fw_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("simplefirewall, hooked in netfilter, created by foolfoot");
