#include <linux/module.h>
#include <linux/kernel.h>

static int __init persist_mod_init(void)
{
    printk(KERN_INFO "sentinel_rep17: finit_module loaded (harmless persistence test)\n");
    return 0;
}

static void __exit persist_mod_exit(void)
{
    printk(KERN_INFO "sentinel_rep17: finit_module unloaded\n");
}

module_init(persist_mod_init);
module_exit(persist_mod_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Harmless LKM for finit_module (fd-based) detection testing");
