#include <linux/module.h>
#include <linux/kernel.h>

static int __init harmless_kernel_module_init(void)
{
    printk(KERN_INFO "harmless_kernel_module: loaded\n");
    return 0;
}

static void __exit harmless_kernel_module_exit(void)
{
    printk(KERN_INFO "harmless_kernel_module: unloaded\n");
    return;
}

module_init(harmless_kernel_module_init);
module_exit(harmless_kernel_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Harmless LKM rootkit detection testing");
