#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

static struct kprobe kp = {
    .symbol_name = "do_sys_openat2",
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk(KERN_INFO "SENTINEL: pid=%d comm=%s opened a file\n", current->pid, current->comm);
    return 0;
}

static int __init tracer_init(void)
{
    kp.pre_handler = handler_pre;
    register_kprobe(&kp);
    printk(KERN_INFO "SENTINEL: tracer loaded\n");
    return 0;
}

static void __exit tracer_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "SENTINEL: tracer unloaded\n");
}

module_init(tracer_init);
module_exit(tracer_exit);
MODULE_LICENSE("GPL");
