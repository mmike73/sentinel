#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

#define SIGNAL_HIDE_MODULE   31
#define SIGNAL_HIDE_PROCESS  63
#define SIGNAL_GET_ROOT      64

static int kprobe_kill_pre(struct kprobe *p, struct pt_regs *regs)
{
    int sig = (int)regs->si;

    switch (sig) {
    case SIGNAL_GET_ROOT:
        pr_warn("sentinel_rep18: BACKDOOR signal %d - would commit_creds(prepare_kernel_cred(0)) [blocked]\n", sig);
        break;
    case SIGNAL_HIDE_PROCESS:
        pr_warn("sentinel_rep18: BACKDOOR signal %d - would list_del from /proc task list [blocked]\n", sig);
        break;
    case SIGNAL_HIDE_MODULE:
        pr_warn("sentinel_rep18: BACKDOOR signal %d - would list_del(&THIS_MODULE->list) [blocked]\n", sig);
        break;
    }
    return 0;
}

static struct kprobe kill_kp = {
    .symbol_name = "__x64_sys_kill",
    .pre_handler = kprobe_kill_pre,
};

static int __init hook_init(void)
{
    int ret = register_kprobe(&kill_kp);
    if (ret < 0) {
        printk(KERN_ERR "sentinel_rep18: register_kprobe failed: %d\n", ret);
        return ret;
    }
    pr_warn("sentinel_rep18: SYSCALL HOOK ACTIVE - __x64_sys_kill intercepted at %p\n", kill_kp.addr);
    pr_warn("sentinel_rep18: Awaiting magic signals 31/63/64 for backdoor commands\n");
    return 0;
}

static void __exit hook_exit(void)
{
    unregister_kprobe(&kill_kp);
    printk(KERN_INFO "sentinel_rep18: kprobe hook unregistered\n");
}

module_init(hook_init);
module_exit(hook_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Reptile-style signal-backdoor kprobe hook (detection test REP-18)");
