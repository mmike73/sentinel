#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>

struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u32 syscall_nr;
    char  comm[16];
    char  fname[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} pid_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC(".maps");

static __always_inline int submit_event(__u32 syscall_nr)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&pid_blacklist, &pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&drop_count, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return 0;
    }

    e->ts_ns      = bpf_ktime_get_ns();
    e->pid        = pid;
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->syscall_nr = syscall_nr;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->fname[0]   = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int submit_event_with_path(__u32 syscall_nr,
                                                   struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&pid_blacklist, &pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&drop_count, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return 0;
    }

    e->ts_ns      = bpf_ktime_get_ns();
    e->pid        = pid;
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->syscall_nr = syscall_nr;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->fname[0]   = '\0';

    struct pt_regs *inner = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long fname_uptr = 0;
    bpf_probe_read_kernel(&fname_uptr, sizeof(fname_uptr), &inner->rsi);
    if (fname_uptr)
        bpf_probe_read_user_str(e->fname, sizeof(e->fname),
                                (const char *)fname_uptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_write")
int kp_write(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&pid_blacklist, &pid))
        return 0;

    struct pt_regs *inner = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long fd_val = 0;
    bpf_probe_read_kernel(&fd_val, sizeof(fd_val), &inner->rdi);
    if (fd_val < 3)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns      = bpf_ktime_get_ns();
    e->pid        = pid;
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->syscall_nr = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->fname[0] = 'f'; e->fname[1] = 'd'; e->fname[2] = ':';
    __u32 f = (__u32)fd_val;
    char digits[10] = {};
    int n = 0;
    if (f == 0) {
        e->fname[3] = '0'; e->fname[4] = '\0';
    } else {
        __u32 tmp = f;
        for (int i = 0; i < 9 && tmp > 0; i++) {
            digits[n++] = '0' + (tmp % 10);
            tmp /= 10;
        }
        for (int i = 0; i < n && i < 9; i++)
            e->fname[3 + i] = digits[n - 1 - i];
        e->fname[3 + n] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_execve")        int kp_execve(struct pt_regs *ctx)       { return submit_event(59);  }
SEC("kprobe/__x64_sys_execveat")      int kp_execveat(struct pt_regs *ctx)     { return submit_event(322); }
SEC("kprobe/__x64_sys_clone")         int kp_clone(struct pt_regs *ctx)        { return submit_event(56);  }
SEC("kprobe/__x64_sys_setuid")        int kp_setuid(struct pt_regs *ctx)       { return submit_event(105); }
SEC("kprobe/__x64_sys_setgid")        int kp_setgid(struct pt_regs *ctx)       { return submit_event(106); }
SEC("kprobe/__x64_sys_capset")        int kp_capset(struct pt_regs *ctx)       { return submit_event(126); }
SEC("kprobe/__x64_sys_ptrace")        int kp_ptrace(struct pt_regs *ctx)       { return submit_event(101); }
SEC("kprobe/__x64_sys_mmap")          int kp_mmap(struct pt_regs *ctx)         { return submit_event(9);   }
SEC("kprobe/__x64_sys_mprotect")      int kp_mprotect(struct pt_regs *ctx)     { return submit_event(10);  }
SEC("kprobe/__x64_sys_socket")        int kp_socket(struct pt_regs *ctx)       { return submit_event(41);  }
SEC("kprobe/__x64_sys_connect")       int kp_connect(struct pt_regs *ctx)      { return submit_event(42);  }
SEC("kprobe/__x64_sys_bind")          int kp_bind(struct pt_regs *ctx)         { return submit_event(49);  }
SEC("kprobe/__x64_sys_init_module")   int kp_init_module(struct pt_regs *ctx)  { return submit_event(175); }
SEC("kprobe/__x64_sys_finit_module")  int kp_finit_module(struct pt_regs *ctx) { return submit_event(313); }
SEC("kprobe/__x64_sys_delete_module") int kp_delete_module(struct pt_regs *ctx){ return submit_event(176); }
SEC("kprobe/__x64_sys_kill")          int kp_kill(struct pt_regs *ctx)         { return submit_event(62);  }

SEC("kprobe/__x64_sys_openat")    int kp_openat(struct pt_regs *ctx)    { return submit_event_with_path(257, ctx); }
SEC("kprobe/__x64_sys_unlinkat")  int kp_unlinkat(struct pt_regs *ctx)  { return submit_event_with_path(263, ctx); }
SEC("kprobe/__x64_sys_renameat2") int kp_renameat2(struct pt_regs *ctx) { return submit_event_with_path(316, ctx); }

char _license[] SEC("license") = "GPL";
