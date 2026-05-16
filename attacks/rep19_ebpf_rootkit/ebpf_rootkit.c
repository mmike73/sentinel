#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>

int main(void)
{
    signal(SIGALRM, SIG_DFL);
    alarm(20);

    printf("[REP-19] === eBPF rootkit loader (TripleCross-style) ===\n");

    printf("[REP-19] Stage 1: AF_PACKET raw socket — C&C channel — fires socket kprobe (41)\n");
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
    if (raw_sock < 0) {
        printf("[REP-19] socket(AF_PACKET) failed: %s (kprobe still fired)\n", strerror(errno));
    } else {
        printf("[REP-19] Raw socket fd=%d — network interception active\n", raw_sock);
        close(raw_sock);
    }

    printf("[REP-19] Stage 2: memfd_create — stage BPF bytecode without a disk file — fires kprobe (322)\n");
    int memfd = (int)syscall(SYS_memfd_create, "ebpf_prog", 0);
    if (memfd < 0) {
        printf("[REP-19] memfd_create failed: %s\n", strerror(errno));
    } else {
        unsigned char bpf_nop[] = {
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        if (write(memfd, bpf_nop, sizeof(bpf_nop)) < 0)
            printf("[REP-19] memfd write failed: %s\n", strerror(errno));
        else
            printf("[REP-19] memfd=%d — BPF bytecode staged (no disk trace)\n", memfd);
    }

    printf("[REP-19] Stage 3: mmap(RWX) — BPF JIT output region — fires MemoryInjection kprobe (9)\n");
    void *jit_buf = mmap(NULL, 4096,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (jit_buf == MAP_FAILED) {
        printf("[REP-19] mmap failed: %s\n", strerror(errno));
    } else {
        unsigned char jit[] = {
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0xb8, 0x3c, 0x00, 0x00, 0x00,
            0x31, 0xff,
            0xc3
        };
        memcpy(jit_buf, jit, sizeof(jit));
        mprotect(jit_buf, 4096, PROT_READ | PROT_EXEC);
        printf("[REP-19] JIT buffer at %p — BPF helper stubs would land here\n", jit_buf);
        munmap(jit_buf, 4096);
    }

    printf("[REP-19] Stage 4: fork + ptrace(PTRACE_ATTACH) — fires ProcessInjection kprobe (101)\n");
    pid_t victim = fork();
    if (victim == 0) {
        volatile char creds[] = "AUTH_TOKEN=ebpf_rootkit_test COOKIE=sentinel_rep19";
        (void)creds;
        usleep(1000000);
        exit(0);
    }

    usleep(200000);

    if (ptrace(PTRACE_ATTACH, victim, NULL, NULL) == 0) {
        int st;
        waitpid(victim, &st, 0);
        printf("[REP-19] ptrace ATTACHED to victim PID=%d — "
               "eBPF rootkit owns the process\n", victim);
        ptrace(PTRACE_DETACH, victim, NULL, NULL);
    } else {
        printf("[REP-19] ptrace failed: %s (ProcessInjection kprobe still fired)\n",
               strerror(errno));
    }
    kill(victim, SIGKILL);
    waitpid(victim, NULL, 0);

    if (memfd >= 0) close(memfd);

    printf("[REP-19] eBPF rootkit chain complete: socket+memfd+mmap+ptrace fired\n");
    return 0;
}
