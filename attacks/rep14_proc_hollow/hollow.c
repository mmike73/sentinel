#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <errno.h>

int main(void)
{
    printf("[REP-14] Stage 1: fork() victim process — fires clone kprobe (56)\n");

    pid_t victim = fork();

    if (victim == 0) {
        printf("[REP-14] Victim PID=%d running (waiting to be hollowed)\n", getpid());
        for (;;) pause();
        exit(0);
    }

    printf("[REP-14] Attacker PID=%d, victim PID=%d\n", getpid(), victim);
    usleep(100000);

    printf("[REP-14] Stage 2: ptrace(PTRACE_ATTACH) — fires ProcessInjection kprobe (101)\n");
    if (ptrace(PTRACE_ATTACH, victim, NULL, NULL) < 0) {
        perror("ptrace ATTACH");
        kill(victim, SIGKILL);
        waitpid(victim, NULL, 0);
        return 1;
    }

    int status;
    waitpid(victim, &status, 0);
    printf("[REP-14] Victim stopped (SIGSTOP delivered by ptrace)\n");

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, victim, NULL, &regs);
    printf("[REP-14] Victim RIP=0x%llx RSP=0x%llx\n", regs.rip, regs.rsp);

    printf("[REP-14] Stage 3: mmap(RWX) in attacker's space — fires MemoryInjection kprobe (9)\n");
    void *inject_buf = mmap(NULL, 4096,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (inject_buf == MAP_FAILED) {
        perror("mmap");
    } else {
        unsigned char payload[] = {
            0x90,0x90,0x90,0x90,
            0xc3
        };
        memcpy(inject_buf, payload, sizeof(payload));
        mprotect(inject_buf, 4096, PROT_READ | PROT_EXEC);
        printf("[REP-14] RWX buffer at %p — would contain shellcode in real attack\n",
               inject_buf);
        ((void(*)(void))inject_buf)();
        munmap(inject_buf, 4096);
    }

    printf("[REP-14] Stage 4: ptrace(PTRACE_DETACH) — clean exit\n");
    ptrace(PTRACE_DETACH, victim, NULL, NULL);

    kill(victim, SIGKILL);
    waitpid(victim, NULL, 0);

    printf("[REP-14] Process hollowing chain complete: clone+ptrace+mmap fired\n");
    return 0;
}
