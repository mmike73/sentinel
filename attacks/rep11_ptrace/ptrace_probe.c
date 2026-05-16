#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <pid>\n", argv[0]); return 1; }
    pid_t target = atoi(argv[1]);

    printf("PTRACE_ATTACH to PID %d — fires kprobe nr 101\n", target);
    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
        perror("ptrace ATTACH failed (kprobe still fired)");
        return 0;
    }

    int status;
    waitpid(target, &status, 0);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, target, NULL, &regs);
    printf("RIP = 0x%llx (kprobe fired, no shellcode injected)\n", regs.rip);

    ptrace(PTRACE_DETACH, target, NULL, NULL);
    printf("Detached safely\n");
    return 0;
}
