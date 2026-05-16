#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <errno.h>

static const char *TARGETS[] = {
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/passwd",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/authorized_keys",
    "/root/.bash_history",
    "/home/vagrant/.bash_history",
    "/home/vagrant/.ssh/id_rsa",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/proc/1/mem",
    "/proc/1/maps",
    "/proc/keys",
    "/etc/sudoers",
    "/etc/crontab",
    "/run/secrets",
    NULL
};

int main(void)
{
    printf("[REP-16] Starting credential harvest — %d target paths\n",
           (int)(sizeof(TARGETS)/sizeof(TARGETS[0]) - 1));

    int opened = 0, denied = 0;

    for (int i = 0; TARGETS[i] != NULL; i++) {
        int fd = open(TARGETS[i], O_RDONLY);
        if (fd >= 0) {
            char buf[256];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                printf("[REP-16] HARVESTED: %s (%zd bytes)\n", TARGETS[i], n);
            }
            close(fd);
            opened++;
        } else {
            printf("[REP-16] DENIED: %s — %s (openat kprobe still fired)\n",
                   TARGETS[i], strerror(errno));
            denied++;
        }
    }

    printf("[REP-16] Walking /proc for process memory maps...\n");
    DIR *proc = opendir("/proc");
    if (proc) {
        struct dirent *ent;
        int proc_count = 0;
        while ((ent = readdir(proc)) != NULL && proc_count < 10) {
            if (ent->d_type == DT_DIR && ent->d_name[0] >= '1' && ent->d_name[0] <= '9') {
                char path[64];
                snprintf(path, sizeof(path), "/proc/%s/maps", ent->d_name);
                int fd = open(path, O_RDONLY);
                if (fd >= 0) {
                    close(fd);
                    proc_count++;
                }
            }
        }
        closedir(proc);
        printf("[REP-16] Opened %d /proc/<PID>/maps files\n", proc_count);
    }

    printf("[REP-16] Harvest complete: %d opened, %d denied\n", opened, denied);
    return 0;
}
