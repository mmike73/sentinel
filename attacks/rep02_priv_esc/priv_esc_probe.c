#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/capability.h>

int main(void) {
    printf("Calling setuid(0) — fires kprobe nr 105\n");
    if (setuid(0) == -1)
        printf("setuid(0) failed: EPERM (expected) — kprobe still fired\n");

    printf("Calling capset() — fires kprobe nr 126\n");
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid     = 0,
    };
    struct __user_cap_data_struct data[2] = {};
    if (syscall(SYS_capset, &hdr, data) == -1)
        printf("capset failed: EPERM (expected) — kprobe still fired\n");

    return 0;
}
