#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    void *region = mmap(NULL, 4096,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }
    unsigned char nop_sled[] = {
        0x90,0x90,0x90,0x90, 0x90,0x90,0x90,0x90,
        0x90,0x90,0x90,0x90, 0x90,0x90,0x90,0x90,
        0xC3
    };
    memcpy(region, nop_sled, sizeof(nop_sled));
    mprotect(region, 4096, PROT_READ | PROT_EXEC);
    ((void(*)(void))region)();
    munmap(region, 4096);
    printf("NOP sled executed safely\n");
    return 0;
}
