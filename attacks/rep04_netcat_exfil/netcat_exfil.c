#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TARGET_IP   "203.0.113.100"
#define TARGET_PORT 4444
#define BURST_N     6

int main(void)
{
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(TARGET_PORT);
    inet_pton(AF_INET, TARGET_IP, &dst.sin_addr);

    printf("[REP-04] Burst-exfil to %s:%d (%d attempts, non-blocking)\n",
           TARGET_IP, TARGET_PORT, BURST_N);

    for (int i = 0; i < BURST_N; i++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) { perror("socket"); continue; }
        connect(fd, (struct sockaddr *)&dst, sizeof(dst));
        close(fd);
    }

    printf("[REP-04] Done: socket+connect fired %d times from PID %d\n",
           BURST_N, (int)getpid());
    return 0;
}
