#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define C2_IP    "203.0.113.200"
#define C2_PORT  4444
#define ATTEMPTS 6

int main(void)
{
    struct sockaddr_in c2;
    memset(&c2, 0, sizeof(c2));
    c2.sin_family = AF_INET;
    c2.sin_port   = htons(C2_PORT);
    inet_pton(AF_INET, C2_IP, &c2.sin_addr);

    printf("[REP-15] Simulating reverse shell reconnect loop to %s:%d\n", C2_IP, C2_PORT);

    for (int i = 0; i < ATTEMPTS; i++) {
        int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sock < 0) { perror("socket"); continue; }

        connect(sock, (struct sockaddr *)&c2, sizeof(c2));
        printf("[REP-15] connect attempt %d/%d (EINPROGRESS expected)\n", i+1, ATTEMPTS);
        close(sock);
    }

    printf("[REP-15] Stage 3: execve(/bin/echo) — fires ParentChildAnomaly kprobe (59)\n");
    char *argv[] = { "/bin/echo", "[REP-15] reverse shell payload executed", NULL };
    char *envp[] = { NULL };
    execve("/bin/echo", argv, envp);

    perror("execve");
    return 1;
}
