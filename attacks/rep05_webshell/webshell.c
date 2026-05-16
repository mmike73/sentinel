#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

static void shell_cmd(const char *path, char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        execve(path, argv, NULL);
        _exit(1);
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
    }
}

int main(void) {
    printf("[REP-05] Webshell running as comm=apache2-worker (PID=%d)\n", getpid());
    printf("[REP-05] Executing OS commands via execve — simulating RCE via web server\n");

    char *id_args[]   = { "/usr/bin/id",   NULL };
    char *cat_args[]  = { "/bin/cat",   "/etc/passwd", NULL };
    char *who_args[]  = { "/usr/bin/whoami", NULL };
    char *ls_args[]   = { "/bin/ls",    "/root",       NULL };

    shell_cmd("/usr/bin/id",      id_args);
    shell_cmd("/bin/cat",         cat_args);
    shell_cmd("/usr/bin/whoami",  who_args);
    shell_cmd("/bin/ls",          ls_args);

    printf("[REP-05] Done: execve kprobes fired 4x from comm=apache2-worker\n");
    return 0;
}
