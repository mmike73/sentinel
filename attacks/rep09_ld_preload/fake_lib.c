#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>

int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    fprintf(stderr, "[fake_lib] intercepted open: %s\n", pathname);
    va_list args;
    va_start(args, flags);
    int mode = va_arg(args, int);
    va_end(args);
    return real_open(pathname, flags, mode);
}

__attribute__((constructor))
void init(void) {
    fprintf(stderr, "[fake_lib] LOADED via LD_PRELOAD — hijacking open()\n");
}
