/*
 * An LD_PRELOAD object for scripts/restricted-host.sh (issue 217).
 *
 * bind() of an AF_INET or AF_INET6 address fails with EACCES, as on a host
 * whose seccomp filter or LSM refuses it. Other families (AF_UNIX) go to
 * the bind() of the C library.
 *
 *   cc -shared -fPIC -o deny-bind.so scripts/deny-bind.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    static int (*next)(int, const struct sockaddr *, socklen_t);
    if (addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        errno = EACCES;
        return -1;
    }
    if (!next) {
        next = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "bind");
    }
    if (!next) {
        errno = ENOSYS;
        return -1;
    }
    return next(fd, addr, len);
}
