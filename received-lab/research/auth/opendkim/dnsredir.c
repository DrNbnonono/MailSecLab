#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

__attribute__((constructor)) static void mark_loaded(void) {
    char buf[64];
    int n = snprintf(buf, sizeof buf, "pid %d\n", (int)getpid());
    int fd = open("/tmp/dnsredir-loaded", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0 && n > 0) {
        write(fd, buf, (size_t)n);
        close(fd);
    }
}

/* Lab overlay: this process's port-53 packets go to the local forwarder. */
static void fix(struct sockaddr *sa) {
    struct sockaddr_in *in;
    if (sa == 0 || sa->sa_family != AF_INET)
        return;
    in = (struct sockaddr_in *)sa;
    if (ntohs(in->sin_port) == 53)
        inet_pton(AF_INET, "127.0.0.1", &in->sin_addr);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               __CONST_SOCKADDR_ARG addr, socklen_t alen) {
    static ssize_t (*real_sendto)(int, const void *, size_t, int, __CONST_SOCKADDR_ARG, socklen_t);
    if (!real_sendto)
        real_sendto = dlsym(RTLD_NEXT, "sendto");
    fix((struct sockaddr *)addr.__sockaddr__);
    return real_sendto(fd, buf, len, flags, addr, alen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
    if (!real_sendmsg)
        real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    if (msg && msg->msg_name)
        fix(msg->msg_name);
    return real_sendmsg(fd, msg, flags);
}

int sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
    static int (*real_sendmmsg)(int, struct mmsghdr *, unsigned int, int);
    unsigned int i;
    if (!real_sendmmsg)
        real_sendmmsg = dlsym(RTLD_NEXT, "sendmmsg");
    for (i = 0; i < vlen; i++) {
        if (msgvec[i].msg_hdr.msg_name)
            fix(msgvec[i].msg_hdr.msg_name);
    }
    return real_sendmmsg(fd, msgvec, vlen, flags);
}

long syscall(long number, ...) {
    static long (*real_syscall)(long, ...);
    va_list ap;
    long a1, a2, a3, a4, a5, a6;
    if (!real_syscall)
        real_syscall = dlsym(RTLD_NEXT, "syscall");
    va_start(ap, number);
    a1 = va_arg(ap, long);
    a2 = va_arg(ap, long);
    a3 = va_arg(ap, long);
    a4 = va_arg(ap, long);
    a5 = va_arg(ap, long);
    a6 = va_arg(ap, long);
    va_end(ap);
    if (number == SYS_connect)
        fix((struct sockaddr *)a2);
    else if (number == SYS_sendto)
        fix((struct sockaddr *)a5);
    else if (number == SYS_sendmsg) {
        struct msghdr *msg = (struct msghdr *)a2;
        if (msg && msg->msg_name)
            fix(msg->msg_name);
    }
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}

int connect(int fd, __CONST_SOCKADDR_ARG addr, socklen_t alen) {
    static int (*real_connect)(int, __CONST_SOCKADDR_ARG, socklen_t);
    if (!real_connect)
        real_connect = dlsym(RTLD_NEXT, "connect");
    fix((struct sockaddr *)addr.__sockaddr__);
    return real_connect(fd, addr, alen);
}
