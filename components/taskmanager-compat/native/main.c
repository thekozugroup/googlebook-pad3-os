#define _GNU_SOURCE
#include "metrics.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

static int identity_ok(void) {
    if (getuid() != 1000 || geteuid() != 1000 || getgid() != 1000 || getegid() != 1000) return 0;
    gid_t groups[4];
    int n = getgroups(4, groups), readproc = 0;
    if (n < 0) return 0;
    for (int i = 0; i < n; ++i) {
        if (groups[i] != 1000 && groups[i] != 3009) return 0;
        if (groups[i] == 3009) readproc = 1;
    }
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}};
    if (!readproc || syscall(SYS_capget, &header, caps)) return 0;
    for (unsigned i = 0; i < 2; ++i)
        if (caps[i].effective || caps[i].permitted || caps[i].inheritable) return 0;
    return 1;
}

static int init_socket(void) {
    const char *text = getenv("ANDROID_SOCKET_" TM_SOCKET_NAME);
    if (!text || !*text) return -1;
    for (const char *p = text; *p; ++p) if (*p < '0' || *p > '9') return -1;
    errno = 0;
    char *end;
    long number = strtol(text, &end, 10);
    if (errno || *end || number < 3 || number > 1023) return -1;
    int fd = (int)number, type, listening;
    socklen_t n = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &n) || type != SOCK_STREAM) return -1;
    n = sizeof(listening);
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &n) || listening) return -1;
    struct sockaddr_un address = {0};
    n = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &n) || address.sun_family != AF_UNIX ||
            memcmp(address.sun_path, TM_SOCKET_PATH, sizeof(TM_SOCKET_PATH))) return -1;
    /* Do not use init's stream+listen: the client must see the daemon's UID 1000. */
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) || listen(fd, 8)) return -1;
    return fd;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || !identity_ok() || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
            prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) return 1;
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 1;
    int server = init_socket();
    if (server < 0) return 1;
    int proc = open("/proc", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (proc < 0) return 1;
    for (;;) {
        int client = accept4(server, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (client < 0) {
            if (errno == EINTR) continue;
            close(proc);
            return 1; /* init applies its normal restart backoff; never busy-loop. */
        }
        uid_t uid;
        if (!tm_peer_uid(client, &uid)) (void)tm_serve_client(client, proc, uid);
        close(client);
    }
}
