#define _GNU_SOURCE
#include "metrics.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int tm_allowed_uid(uid_t uid) { return uid % 100000 == 1000; }

int tm_peer_uid(int fd, uid_t *uid) {
#ifdef __linux__
    struct ucred peer;
    socklen_t n = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &n) || n != sizeof(peer)) return -1;
    *uid = peer.uid;
    return 0;
#else
    /* Host tests only; production is compiled for Android/Linux. */
    gid_t gid;
    return getpeereid(fd, uid, &gid);
#endif
}

static int decimal(const char *s, size_t n, uint64_t *out) {
    if (!n) return -1;
    uint64_t value = 0;
    for (size_t i = 0; i < n; ++i) {
        if (s[i] < '0' || s[i] > '9') return -1;
        unsigned digit = (unsigned)(s[i] - '0');
        if (value > ((uint64_t)INT64_MAX - digit) / 10) return -1;
        value = value * 10 + digit;
    }
    *out = value;
    return 0;
}

static int space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

int tm_parse_stat(uint32_t pid, const char *text, size_t size, struct tm_stat *out) {
    if (!pid || pid > INT32_MAX || !size || size >= TM_STAT_BYTES || memchr(text, 0, size)) return -1;
    const char *end = text + size, *open = memchr(text, ' ', size), *close = NULL;
    uint64_t actual;
    if (!open || decimal(text, (size_t)(open - text), &actual) || actual != pid ||
            open + 1 >= end || open[1] != '(') return -1;
    /* comm may contain spaces, parentheses and newlines. Its last ')' ends field 2. */
    for (const char *p = open + 2; p < end; ++p) if (*p == ')') close = p;
    if (!close || end - close < 3 || close[1] != ' ') return -1;
    const char *p = close + 2;
    struct tm_stat sample = {0};
    for (unsigned field = 3; field <= 22; ++field) {
        const char *start = p;
        while (p < end && !space(*p)) ++p;
        size_t n = (size_t)(p - start);
        if (!n || (field == 3 && n != 1)) return -1;
        uint64_t *counter = field == 14 ? &sample.user : field == 15 ? &sample.system :
                field == 22 ? &sample.start : NULL;
        if (counter && decimal(start, n, counter)) return -1;
        while (p < end && space(*p)) ++p;
    }
    *out = sample;
    return 0;
}

static enum tm_status io_status(int error) {
    if (error == ENOENT || error == ESRCH) return TM_GONE;
    if (error == EACCES || error == EPERM) return TM_DENIED;
    return TM_UNAVAILABLE;
}

static enum tm_status read_stat_before(int proc_fd, uint32_t pid, struct tm_stat *out, int64_t deadline) {
    if (!pid || pid > INT32_MAX) return TM_BAD_REQUEST;
    char name[16];
    int length = snprintf(name, sizeof(name), "%u", pid);
    if (length <= 0 || (size_t)length >= sizeof(name)) return TM_BAD_REQUEST;
    /* Linux O_PATH traverses the fixed PID without requesting directory enumeration. */
#if defined(__linux__)
    int dir = openat(proc_fd, name, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
#else
    int dir = openat(proc_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
#endif
    if (dir < 0) return io_status(errno);
    int fd = openat(dir, "stat", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int error = errno;
    close(dir);
    if (fd < 0) return io_status(error);
    struct stat st;
    char text[TM_STAT_BYTES];
    size_t used = 0;
    enum tm_status status = TM_UNAVAILABLE;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) goto done;
    while (used < sizeof(text)) {
        int64_t now = now_ms();
        if (now < 0 || now >= deadline) goto done;
        ssize_t n = read(fd, text + used, sizeof(text) - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { status = io_status(errno); goto done; }
        if (!n) {
            if (!tm_parse_stat(pid, text, used, out)) status = TM_OK;
            goto done;
        }
        used += (size_t)n;
    }
done:
    close(fd);
    return status;
}

enum tm_status tm_read_stat(int proc_fd, uint32_t pid, struct tm_stat *out) {
    int64_t now = now_ms();
    if (now < 0) return TM_UNAVAILABLE;
    return read_stat_before(proc_fd, pid, out, now + TM_TIMEOUT_MS);
}

static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void put32(unsigned char *p, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(value >> (24 - 8 * i));
}

static void put64(unsigned char *p, uint64_t value) {
    put32(p, (uint32_t)(value >> 32));
    put32(p + 4, (uint32_t)value);
}

static int wait_io(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t now = now_ms();
        if (now < 0 || now >= deadline) return -1;
        struct pollfd p = {.fd = fd, .events = events};
        int result = poll(&p, 1, (int)(deadline - now));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || (p.revents & POLLNVAL)) return -1;
        return 0;
    }
}

static int transfer(int fd, unsigned char *bytes, size_t size, int sending, int64_t deadline) {
    size_t used = 0;
    while (used < size) {
        if (wait_io(fd, sending ? POLLOUT : POLLIN, deadline)) return -1;
#ifdef MSG_NOSIGNAL
        int flags = MSG_NOSIGNAL;
#else
        int flags = 0;
#endif
        ssize_t n = sending ? send(fd, bytes + used, size - used, flags) :
                recv(fd, bytes + used, size - used, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return -1;
        used += (size_t)n;
    }
    return 0;
}

int tm_serve_client(int fd, int proc_fd, uid_t peer_uid) {
    if (!tm_allowed_uid(peer_uid)) return -1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return -1;
    int64_t start = now_ms();
    if (start < 0) return -1;
    int64_t deadline = start + TM_TIMEOUT_MS;
    unsigned char request[TM_REQUEST_BYTES], response[TM_RESPONSE_BYTES] = {0};
    if (transfer(fd, request, sizeof(request), 0, deadline)) return -1;
    /* A request is exactly 12 bytes followed by shutdown(SHUT_WR), never a command stream. */
    if (wait_io(fd, POLLIN, deadline)) return -1;
    unsigned char extra;
    if (recv(fd, &extra, 1, 0) != 0) return -1;
    uint32_t pid = get32(request + 8);
    struct tm_stat sample = {0};
    enum tm_status status = TM_BAD_REQUEST;
    if (get32(request) == TM_MAGIC && get32(request + 4) == 1 && pid && pid <= INT32_MAX)
        status = read_stat_before(proc_fd, pid, &sample, deadline);
    put32(response, TM_MAGIC);
    put32(response + 4, (uint32_t)status);
    put32(response + 8, pid);
    if (status == TM_OK) {
        put64(response + 16, sample.user);
        put64(response + 24, sample.system);
        put64(response + 32, sample.start);
    }
    return transfer(fd, response, sizeof(response), 1, deadline);
}
