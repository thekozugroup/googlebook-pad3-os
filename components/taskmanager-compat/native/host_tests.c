#define _GNU_SOURCE
#include "metrics.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); abort(); } } while (0)

static void fixture(const char *path, const char *data, size_t size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, data, size) == (ssize_t)size);
    CHECK(close(fd) == 0);
}

static void sample(char *text, size_t size, const char *user, const char *system, const char *start) {
    int n = snprintf(text, size, "321 (name ) with ( spaces\nand newline) S 1 2 3 4 5 6 7 8 9 10 %s %s -1 -2 -3 -4 1 0 %s 0\n",
            user, system, start);
    CHECK(n > 0 && (size_t)n < size);
}

static void put32(unsigned char *p, uint32_t x) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(x >> (24 - 8 * i));
}
static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint64_t get64(const unsigned char *p) { return (uint64_t)get32(p) << 32 | get32(p + 4); }

static size_t exchange(int proc, uid_t uid, const unsigned char *request, size_t size,
        int half_close, unsigned char response[TM_RESPONSE_BYTES]) {
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    uid_t actual;
    CHECK(tm_peer_uid(pair[0], &actual) == 0 && actual == geteuid());
    struct timeval timeout = {.tv_sec = 2};
    CHECK(setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(pair[0]);
        /* Simulate Android SO_PEERCRED UIDs only at this function boundary. Production main
         * always obtains the UID from getsockopt and has no UID/proc-root argument. */
        (void)tm_serve_client(pair[1], proc, uid);
        close(pair[1]);
        _exit(0);
    }
    close(pair[1]);
    if (size) {
        ssize_t sent = send(pair[0], request, size, 0);
        CHECK(sent == (ssize_t)size || (!tm_allowed_uid(uid) && sent == -1 && errno == EPIPE));
    }
    if (half_close) (void)shutdown(pair[0], SHUT_WR);
    size_t used = 0;
    while (used < TM_RESPONSE_BYTES) {
        ssize_t n = read(pair[0], response + used, TM_RESPONSE_BYTES - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == ECONNRESET && !used) break;
        CHECK(n >= 0);
        if (!n) break;
        used += (size_t)n;
    }
    close(pair[0]);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return used;
}

int main(int argc, char **argv) {
    CHECK(argc == 3);
    CHECK(chdir(argv[1]) == 0);
    CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    char text[TM_STAT_BYTES];
    struct tm_stat stat;
    sample(text, sizeof(text), "70", "13", "800");
    CHECK(tm_parse_stat(321, text, strlen(text), &stat) == 0);
    CHECK(stat.user == 70 && stat.system == 13 && stat.start == 800);
    CHECK(tm_parse_stat(322, text, strlen(text), &stat) != 0);
    CHECK(tm_parse_stat(0, text, strlen(text), &stat) != 0);
    CHECK(tm_parse_stat(UINT32_MAX, text, strlen(text), &stat) != 0);
    CHECK(tm_parse_stat(321, "321 (cut) S 0", 13, &stat) != 0);
    CHECK(tm_parse_stat(321, "321 (cut)", 9, &stat) != 0);
    sample(text, sizeof(text), "9223372036854775807", "4294967296", "800");
    CHECK(tm_parse_stat(321, text, strlen(text), &stat) == 0 && stat.user == INT64_MAX && stat.system == UINT64_C(4294967296));
    for (unsigned i = 0; i < 3; ++i) {
        const char *bad[] = {"-1", "9223372036854775808", "+1"};
        sample(text, sizeof(text), bad[i], "13", "800");
        CHECK(tm_parse_stat(321, text, strlen(text), &stat) != 0);
        sample(text, sizeof(text), "70", bad[i], "800");
        CHECK(tm_parse_stat(321, text, strlen(text), &stat) != 0);
        sample(text, sizeof(text), "70", "13", bad[i]);
        CHECK(tm_parse_stat(321, text, strlen(text), &stat) != 0);
    }
    sample(text, sizeof(text), "70", "13", "800");
    size_t length = strlen(text);
    text[15] = 0;
    CHECK(tm_parse_stat(321, text, length, &stat) != 0);
    CHECK(mkdir("321", 0700) == 0);
    sample(text, sizeof(text), "70", "13", "800");
    fixture("321/stat", text, strlen(text));
    int proc = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(proc >= 0);
    CHECK(tm_read_stat(proc, 321, &stat) == TM_OK && stat.user == 70 && stat.start == 800);
    if (geteuid() != 0) {
        CHECK(chmod("321/stat", 0000) == 0);
        CHECK(tm_read_stat(proc, 321, &stat) == TM_DENIED);
        CHECK(chmod("321/stat", 0600) == 0);
    }
    CHECK(tm_read_stat(proc, 987654, &stat) == TM_GONE);
    CHECK(tm_read_stat(proc, 0, &stat) == TM_BAD_REQUEST);
    CHECK(tm_read_stat(proc, UINT32_MAX, &stat) == TM_BAD_REQUEST);
    CHECK(symlink("321", "77") == 0);
    CHECK(tm_read_stat(proc, 77, &stat) == TM_UNAVAILABLE);
    CHECK(mkdir("88", 0700) == 0 && symlink("../321/stat", "88/stat") == 0);
    CHECK(tm_read_stat(proc, 88, &stat) == TM_UNAVAILABLE);
    CHECK(mkdir("99", 0700) == 0 && mkdir("99/stat", 0700) == 0);
    CHECK(tm_read_stat(proc, 99, &stat) == TM_UNAVAILABLE);
    CHECK(mkdir("66", 0700) == 0 && mkfifo("66/stat", 0600) == 0);
    CHECK(tm_read_stat(proc, 66, &stat) == TM_UNAVAILABLE);
    memset(text, '1', sizeof(text));
    fixture("321/stat", text, sizeof(text));
    CHECK(tm_read_stat(proc, 321, &stat) == TM_UNAVAILABLE);
    sample(text, sizeof(text), "70", "13", "800");
    fixture("321/stat", text, strlen(text));
    CHECK(tm_allowed_uid(1000) && tm_allowed_uid(1001000) && tm_allowed_uid(1101000));
    CHECK(!tm_allowed_uid(0) && !tm_allowed_uid(2000) && !tm_allowed_uid(10192) && !tm_allowed_uid(1001001));

    unsigned char request[13] = {0}, response[TM_RESPONSE_BYTES];
    put32(request, TM_MAGIC); put32(request + 4, 1); put32(request + 8, 321);
    for (unsigned i = 0; i < 3; ++i) {
        uid_t uid[] = {1000, 1001000, 1101000};
        CHECK(exchange(proc, uid[i], request, 12, 1, response) == 40);
        CHECK(get32(response) == TM_MAGIC && get32(response + 4) == TM_OK && get32(response + 8) == 321);
        CHECK(get32(response + 12) == 0 && get64(response + 16) == 70 && get64(response + 24) == 13 && get64(response + 32) == 800);
    }
    fixture(argv[2], (const char *)response, sizeof(response));
    for (unsigned i = 0; i < 5; ++i) {
        uid_t uid[] = {0, 2000, 10192, 1001001, geteuid()};
        if (!tm_allowed_uid(uid[i])) CHECK(exchange(proc, uid[i], request, 12, 1, response) == 0);
    }
    CHECK(exchange(proc, 1001000, request, 5, 1, response) == 0);
    CHECK(exchange(proc, 1001000, request, 13, 1, response) == 0);
    struct timespec before, after;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    CHECK(exchange(proc, 1001000, request, 12, 0, response) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    int64_t elapsed = (after.tv_sec - before.tv_sec) * 1000 + (after.tv_nsec - before.tv_nsec) / 1000000;
    CHECK(elapsed >= TM_TIMEOUT_MS - 50 && elapsed < 2000);
    for (unsigned i = 0; i < 4; ++i) {
        put32(request, i == 0 ? 0 : TM_MAGIC);
        put32(request + 4, i == 1 ? 2 : 1);
        put32(request + 8, i == 2 ? 0 : i == 3 ? UINT32_MAX : 321);
        CHECK(exchange(proc, 1001000, request, 12, 1, response) == 40 && get32(response + 4) == TM_BAD_REQUEST);
        CHECK(get64(response + 16) == 0 && get64(response + 24) == 0 && get64(response + 32) == 0);
    }
    put32(request, TM_MAGIC); put32(request + 4, 1); put32(request + 8, 987654);
    CHECK(exchange(proc, 1001000, request, 12, 1, response) == 40 && get32(response + 4) == TM_GONE);
    CHECK(get64(response + 16) == 0 && get64(response + 24) == 0 && get64(response + 32) == 0);
    CHECK(close(proc) == 0);
    printf("C host checks: %u; absolute deadline: %lld ms\n", checks, (long long)elapsed);
    return 0;
}
