#ifndef GOOGLEBOOK_TASKMANAGER_METRICS_H
#define GOOGLEBOOK_TASKMANAGER_METRICS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TM_MAGIC UINT32_C(0x47544d31) /* GTM1, network byte order on the wire */
#define TM_REQUEST_BYTES 12
#define TM_RESPONSE_BYTES 40
#define TM_TIMEOUT_MS 500
#define TM_STAT_BYTES 4096
#define TM_SOCKET_NAME "googlebook_taskmanager_metrics"
#define TM_SOCKET_PATH "/dev/socket/" TM_SOCKET_NAME

enum tm_status { TM_OK, TM_GONE, TM_DENIED, TM_BAD_REQUEST, TM_UNAVAILABLE };
struct tm_stat { uint64_t user, system, start; };

int tm_allowed_uid(uid_t uid);
int tm_peer_uid(int fd, uid_t *uid);
int tm_parse_stat(uint32_t pid, const char *text, size_t size, struct tm_stat *out);
enum tm_status tm_read_stat(int proc_fd, uint32_t pid, struct tm_stat *out);
/* proc_fd is opened on /proc by main; only host tests supply a fixture root. */
int tm_serve_client(int fd, int proc_fd, uid_t peer_uid);

#endif
