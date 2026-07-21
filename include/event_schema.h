#ifndef VISHAYA_EVENT_SCHEMA_H
#define VISHAYA_EVENT_SCHEMA_H

/*
 * File Notes:
 * - Defines the binary event contract shared by kernel eBPF producer and C++ consumers.
 * - Field order and width are ABI-sensitive: changing them can break decode compatibility.
 */

#ifndef __BPF__
#include <stdint.h>
#else
/* vmlinux.h provides __u/__s types but not the C-standard uint*_t names.
 * Define them here so this header compiles in both BPF and userspace contexts. */
#ifndef __VISHAYA_BPF_STDINT
#define __VISHAYA_BPF_STDINT
typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s8  int8_t;
typedef __s16 int16_t;
typedef __s32 int32_t;
typedef __s64 int64_t;
#endif /* __VISHAYA_BPF_STDINT */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Fixed process command-name length in event payloads. */
#define VISHAYA_COMM_LEN 16
/** @brief Fixed path buffer length used by process/file payload fields. */
#define VISHAYA_PATH_LEN 256
/** @brief Fixed pathname buffer length for UNIX domain socket endpoints. */
#define VISHAYA_UNIX_PATH_LEN 108
/** @brief Bounded payload prefix captured for send/recv network events (v0.1). */
#define VISHAYA_NET_PAYLOAD_LEN 128

/**
 * @brief Top-level event family identifiers.
 */
enum event_type {
  EVENT_TYPE_PROCESS = 1,
  EVENT_TYPE_FILE = 2,
  EVENT_TYPE_SYSCALL = 3,
  EVENT_TYPE_NETWORK = 4,
};

/**
 * @brief Process lifecycle event subtypes.
 */
enum process_event_kind {
  PROCESS_EXEC = 1,
  PROCESS_FORK = 2,
  PROCESS_EXIT = 3,
  PROCESS_CLONE = 4,
  PROCESS_CLONE3 = 5,
  PROCESS_VFORK = 6,
};

/**
 * @brief File operation event subtypes.
 */
enum file_event_kind {
  FILE_OPENAT = 1,
  FILE_UNLINKAT = 2,
  FILE_RENAMEAT2 = 3,
};

/**
 * @brief Socket-centric network event subtypes.
 *
 * Control-plane kinds come first so kernel and userspace can evolve the socket
 * layer incrementally without renumbering earlier records.
 */
enum network_event_kind {
  NETWORK_SOCKET = 1,
  NETWORK_CONNECT = 2,
  NETWORK_ACCEPT = 3,
  NETWORK_BIND = 4,
  NETWORK_LISTEN = 5,
  NETWORK_CLOSE = 6,
  NETWORK_SENDTO = 7,
  NETWORK_RECVFROM = 8,
  NETWORK_SHUTDOWN = 9,
  NETWORK_SOCKETPAIR = 10,
  NETWORK_ACCEPT4 = 11,
  NETWORK_GETSOCKNAME = 12,
  NETWORK_GETPEERNAME = 13,
  NETWORK_SETSOCKOPT = 14,
  NETWORK_GETSOCKOPT = 15,
  NETWORK_SENDMSG = 16,
  NETWORK_RECVMSG = 17,
  NETWORK_READ = 18,
  NETWORK_WRITE = 19,
  NETWORK_READV = 20,
  NETWORK_WRITEV = 21,
  NETWORK_SENDMMSG = 22,
  NETWORK_RECVMMSG = 23,
};

enum network_event_direction {
  NETWORK_DIRECTION_UNKNOWN = 0,
  NETWORK_DIRECTION_INBOUND = 1,
  NETWORK_DIRECTION_OUTBOUND = 2,
};

enum network_transport {
  NETWORK_TRANSPORT_UNKNOWN = 0,
  NETWORK_TRANSPORT_TCP = 1,
  NETWORK_TRANSPORT_UDP = 2,
  NETWORK_TRANSPORT_UNIX = 3,
  NETWORK_TRANSPORT_RAW = 4,
};

/**
 * @brief Common event envelope present in every event payload.
 *
 * Contains identity/time metadata used by all downstream processing stages.
 */
struct event_header {
  uint64_t ts_ns;
  uint32_t type;
  uint32_t size;
  uint32_t pid;
  uint32_t tgid;
  uint32_t ppid;
  uint32_t uid;
  uint32_t gid;
  char comm[VISHAYA_COMM_LEN];
};

/**
 * @brief Process event payload.
 */
struct process_event {
  struct event_header hdr;
  uint32_t kind;
  uint32_t exit_code;
  uint32_t child_pid;
  char filename[VISHAYA_PATH_LEN];
  char exec_path[VISHAYA_PATH_LEN];
  char cmdline[VISHAYA_PATH_LEN];
  char cwd[VISHAYA_PATH_LEN];
  char parent_comm[VISHAYA_COMM_LEN];
  uint32_t _pad0;           /* explicit: 4-byte gap before uint64_t (offset 1108–1111) */
  uint64_t start_time_ticks;
};

/**
 * @brief File event payload.
 *
 * @note `mode` carries syscall-specific context. In the current schema it is
 *       reused for `renameat2` newdfd context.
 */
struct file_event {
  struct event_header hdr;
  uint32_t kind;
  int32_t dfd;
  int32_t flags;
  int32_t mode;
  int32_t ret;
  char path_a[VISHAYA_PATH_LEN];
  char path_b[VISHAYA_PATH_LEN];
};

/**
 * @brief Syscall event payload.
 */
struct syscall_event {
  struct event_header hdr;
  uint32_t is_enter;
  int32_t syscall_nr;
  int64_t arg0;
  int64_t arg1;
  int64_t arg2;
  int64_t ret;
};

/**
 * @brief Socket endpoint snapshot shared by control-plane and future data-plane records.
 *
 * @note `addr` is used for IPv4/IPv6 raw bytes.
 * @note `path` is used for UNIX domain sockets, including abstract paths when present.
 */
struct network_endpoint {
  uint32_t family;
  uint32_t port;
  uint32_t addr_len;
  uint8_t addr[16];
  char path[VISHAYA_UNIX_PATH_LEN];
};

/**
 * @brief Network socket event payload.
 *
 * Socket events keep control-plane facts and bounded endpoint snapshots in one
 * record so userspace can correlate flow identity without kernel-side protocol
 * parsing. Future data-plane hooks will reuse the same envelope.
 */
struct network_event {
  struct event_header hdr;
  uint32_t kind;
  int32_t fd;
  int32_t peer_fd;
  int32_t ret;
  int32_t domain;
  int32_t sock_type;
  int32_t protocol;
  int32_t flags;
  int32_t backlog;
  int32_t how;
  int32_t opt_level;
  int32_t opt_name;
  int32_t opt_len;
  uint8_t optval_prefix[16];
  uint32_t _pad0;           /* explicit: 4-byte gap before uint64_t (offset 124–127) */
  uint64_t flow_id;
  uint64_t socket_id;
  uint32_t direction;
  uint32_t transport;
  uint64_t bytes_requested;
  uint64_t bytes_transferred;
  uint32_t bytes_captured;
  uint32_t bytes_truncated;
  struct network_endpoint local;
  struct network_endpoint remote;
  /*
   * Payload prefix captured from user buffers on send/recv paths (v0.1 Step 9).
   * payload_len is the number of valid bytes at the front of payload_prefix.
   * Feeds the userspace protocol decoder (DNS parsing, later HTTP detection).
   */
  uint32_t payload_len;
  uint8_t  payload_prefix[VISHAYA_NET_PAYLOAD_LEN];
};

#ifdef __cplusplus
}
#endif

/* ABI-locking compile-time checks. Any struct size change is a compile error.
 * Update the expected value AND add a _padN field if a new implicit gap appears. */
#ifndef __BPF__
#  ifdef __cplusplus
static_assert(sizeof(struct event_header)     ==   56, "event_header layout changed");
static_assert(sizeof(struct process_event)    == 1120, "process_event layout changed — verify _pad0 before start_time_ticks");
static_assert(sizeof(struct file_event)       ==  592, "file_event layout changed");
static_assert(sizeof(struct syscall_event)    ==   96, "syscall_event layout changed");
static_assert(sizeof(struct network_endpoint) ==  136, "network_endpoint layout changed");
static_assert(sizeof(struct network_event)    ==  584, "network_event layout changed — verify _pad0 before flow_id");
#  else
_Static_assert(sizeof(struct event_header)     ==   56, "event_header layout changed");
_Static_assert(sizeof(struct process_event)    == 1120, "process_event layout changed");
_Static_assert(sizeof(struct file_event)       ==  592, "file_event layout changed");
_Static_assert(sizeof(struct syscall_event)    ==   96, "syscall_event layout changed");
_Static_assert(sizeof(struct network_endpoint) ==  136, "network_endpoint layout changed");
_Static_assert(sizeof(struct network_event)    ==  584, "network_event layout changed");
#  endif
#endif /* !__BPF__ */

#endif /* VISHAYA_EVENT_SCHEMA_H */
