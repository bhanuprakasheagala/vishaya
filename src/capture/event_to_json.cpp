#include "capture/event_to_json.h"

#include "event_schema.h"

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <type_traits>
#include <unordered_map>

namespace vishaya::capture {

namespace {

using json = nlohmann::json;

// Safely construct a string from a fixed-size C char array that may or may not
// be null-terminated. Uses strnlen to cap length.
template <size_t N>
std::string safe_str(const char (&arr)[N]) {
  return std::string(arr, ::strnlen(arr, N));
}

// ---- Family / kind name mappers ----------------------------------------

const char* process_kind_name(uint32_t kind) {
  switch (kind) {
    case PROCESS_EXEC:   return "exec";
    case PROCESS_FORK:   return "fork";
    case PROCESS_EXIT:   return "exit";
    case PROCESS_CLONE:  return "clone";
    case PROCESS_CLONE3: return "clone3";
    case PROCESS_VFORK:  return "vfork";
    default:             return "unknown";
  }
}

const char* file_kind_name(uint32_t kind) {
  switch (kind) {
    case FILE_OPENAT:    return "openat";
    case FILE_UNLINKAT:  return "unlinkat";
    case FILE_RENAMEAT2: return "renameat2";
    default:             return "unknown";
  }
}

const char* network_kind_name(uint32_t kind) {
  switch (kind) {
    case NETWORK_SOCKET:      return "socket";
    case NETWORK_CONNECT:     return "connect";
    case NETWORK_ACCEPT:      return "accept";
    case NETWORK_BIND:        return "bind";
    case NETWORK_LISTEN:      return "listen";
    case NETWORK_CLOSE:       return "close";
    case NETWORK_SENDTO:      return "sendto";
    case NETWORK_RECVFROM:    return "recvfrom";
    case NETWORK_SHUTDOWN:    return "shutdown";
    case NETWORK_SOCKETPAIR:  return "socketpair";
    case NETWORK_ACCEPT4:     return "accept4";
    case NETWORK_GETSOCKNAME: return "getsockname";
    case NETWORK_GETPEERNAME: return "getpeername";
    case NETWORK_SETSOCKOPT:  return "setsockopt";
    case NETWORK_GETSOCKOPT:  return "getsockopt";
    case NETWORK_SENDMSG:     return "sendmsg";
    case NETWORK_RECVMSG:     return "recvmsg";
    case NETWORK_READ:        return "read";
    case NETWORK_WRITE:       return "write";
    case NETWORK_READV:       return "readv";
    case NETWORK_WRITEV:      return "writev";
    case NETWORK_SENDMMSG:    return "sendmmsg";
    case NETWORK_RECVMMSG:    return "recvmmsg";
    default:                  return "unknown";
  }
}

const char* transport_name(uint32_t t) {
  switch (t) {
    case NETWORK_TRANSPORT_TCP:  return "tcp";
    case NETWORK_TRANSPORT_UDP:  return "udp";
    case NETWORK_TRANSPORT_UNIX: return "unix";
    case NETWORK_TRANSPORT_RAW:  return "raw";
    default:                     return "unknown";
  }
}

const char* direction_name(uint32_t d) {
  switch (d) {
    case NETWORK_DIRECTION_INBOUND:  return "inbound";
    case NETWORK_DIRECTION_OUTBOUND: return "outbound";
    default:                         return "unknown";
  }
}

const char* endpoint_family_name(uint32_t f) {
  // Linux socket-family constants (AF_UNSPEC=0, AF_UNIX=1, AF_INET=2, AF_INET6=10).
  switch (f) {
    case 0:  return "unspec";
    case 1:  return "unix";
    case 2:  return "inet";
    case 10: return "inet6";
    default: return "other";
  }
}

// ---- Container context helpers -----------------------------------------

// Read the cgroupv2 membership path for a process. The cgroupv2 unified
// hierarchy line in /proc/<pid>/cgroup has the form "0::<path>".
// Returns "" if the file is unreadable or the process has exited.
std::string read_cgroup_path(uint32_t pid) {
  if (pid == 0) return {};
  std::ifstream in("/proc/" + std::to_string(pid) + "/cgroup");
  if (!in.is_open()) return {};
  std::string line;
  while (std::getline(in, line)) {
    if (line.rfind("0::", 0) == 0) {
      return line.substr(3);
    }
  }
  return {};
}

// Return the inode of the mount namespace for a process (stat of
// /proc/<pid>/ns/mnt). Matching inodes identify the same mount namespace.
// Returns 0 if the path is unreadable or the process has exited.
uint64_t read_mount_ns_ino(uint32_t pid) {
  if (pid == 0) return 0;
  struct stat st{};
  if (::stat(("/proc/" + std::to_string(pid) + "/ns/mnt").c_str(), &st) != 0) {
    return 0;
  }
  return static_cast<uint64_t>(st.st_ino);
}

// ---- Per-pid container context cache -----------------------------------
//
// /proc reads for cgroup path and mount-ns inode are stable for the lifetime
// of a process. Caching by tgid eliminates redundant syscalls when the same
// process emits many events. The map is cleared wholesale at kMaxPids entries
// to bound memory and handle PID reuse without stale-entry tracking overhead.
//
// Known limitation: unlike process-event enrichment, these fields have no
// per-event kernel start-time to cross-check against (only process_event carries
// start_time_ticks; file/network headers do not), so a PID recycled within a
// single capture could receive the prior process's cgroup/mount-ns until the
// wholesale clear. Target-scoping bounds the blast radius: every captured event
// already belongs to the target's cgroup subtree, so a reused PID resolves to the
// same scope (and usually the same mount namespace). A fully race-free fix would
// require threading a start-time into the shared event header — deferred until a
// schema-major bump makes that additive change worthwhile.

struct ContainerCtx {
  std::string cgroup_path;
  uint64_t    mount_ns_ino = 0;
};

constexpr size_t kContainerCacheMaxPids = 4096;
thread_local std::unordered_map<uint32_t, ContainerCtx> g_container_cache;

const ContainerCtx& container_ctx_for(uint32_t pid) {
  auto it = g_container_cache.find(pid);
  if (it != g_container_cache.end()) return it->second;
  if (g_container_cache.size() >= kContainerCacheMaxPids) {
    g_container_cache.clear();
  }
  auto [ins_it, ok] = g_container_cache.emplace(
      pid, ContainerCtx{read_cgroup_path(pid), read_mount_ns_ino(pid)});
  (void)ok;
  return ins_it->second;
}

// ---- Endpoint / data payload builders ----------------------------------

json endpoint_to_json(const network_endpoint& ep) {
  json j;
  j["family"] = endpoint_family_name(ep.family);
  j["port"]   = ep.port;
  j["addr"]   = "";
  j["path"]   = safe_str(ep.path);

  if (ep.family == 2 /*AF_INET*/) {
    char buf[INET_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET, ep.addr, buf, sizeof(buf))) {
      j["addr"] = buf;
    }
  } else if (ep.family == 10 /*AF_INET6*/) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET6, ep.addr, buf, sizeof(buf))) {
      j["addr"] = buf;
    }
  }
  return j;
}

json header_common(const event_header& h,
                   const char*         family,
                   const char*         kind) {
  const uint32_t proc_pid = h.tgid != 0 ? h.tgid : h.pid;
  const ContainerCtx& cctx = container_ctx_for(proc_pid);
  return json{
    {"ts_ns",  h.ts_ns},
    {"family", family},
    {"kind",   kind},
    {"pid",    h.pid},
    {"tgid",   h.tgid},
    {"ppid",   h.ppid},
    {"uid",    h.uid},
    {"gid",    h.gid},
    {"comm",   safe_str(h.comm)},
    {"container", json{
      {"cgroup_path",  cctx.cgroup_path},
      {"mount_ns_ino", cctx.mount_ns_ino},
    }},
  };
}

json process_data(const process_event& e) {
  return json{
    {"exit_code",        e.exit_code},
    {"child_pid",        e.child_pid},
    {"filename",         safe_str(e.filename)},
    {"exec_path",        safe_str(e.exec_path)},
    {"cmdline",          safe_str(e.cmdline)},
    {"cwd",              safe_str(e.cwd)},
    {"parent_comm",      safe_str(e.parent_comm)},
    {"start_time_ticks", e.start_time_ticks},
  };
}

json file_data(const file_event& e) {
  return json{
    {"dfd",    e.dfd},
    {"flags",  e.flags},
    {"mode",   e.mode},
    {"ret",    e.ret},
    {"path_a", safe_str(e.path_a)},
    {"path_b", safe_str(e.path_b)},
  };
}

json syscall_data(const syscall_event& e) {
  return json{
    {"syscall_nr",   e.syscall_nr},
    {"syscall_name", ""},  // v0.1 does not resolve syscall names in userspace
    {"args",         json::array({e.arg0, e.arg1, e.arg2})},
    {"ret",          e.is_enter ? json(nullptr) : json(e.ret)},
  };
}

json network_data(const network_event& e) {
  return json{
    {"fd",                e.fd},
    {"peer_fd",           e.peer_fd},
    {"ret",               e.ret},
    {"domain",            e.domain},
    {"sock_type",         e.sock_type},
    {"protocol",          e.protocol},
    {"flags",             e.flags},
    {"backlog",           e.backlog},
    {"how",               e.how},
    {"socket_id",         e.socket_id},
    {"flow_id",           e.flow_id},
    {"direction",         direction_name(e.direction)},
    {"transport",         transport_name(e.transport)},
    {"bytes_requested",   e.bytes_requested},
    {"bytes_transferred", e.bytes_transferred},
    {"bytes_captured",    e.bytes_captured},
    {"bytes_truncated",   e.bytes_truncated},
    {"local",             endpoint_to_json(e.local)},
    {"remote",            endpoint_to_json(e.remote)},
  };
}

} // namespace

std::string event_to_json(const vishaya::collector::EventVariant& event) {
  return std::visit(
      [](const auto& e) -> std::string {
        using T = std::decay_t<decltype(e)>;
        json j;
        if constexpr (std::is_same_v<T, process_event>) {
          j          = header_common(e.hdr, "process", process_kind_name(e.kind));
          j["data"]  = process_data(e);
        } else if constexpr (std::is_same_v<T, file_event>) {
          j          = header_common(e.hdr, "file", file_kind_name(e.kind));
          j["data"]  = file_data(e);
        } else if constexpr (std::is_same_v<T, syscall_event>) {
          j          = header_common(e.hdr, "syscall",
                                     e.is_enter ? "sys_enter" : "sys_exit");
          j["data"]  = syscall_data(e);
        } else if constexpr (std::is_same_v<T, network_event>) {
          j          = header_common(e.hdr, "network", network_kind_name(e.kind));
          j["data"]  = network_data(e);
        } else {
          return "{}";
        }
        // Kernel-sourced strings (comm, paths, cmdline, argv) can contain bytes
        // that are not valid UTF-8. nlohmann's default dump() throws type_error 316
        // on such bytes, which would silently drop the event upstream. Use the
        // 'replace' handler so invalid sequences become U+FFFD and the event is
        // still recorded. (indent=-1, space, ensure_ascii=false → compact output.)
        return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
      },
      event);
}

} // namespace vishaya::capture
