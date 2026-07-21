#pragma once

/*
 * File Notes:
 * - Cgroup v2 handle. Creates a fresh cgroup under $VISHAYA_CGROUP_ROOT (default
 *   /sys/fs/cgroup) on construction and removes it on destruction.
 * - Move-only. The kernel cgroup ID (inode number) is used by BPF probes to
 *   filter events; expose via id().
 * - Requires root and a systemd-style unified cgroup v2 hierarchy.
 */

#include <cstdint>
#include <string>
#include <sys/types.h>

namespace vishaya::isolation {

class Cgroup {
 public:
  // Returns the cgroup v2 root path. Defaults to /sys/fs/cgroup, overridable via
  // VISHAYA_CGROUP_ROOT env var (for tests running in unprivileged sandboxes).
  static const char* root_path();

  // Creates a fresh cgroup. Throws IsolationError on failure.
  Cgroup();

  // Removes the cgroup on destruction. Logs a warning on cleanup failure but does
  // not throw (destructors must not throw).
  ~Cgroup();

  Cgroup(const Cgroup&)            = delete;
  Cgroup& operator=(const Cgroup&) = delete;
  Cgroup(Cgroup&& other) noexcept;
  Cgroup& operator=(Cgroup&& other) noexcept;

  // Moves a pid into this cgroup by writing to cgroup.procs.
  // Throws IsolationError on failure.
  void attach_pid(pid_t pid) const;

  const std::string& path() const noexcept { return path_; }
  uint64_t           id()   const noexcept { return id_;   }

 private:
  std::string path_;    // absolute path, e.g. /sys/fs/cgroup/vishaya-<uuid>
  uint64_t    id_ = 0;  // kernel cgroup ID (stat().st_ino)
  bool        owned_ = false;
};

} // namespace vishaya::isolation
