#pragma once

/*
 * File Notes:
 * - Launches a target binary inside the isolation boundary. Uses a
 *   parent<->child sync pipe so the parent finishes cgroup attach before the
 *   child execs; this guarantees no observable target activity occurs outside
 *   the cgroup.
 * - v0.1 isolation = cgroup + mount namespace only. PID and net namespaces are
 *   deferred (see ARCHITECTURE.md D3).
 */

#include <string>
#include <sys/types.h>
#include <vector>

namespace vishaya::isolation {

class Cgroup;

// Per-namespace toggles. Only mount is enabled by default in v0.1; the others
// exist so future work can turn them on additively without changing the ABI.
struct NamespaceFlags {
  bool mount = true;   // v0.1 default: isolated filesystem view.
  bool pid   = false;  // v0.5+: adds double-fork trick for PID 1 semantics.
  bool net   = false;  // v0.5+: requires veth pair for network reachability.
  bool uts   = false;
  bool ipc   = false;
  // User namespace deliberately absent; see ARCHITECTURE.md D3.
};

struct LaunchOptions {
  std::string              binary;  // absolute path to the target binary
  std::vector<std::string> args;    // argv[1..]; argv[0] is set to basename(binary)
  std::vector<std::string> envp;    // empty -> inherit parent environment
  std::string              cwd;     // empty -> "/"
};

struct LaunchResult {
  pid_t host_pid;  // pid visible in caller's PID namespace
};

// Fork, attach child to cgroup, unshare requested namespaces, exec target.
// Throws IsolationError on any failure. Kills and reaps the child on failure.
LaunchResult launch_target(const LaunchOptions&    opts,
                           const NamespaceFlags&   ns,
                           const Cgroup&           cgroup);

// Block until the target exits. Returns waitpid-style status. Retries on EINTR.
int wait_for_exit(pid_t host_pid);

} // namespace vishaya::isolation
