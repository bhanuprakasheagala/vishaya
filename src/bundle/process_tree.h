#pragma once

/*
 * File Notes:
 * - ProcessTree data model and reconstruction from an events.ndjson stream.
 * - The tree is materialized once at bundle finalize; it is derivable from
 *   events alone (fork/clone/vfork parent-child edges, exec updates, exit
 *   terminates). We store the reconstructed tree for reader convenience.
 * - One record per real process (thread-group leader). A fork/clone "child" is
 *   only added as a process node when it is itself observed as a process tgid,
 *   so CLONE_THREAD threads (which share the parent's tgid) are excluded, and
 *   duplicate fork/clone edges for the same child are collapsed.
 * - Known limitation: records are keyed by tgid for the whole capture, so a
 *   reused tgid (process A exits, later process B reuses the number) merges into
 *   one record. Rare for short captures; see backlog R2-06 for the fix plan.
 * - Layout follows docs/BUNDLE-SPEC-v0.1.md §5.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vishaya::bundle {

struct ProcessRecord {
  int32_t                 pid  = 0;
  int32_t                 tgid = 0;
  int32_t                 ppid = 0;
  std::string             comm;
  std::string             exec_path;
  std::string             cmdline;
  std::string             cwd;
  uint32_t                uid = 0;
  uint32_t                gid = 0;
  uint64_t                start_ts_ns = 0;
  std::optional<uint64_t> end_ts_ns;
  std::optional<int32_t>  exit_code;
  std::vector<int32_t>    children;  // direct child tgids
};

struct ProcessTree {
  int32_t                    root_pid = 0;
  std::vector<ProcessRecord> processes;  // sorted by (start_ts_ns, tgid) for determinism
};

// Walk an events.ndjson file line by line, extract process family events, and
// reconstruct the process tree rooted at root_pid.
// Malformed lines are silently skipped (debug logged).
// Throws BundleError if the file cannot be opened.
ProcessTree reconstruct_tree(const std::string& events_ndjson_path,
                             int32_t            root_pid);

std::string tree_to_json(const ProcessTree& t);
ProcessTree tree_from_json(const std::string& json);

} // namespace vishaya::bundle
