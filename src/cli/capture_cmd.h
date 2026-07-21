#pragma once

/*
 * File Notes:
 * - `vishaya capture` subcommand implementation. Orchestrates cgroup setup,
 *   scratch dir, isolation-based target launch, ring-buffer poll loop, and
 *   final bundle write.
 */

#include <string>
#include <vector>

namespace vishaya::cli {

struct CaptureArgs {
  std::string              target;
  std::vector<std::string> args;
  std::string              output          = "case.vishaya";
  std::string              cwd;
  bool                     enable_syscalls = false;
  // Escape hatch: continue capturing HOST-WIDE if the loaded BPF object cannot
  // scope to the target cgroup (map missing). Off by default — capture refuses
  // rather than silently recording unrelated host processes.
  bool                     allow_host_wide = false;
};

// Runs a complete capture from start to bundle-written. Returns process exit
// code (0 = success, target exit code passthrough is deliberately NOT used
// because the exit code semantic is "did capture succeed", not "did target
// succeed"; the target's exit code is recorded in the bundle's process tree).
int run_capture(const CaptureArgs& args);

} // namespace vishaya::cli
