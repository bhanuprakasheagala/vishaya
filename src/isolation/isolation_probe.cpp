/*
 * isolation_probe — standalone smoke test for Vishaya isolation primitives.
 *
 * Purpose: prove that Cgroup + launch_target() correctly spawn a target binary
 *   inside a fresh cgroup + mount namespace, wait for it, and clean up. No
 *   eBPF, no bundle writing; this is the isolation subsystem in isolation.
 *
 * Usage:
 *   sudo isolation_probe --binary /bin/ls -- /etc
 *   sudo isolation_probe -v --binary /usr/bin/curl -- https://example.com
 */

#include "common/errors.h"
#include "common/log.h"
#include "isolation/cgroup.h"
#include "isolation/target_launch.h"

#include <CLI/CLI.hpp>
#include <iostream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

int main(int argc, char** argv) {
  CLI::App app{"isolation_probe — Vishaya isolation smoke test"};

  std::string              binary;
  std::vector<std::string> args;
  std::string              cwd;
  bool                     verbose = false;

  app.add_option("--binary", binary,
                 "Absolute path to the target binary")->required();
  app.add_option("--cwd", cwd,
                 "Working directory for the target (default: /)");
  app.add_option("args", args,
                 "Arguments to pass to the target after --");
  app.add_flag("-v,--verbose", verbose,
               "Enable debug logging");

  CLI11_PARSE(app, argc, argv);

  if (verbose) {
    vishaya::log::set_level(vishaya::log::Level::Debug);
  }

  if (::geteuid() != 0) {
    vishaya::log::error(
        "isolation_probe must run as root (cgroup v2 create/attach requires it)");
    return 1;
  }

  try {
    vishaya::isolation::Cgroup cgroup;
    vishaya::log::info("cgroup: " + cgroup.path() +
                       " (id=" + std::to_string(cgroup.id()) + ")");

    vishaya::isolation::LaunchOptions opts;
    opts.binary = binary;
    opts.args   = args;
    opts.cwd    = cwd;

    vishaya::isolation::NamespaceFlags ns;  // v0.1 defaults: mount only

    const auto result =
        vishaya::isolation::launch_target(opts, ns, cgroup);
    vishaya::log::info("waiting for target: pid=" +
                       std::to_string(result.host_pid));

    const int status = vishaya::isolation::wait_for_exit(result.host_pid);

    if (WIFEXITED(status)) {
      const int code = WEXITSTATUS(status);
      vishaya::log::info("target exited: code=" + std::to_string(code));
      return code;
    }
    if (WIFSIGNALED(status)) {
      const int sig = WTERMSIG(status);
      vishaya::log::info("target killed: signal=" + std::to_string(sig));
      return 128 + sig;
    }
    vishaya::log::warn("target ended in unexpected state");
    return 1;
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("isolation_probe failed: ") + e.what());
    return 1;
  }
}
