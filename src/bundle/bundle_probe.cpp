/*
 * bundle_probe — standalone smoke test for the Vishaya bundle writer.
 *
 * Purpose: writes a small synthetic bundle end-to-end (a hand-authored
 *   events.ndjson with 3 process events) and verifies libarchive + libzstd +
 *   OpenSSL are wired up correctly. No eBPF, no isolation involvement.
 *
 * Usage:
 *   bundle_probe                             # writes ./test-case.vishaya
 *   bundle_probe --output /tmp/foo.vishaya   # custom path
 *   bundle_probe -v                          # verbose logs
 *
 * Inspect the produced bundle with:
 *   zstd -d < test-case.vishaya | tar -tv
 *   zstd -d < test-case.vishaya | tar -xO manifest.json | jq
 */

#include "bundle/manifest.h"
#include "bundle/writer.h"
#include "common/errors.h"
#include "common/log.h"

#include <CLI/CLI.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

// Three-event synthetic capture: exec + fork(child) + exit.
constexpr const char* kSyntheticEvents =
R"({"ts_ns":1721390096100000000,"family":"process","kind":"exec","pid":12345,"tgid":12345,"ppid":1,"uid":1000,"gid":1000,"comm":"probe","data":{"exec_path":"/bin/probe","cmdline":"probe","cwd":"/","filename":"/bin/probe","exit_code":0,"child_pid":0,"parent_comm":"vishaya","start_time_ticks":0}}
{"ts_ns":1721390096200000000,"family":"process","kind":"fork","pid":12345,"tgid":12345,"ppid":1,"uid":1000,"gid":1000,"comm":"probe","data":{"child_pid":12346,"exec_path":"","cmdline":"","cwd":"","filename":"","exit_code":0,"parent_comm":"","start_time_ticks":0}}
{"ts_ns":1721390096500000000,"family":"process","kind":"exit","pid":12345,"tgid":12345,"ppid":1,"uid":1000,"gid":1000,"comm":"probe","data":{"exit_code":0,"child_pid":0,"exec_path":"","cmdline":"","cwd":"","filename":"","parent_comm":"","start_time_ticks":0}}
)";

} // namespace

int main(int argc, char** argv) {
  CLI::App app{"bundle_probe — Vishaya bundle writer smoke test"};

  std::string bundle_path = "test-case.vishaya";
  bool        verbose     = false;

  app.add_option("--output", bundle_path,
                 "Output bundle path (default: ./test-case.vishaya)");
  app.add_flag("-v,--verbose", verbose, "Enable debug logging");

  CLI11_PARSE(app, argc, argv);

  if (verbose) vishaya::log::set_level(vishaya::log::Level::Debug);

  // Scratch directory unique to this run.
  const fs::path scratch = fs::temp_directory_path() /
      ("vishaya-bundle-probe-" + std::to_string(::getpid()));

  std::error_code ec;
  fs::create_directories(scratch, ec);
  if (ec) {
    vishaya::log::error("failed to create scratch dir " + scratch.string() +
                        ": " + ec.message());
    return 1;
  }

  // Write synthetic events.ndjson into the scratch dir.
  const fs::path events_path = scratch / "events.ndjson";
  {
    std::ofstream out(events_path, std::ios::binary);
    if (!out) {
      vishaya::log::error("failed to open " + events_path.string());
      fs::remove_all(scratch, ec);
      return 1;
    }
    out << kSyntheticEvents;
  }

  // Build a hand-authored manifest that matches the synthetic events.
  vishaya::bundle::WriterInput input;
  input.scratch_dir                     = scratch.string();
  input.bundle_path                     = bundle_path;
  input.root_pid                        = 12345;
  input.manifest.capture.started_at     = "2026-07-19T12:34:56.100Z";
  input.manifest.capture.ended_at       = "2026-07-19T12:34:56.500Z";
  input.manifest.capture.duration_seconds = 1;
  input.manifest.capture.host.kernel    = "unknown";
  input.manifest.capture.host.arch      = "unknown";
  input.manifest.capture.host.distro    = "unknown";
  input.manifest.capture.host.hostname  = "bundle-probe";
  input.manifest.target.path            = "/bin/probe";
  input.manifest.target.sha256 =
      "0000000000000000000000000000000000000000000000000000000000000000";
  input.manifest.target.size            = 0;
  input.manifest.target.args            = {};
  input.manifest.target.env_count       = 0;
  input.manifest.isolation.namespaces   = {"mnt"};
  input.manifest.isolation.cgroup_path  = "/sys/fs/cgroup/vishaya-probe";
  input.manifest.isolation.cgroup_id    = 0;
  input.manifest.coverage.families      = {"process"};
  input.manifest.coverage.syscalls_captured = false;
  input.manifest.coverage.network_layers = {};
  input.manifest.counts.events_total    = 3;
  input.manifest.counts.events_dropped  = 0;
  input.manifest.counts.artifacts_count = 0;

  int exit_code = 0;
  try {
    vishaya::bundle::write_bundle(input);
    vishaya::log::info("bundle_probe success: " + bundle_path);
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("bundle_probe failed: ") + e.what());
    exit_code = 1;
  }

  fs::remove_all(scratch, ec);
  if (ec) {
    vishaya::log::warn("scratch cleanup failed: " + ec.message());
  }

  return exit_code;
}
