#include "cli/dispatcher.h"

#include "cli/capture_cmd.h"
#include "common/log.h"
#include "inspect/files.h"
#include "inspect/network.h"
#include "inspect/timeline.h"
#include "inspect/tree.h"

#include <CLI/CLI.hpp>
#include <iostream>
#include <string>
#include <string_view>

namespace vishaya::cli {

namespace {

// Pre-scan argv for -v / --verbose so the log level is set BEFORE CLI11's
// callbacks fire. If we relied on CLI11's parsed flag, the level would be
// applied only after the subcommand had already executed.
void apply_early_verbose(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    const std::string_view a{argv[i]};
    if (a == "--") break;  // end of options
    if (a == "-v" || a == "--verbose") {
      vishaya::log::set_level(vishaya::log::Level::Debug);
      return;
    }
  }
}

} // namespace

int dispatch(int argc, char** argv) {
  apply_early_verbose(argc, argv);

  CLI::App app{
      "vishaya — Linux forensic capture and analysis (v0.1 pre-release)"};
  app.require_subcommand(1);
  app.set_version_flag("--version", std::string("vishaya 0.1.0 (pre-release)"));

  bool verbose = false;
  app.add_flag("-v,--verbose", verbose,
               "Enable debug logging (also honored via pre-parse scan)");

  int    result = 0;

  // ---- capture -----------------------------------------------------------
  auto* capture_cmd =
      app.add_subcommand("capture", "Run a target and capture its activity");
  CaptureArgs cap;
  capture_cmd->add_option("--target", cap.target,
                          "Absolute path to target binary")->required();
  capture_cmd->add_option("--output", cap.output,
                          "Output .vishaya bundle path (default: ./case.vishaya)");
  capture_cmd->add_option("--cwd", cap.cwd,
                          "Working directory for target (default: /)");
  capture_cmd->add_flag("--enable-syscalls", cap.enable_syscalls,
                        "Enable raw syscall capture (high volume; off by default)");
  capture_cmd->add_flag("--allow-host-wide", cap.allow_host_wide,
                        "Continue capturing host-wide if the BPF object cannot scope "
                        "to the target cgroup (default: refuse)");
  capture_cmd->add_option("args", cap.args,
                          "Arguments to pass to target after --");
  capture_cmd->callback([&]() { result = run_capture(cap); });

  // ---- tree --------------------------------------------------------------
  auto* tree_cmd =
      app.add_subcommand("tree", "Show process tree from a bundle");
  std::string tree_bundle;
  tree_cmd->add_option("bundle", tree_bundle, "Path to .vishaya bundle")->required();
  tree_cmd->callback([&]() { result = vishaya::inspect::run_tree(tree_bundle); });

  // ---- files -------------------------------------------------------------
  auto* files_cmd =
      app.add_subcommand("files", "Show file events from a bundle");
  std::string files_bundle;
  files_cmd->add_option("bundle", files_bundle, "Path to .vishaya bundle")->required();
  files_cmd->callback([&]() { result = vishaya::inspect::run_files(files_bundle); });

  // ---- network -----------------------------------------------------------
  auto* network_cmd =
      app.add_subcommand("network", "Show network events from a bundle");
  std::string net_bundle;
  network_cmd->add_option("bundle", net_bundle, "Path to .vishaya bundle")->required();
  network_cmd->callback([&]() { result = vishaya::inspect::run_network(net_bundle); });

  // ---- timeline ----------------------------------------------------------
  auto* timeline_cmd =
      app.add_subcommand("timeline", "Show all events chronologically");
  std::string timeline_bundle;
  timeline_cmd->add_option("bundle", timeline_bundle, "Path to .vishaya bundle")
      ->required();
  timeline_cmd->callback(
      [&]() { result = vishaya::inspect::run_timeline(timeline_bundle); });

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  }

  // Verbose was already applied by apply_early_verbose(); the CLI11 flag exists
  // for help-text visibility and validation.
  (void)verbose;

  return result;
}

} // namespace vishaya::cli
