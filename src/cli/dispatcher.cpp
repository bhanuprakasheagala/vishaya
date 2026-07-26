#include "cli/dispatcher.h"

#include "cli/capture_cmd.h"
#include "common/log.h"
#include "inspect/artifacts.h"
#include "inspect/diff.h"
#include "inspect/files.h"
#include "inspect/network.h"
#include "inspect/summary.h"
#include "inspect/timeline.h"
#include "inspect/tree.h"
#include "inspect/verify.h"

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
      "vishaya — Linux forensic capture and analysis (v0.2 pre-release)"};
  app.require_subcommand(1);
  app.set_version_flag("--version", std::string("vishaya 0.2.0 (pre-release)"));

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
  capture_cmd->add_flag("--capture-artifacts", cap.capture_artifacts,
                        "Copy files the target created/modified into the bundle's "
                        "artifacts/ (bounded; off by default)");
  capture_cmd->add_option("--artifact-max-size", cap.artifact_cfg.max_file_bytes,
                          "Max bytes per captured artifact file (default: 100 MiB)");
  capture_cmd->add_option("--artifact-max-total", cap.artifact_cfg.max_total_bytes,
                          "Max total bytes of captured artifacts (default: 500 MiB)");
  capture_cmd->add_option("--artifact-max-count", cap.artifact_cfg.max_count,
                          "Max number of artifact files to capture (default: 1000)");
  capture_cmd->add_option("args", cap.args,
                          "Arguments to pass to target after --");
  capture_cmd->callback([&]() { result = run_capture(cap); });

  // ---- summary -----------------------------------------------------------
  auto* summary_cmd =
      app.add_subcommand("summary", "One-screen verdict: trust, target, counts, network, files");
  std::string summary_bundle;
  summary_cmd->add_option("bundle", summary_bundle, "Path to .vishaya bundle")->required();
  summary_cmd->callback([&]() { result = vishaya::inspect::run_summary(summary_bundle); });

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

  // ---- diff --------------------------------------------------------------
  auto* diff_cmd =
      app.add_subcommand("diff", "Semantic diff of two bundles (what changed between runs)");
  std::string diff_a;
  std::string diff_b;
  diff_cmd->add_option("bundle_a", diff_a, "First (A) .vishaya bundle")->required();
  diff_cmd->add_option("bundle_b", diff_b, "Second (B) .vishaya bundle")->required();
  diff_cmd->callback([&]() { result = vishaya::inspect::run_diff(diff_a, diff_b); });

  // ---- verify ------------------------------------------------------------
  auto* verify_cmd =
      app.add_subcommand("verify", "Verify a bundle's integrity and signature");
  std::string verify_bundle;
  std::string verify_key;
  verify_cmd->add_option("bundle", verify_bundle, "Path to .vishaya bundle")->required();
  verify_cmd->add_option("--verify-key", verify_key,
                         "Require the bundle to be signed by this base64 Ed25519 public key");
  verify_cmd->callback(
      [&]() { result = vishaya::inspect::run_verify(verify_bundle, verify_key); });

  // ---- artifacts ---------------------------------------------------------
  auto* artifacts_cmd =
      app.add_subcommand("artifacts", "List files captured into the bundle's artifacts/");
  std::string artifacts_bundle;
  artifacts_cmd->add_option("bundle", artifacts_bundle, "Path to .vishaya bundle")
      ->required();
  artifacts_cmd->callback(
      [&]() { result = vishaya::inspect::run_artifacts(artifacts_bundle); });

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
