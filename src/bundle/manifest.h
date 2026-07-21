#pragma once

/*
 * File Notes:
 * - Manifest data model and JSON serialization for the .vishaya bundle format.
 * - Field layout mirrors docs/BUNDLE-SPEC-v0.1.md §3 exactly. Add fields only
 *   via the additive-schema rule (BUNDLE-SPEC §7) — never remove or retype
 *   existing fields within the same schema major.
 */

#include <cstdint>
#include <string>
#include <vector>

namespace vishaya::bundle {

struct HostInfo {
  std::string kernel;
  std::string arch;
  std::string distro;   // may be "" if /etc/os-release unavailable
  std::string hostname;
};

struct TargetInfo {
  std::string              path;
  std::string              sha256;  // hex, 64 chars
  uint64_t                 size = 0;
  std::vector<std::string> args;
  int                      env_count = 0;
};

struct IsolationInfo {
  std::vector<std::string> namespaces;   // subset of "pid","net","mnt","user"
  std::string              cgroup_path;
  uint64_t                 cgroup_id = 0;
};

struct CoverageInfo {
  std::vector<std::string> families;         // subset of "process","file","network","syscall"
  bool                     syscalls_captured = false;
  std::vector<std::string> network_layers;   // subset of "socket","dns","http","https"
};

struct Counts {
  uint64_t events_total    = 0;
  uint64_t events_dropped  = 0;
  uint64_t processes_seen  = 0;
  uint64_t artifacts_count = 0;
};

struct Integrity {
  std::string events_sha256;
  std::string process_tree_sha256;
};

struct BundleSignature {
  std::string algorithm;    // "Ed25519" or "" (empty means unsigned)
  std::string pubkey_b64;   // base64(32-byte Ed25519 raw public key)
  std::string sig_b64;      // base64(64-byte Ed25519 signature)
};

struct CaptureInfo {
  std::string started_at;         // RFC 3339 UTC
  std::string ended_at;           // RFC 3339 UTC
  uint64_t    duration_seconds = 0;
  HostInfo    host;
  // Clock anchor sampled at capture start, mapping the CLOCK_MONOTONIC base of
  // event ts_ns (from bpf_ktime_get_ns) to wall-clock. wall(event) =
  // clock_realtime_ns + (event.ts_ns - clock_monotonic_ns). Both 0 => anchor
  // absent (pre-anchor bundle); readers fall back to relative timestamps.
  uint64_t    clock_realtime_ns  = 0;  // CLOCK_REALTIME at anchor (ns since Unix epoch)
  uint64_t    clock_monotonic_ns = 0;  // CLOCK_MONOTONIC at the same instant (ns)
};

struct Manifest {
  std::string   schema_version;   // filled from kSchemaVersion by the writer
  std::string   tool_name;        // filled from kToolName
  std::string   tool_version;     // filled from kToolVersion
  CaptureInfo   capture;
  TargetInfo    target;
  IsolationInfo isolation;
  CoverageInfo  coverage;
  Counts          counts;
  Integrity       integrity;
  BundleSignature sig;      // empty algorithm = unsigned; populated by write_bundle when key available
};

// Serialize to pretty-printed JSON (2-space indent per spec §3).
std::string manifest_to_json(const Manifest& m);

// Parse a manifest JSON string. Enforces the major-version compatibility rule
// (spec §7): rejects bundles whose major > this reader's kSchemaMajor.
// Unknown fields are silently ignored.
// Throws BundleError on parse errors or version incompatibility.
Manifest manifest_from_json(const std::string& json);

} // namespace vishaya::bundle
