#pragma once

/*
 * File Notes:
 * - Reader for .vishaya bundles. Opens the tar.zst container, parses
 *   manifest.json on construction (enforcing schema version compat per spec §7),
 *   lazy-loads process_tree.json on first access, and streams events.ndjson
 *   through a caller-provided callback.
 * - Not thread-safe. One Reader per bundle per thread.
 */

#include "bundle/artifacts.h"
#include "bundle/manifest.h"
#include "bundle/process_tree.h"

#include <functional>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace vishaya::bundle {

// Outcome of a bundle verification pass. `ok()` is the overall verdict a caller
// should act on: integrity must hold, and if a signature is present it must
// verify. An unsigned bundle with matching hashes is `ok()` (signatures are
// optional per spec §3.2), but callers may still choose to warn on absence.
struct VerifyReport {
  bool integrity_ok       = false;  // both content hashes matched the manifest
  bool signature_present  = false;  // manifest carried a signature block
  bool signature_ok       = false;  // signature verified (only if present)
  // Artifact checks default to true so bundles without artifact capture pass.
  bool artifacts_index_ok   = true; // artifacts.json matched integrity.artifacts_index_sha256
  bool artifacts_content_ok = true; // every artifacts/<sha> matched its name + the index

  bool ok() const noexcept {
    return integrity_ok && artifacts_index_ok && artifacts_content_ok &&
           (!signature_present || signature_ok);
  }
};

class Reader {
 public:
  // Opens the bundle, extracts and parses manifest.json.
  // Throws BundleError on: file not found, archive format error, missing
  // manifest.json, JSON parse error, or unsupported schema major version.
  explicit Reader(const std::string& bundle_path);
  ~Reader() = default;

  Reader(const Reader&)            = delete;
  Reader& operator=(const Reader&) = delete;

  const Manifest&    manifest()     const noexcept { return manifest_; }
  const std::string& bundle_path()  const noexcept { return bundle_path_; }

  // Returns the reconstructed process tree. Extracted and parsed on first call,
  // cached thereafter. Throws BundleError if process_tree.json is missing or
  // malformed.
  const ProcessTree& process_tree();

  // Returns the captured-artifact index (artifacts.json), parsed on first call
  // and cached. Empty when the bundle was produced without artifact capture (no
  // artifacts.json) — that is not an error. Throws BundleError if artifacts.json
  // is present but malformed.
  const std::vector<ArtifactRecord>& artifacts();

  // Streams events.ndjson through the callback in file order. Each call to cb
  // receives one parsed JSON event. Malformed lines are silently skipped
  // (logged at debug level). Callback exceptions propagate out.
  // Throws BundleError if events.ndjson is missing or the archive read fails.
  void for_each_event(const std::function<void(const nlohmann::json&)>& cb);

  // Recomputes SHA-256 of events.ndjson and process_tree.json in the archive
  // and compares against manifest.integrity. Returns true if both match.
  // Logs a warning per mismatch. Does not throw on hash mismatch (returns
  // false); does throw on archive read failure.
  bool verify_integrity();

  // Full verification at load time (spec §9, items 4-5): runs verify_integrity()
  // and, when the manifest carries a signature, verifies it (spec §3.2 requires
  // verifying a signature when present; §6 defines the signed payload). Logs a
  // clear warning for each failure and a debug line on success. Non-fatal —
  // returns a VerifyReport so callers decide policy. Throws BundleError only on
  // archive read failure (a structurally unreadable bundle, not a hash/sig
  // mismatch).
  VerifyReport verify();

 private:
  // Verifies artifacts.json integrity and each artifacts/<sha> entry's content
  // against its name and the index. No-op (leaves report defaults) when the
  // manifest declares no artifact index. May throw BundleError on archive read
  // failure (not on a hash mismatch, which sets the report flags false).
  void verify_artifacts(VerifyReport& report);

  std::string                 bundle_path_;
  Manifest                    manifest_;
  // Raw manifest.json bytes as stored in the bundle. Kept so a "manifest-v1"
  // signature is verified over the exact on-disk canonical bytes (spec §6),
  // preserving fields this build doesn't model — see manifest_canonical_signing_payload().
  std::string                 manifest_raw_json_;
  ProcessTree                 process_tree_;
  bool                        process_tree_loaded_ = false;
  std::vector<ArtifactRecord> artifacts_;
  bool                        artifacts_loaded_    = false;
};

} // namespace vishaya::bundle
