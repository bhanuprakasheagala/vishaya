#pragma once

/*
 * File Notes:
 * - Collects the files a target created/modified during a capture and copies the
 *   survivors into the bundle's artifacts/ directory (content-addressed + hashed).
 * - Two phases: observe() runs on the poll thread per file_event (cheap, records
 *   candidate absolute paths); finalize() runs once after the target exits and
 *   does the actual copy+hash with bounds. See docs/bundle-spec-v0.1.md.
 */

#include "bundle/artifacts.h"
#include "event_schema.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace vishaya::capture {

// Bounds on how much is captured. All CLI-overridable (see capture_cmd).
struct ArtifactConfig {
  uint64_t max_file_bytes  = 100ull * 1024 * 1024;  // skip a single file above this
  uint64_t max_total_bytes = 500ull * 1024 * 1024;  // stop copying past this total
  uint64_t max_count       = 1000;                  // max files copied
  uint64_t max_candidates  = 100000;                // in-memory dedup-set cap (DoS guard)
};

class ArtifactCollector {
 public:
  explicit ArtifactCollector(ArtifactConfig cfg);

  // Called on the poll thread for every decoded file_event. Cheap and never
  // throws: it records write-intent / rename-destination ABSOLUTE paths into a
  // deduped candidate set, copying the path bytes out of `e` (holds no reference).
  void observe(const file_event& e) noexcept;

  // Called ONCE after the target has exited and the session is stopped. Copies
  // each surviving regular file into <artifacts_dir> content-addressed as its
  // SHA-256, enforcing per-file / total / count bounds. Returns one record per
  // distinct content (source_paths merged) plus records for skipped/errored
  // candidates, for forensic transparency. artifacts_dir must already exist.
  std::vector<bundle::ArtifactRecord> finalize(const std::string& artifacts_dir);

  size_t candidate_count() const noexcept { return candidates_.size(); }
  bool   candidates_truncated() const noexcept { return truncated_; }

 private:
  ArtifactConfig        cfg_;
  std::set<std::string> candidates_;      // absolute paths, insertion-deduped, sorted
  bool                  truncated_ = false;  // max_candidates hit → some paths dropped
};

} // namespace vishaya::capture
