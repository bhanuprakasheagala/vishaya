#pragma once

/*
 * File Notes:
 * - Bundle writer: takes a scratch dir + partial manifest and produces a
 *   .vishaya file (tar.zst) atomically. Follows docs/BUNDLE-SPEC-v0.1.md.
 * - Writer fills in: manifest.integrity (both sha256s), manifest.counts.processes_seen,
 *   manifest.schema_version, manifest.tool_name, manifest.tool_version. Caller
 *   fills everything else.
 * - Atomicity: writes to <bundle_path>.tmp, fsyncs, then renames.
 */

#include "bundle/artifacts.h"
#include "bundle/manifest.h"

#include <cstdint>
#include <string>
#include <vector>

namespace vishaya::bundle {

struct WriterInput {
  // Scratch directory containing events.ndjson (produced during capture).
  // The writer also writes process_tree.json and manifest.json into this dir
  // before archiving. Caller owns cleanup of the scratch dir.
  std::string scratch_dir;

  // Final bundle path (e.g. /path/to/case.vishaya).
  std::string bundle_path;

  // Partial manifest — writer fills integrity, counts.processes_seen, and
  // version/name fields.
  Manifest manifest;

  // Root TGID of the target for process tree reconstruction.
  int32_t root_pid = 0;

  // Artifact capture (optional). When enabled, the writer emits artifacts.json,
  // streams each "ok" record's staged file from artifacts_dir into
  // artifacts/<sha256>, and sets manifest.integrity.artifacts_index_sha256 (which
  // the signature then covers). When disabled, none of this is written and the
  // bundle is byte-compatible with pre-artifact bundles.
  bool                        capture_artifacts_enabled = false;
  std::string                 artifacts_dir;  // dir holding staged artifacts/<sha256> files
  std::vector<ArtifactRecord> artifacts;      // index records (incl. skipped/errored)
};

// Write the bundle atomically. Modifies input.manifest in place.
// Throws BundleError on any failure.
void write_bundle(WriterInput& input);

} // namespace vishaya::bundle
