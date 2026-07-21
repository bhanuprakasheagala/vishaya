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

#include "bundle/manifest.h"

#include <cstdint>
#include <string>

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
};

// Write the bundle atomically. Modifies input.manifest in place.
// Throws BundleError on any failure.
void write_bundle(WriterInput& input);

} // namespace vishaya::bundle
