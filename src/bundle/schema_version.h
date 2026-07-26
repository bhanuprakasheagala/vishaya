#pragma once

/*
 * File Notes:
 * - Single source of truth for bundle schema and tool version strings. Both the
 *   writer and reader import these; bumping a version means editing here and
 *   updating docs/BUNDLE-SPEC-v0.1.md.
 * - Format: semver. Major-version bumps are breaking (readers reject bundles
 *   with a newer major than they support).
 */

namespace vishaya::bundle {

// 0.2.0 (additive minor): adds optional artifact capture — artifacts.json,
// integrity.artifacts_index_sha256, coverage.artifacts_captured, and
// artifacts/<sha256> entries. Major stays 0, so 0.1 readers still open 0.2
// bundles (ignoring the new fields) and 0.2 readers still open 0.1 bundles.
constexpr const char* kSchemaVersion = "0.2.0";
constexpr int         kSchemaMajor   = 0;
constexpr int         kSchemaMinor   = 2;
constexpr int         kSchemaPatch   = 0;

constexpr const char* kToolName    = "vishaya";
constexpr const char* kToolVersion = "0.2.0";

} // namespace vishaya::bundle
