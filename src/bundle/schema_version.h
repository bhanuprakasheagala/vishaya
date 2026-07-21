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

constexpr const char* kSchemaVersion = "0.1.0";
constexpr int         kSchemaMajor   = 0;
constexpr int         kSchemaMinor   = 1;
constexpr int         kSchemaPatch   = 0;

constexpr const char* kToolName    = "vishaya";
constexpr const char* kToolVersion = "0.1.0";

} // namespace vishaya::bundle
