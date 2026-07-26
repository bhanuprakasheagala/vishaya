#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vishaya::bundle {

// One captured (or attempted) artifact — a file the target created or modified.
// Serialized into the bundle's artifacts.json index. Content-addressed: for an
// "ok" record, `sha256` is also the tar entry basename (artifacts/<sha256>).
struct ArtifactRecord {
  std::string              sha256;        // 64 lowercase hex; "" unless status=="ok"
  uint64_t                 size = 0;      // file size at copy time, bytes
  uint32_t                 mode = 0;      // st_mode & 07777 (permission bits)
  std::vector<std::string> source_paths; // absolute path(s) that produced this content
  std::string              status;        // see artifact_status below
};

// Stable, additive status vocabulary. Only "ok" records have bytes in the bundle.
namespace artifact_status {
inline constexpr const char* kOk            = "ok";
inline constexpr const char* kTooLarge      = "skipped_too_large";
inline constexpr const char* kSymlink       = "skipped_symlink";
inline constexpr const char* kSpecial       = "skipped_special";
inline constexpr const char* kBoundExceeded = "skipped_bound_exceeded";
inline constexpr const char* kMissing       = "missing_at_finalize";
inline constexpr const char* kUnreadable    = "error_unreadable";
} // namespace artifact_status

// Serialize records to the canonical artifacts.json (a JSON array). Uses the
// UTF-8 'replace' handler because source_paths are raw kernel bytes and may not
// be valid UTF-8. An empty vector serializes to "[]".
std::string artifacts_to_json(const std::vector<ArtifactRecord>& records);

// Parse artifacts.json into records. Throws BundleError on malformed JSON or a
// field of unexpected type (mirrors manifest_from_json's contract).
std::vector<ArtifactRecord> artifacts_from_json(const std::string& jstr);

} // namespace vishaya::bundle
