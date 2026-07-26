#include "bundle/reader.h"

#include "bundle/artifacts.h"
#include "bundle/hash.h"
#include "bundle/sign.h"
#include "common/errors.h"
#include "common/log.h"

#include <archive.h>
#include <archive_entry.h>
#include <set>
#include <string>

namespace vishaya::bundle {

namespace {

// RAII wrapper for libarchive read handles. Ensures archive_read_free is
// always called even on exception paths.
class ArchiveReadHandle {
 public:
  explicit ArchiveReadHandle(const std::string& path) {
    a_ = archive_read_new();
    if (!a_) throw BundleError("archive_read_new failed");
    archive_read_support_format_tar(a_);
    archive_read_support_filter_zstd(a_);
    if (archive_read_open_filename(a_, path.c_str(), 65536) != ARCHIVE_OK) {
      const std::string err = archive_error_string(a_)
                                ? archive_error_string(a_) : "unknown";
      archive_read_free(a_);
      throw BundleError("failed to open bundle " + path + ": " + err);
    }
  }
  ~ArchiveReadHandle() { if (a_) archive_read_free(a_); }

  ArchiveReadHandle(const ArchiveReadHandle&)            = delete;
  ArchiveReadHandle& operator=(const ArchiveReadHandle&) = delete;

  archive* get() const noexcept { return a_; }

 private:
  archive* a_ = nullptr;
};

// Advances the archive to the named entry. Returns true if found and the
// archive is positioned to read that entry's data. Returns false only at clean
// end of archive (ARCHIVE_EOF). Throws BundleError on archive corruption /
// fatal read errors (distinguishing "not present" from "cannot be read").
bool find_entry(archive* a, const std::string& target_name) {
  archive_entry* entry = nullptr;
  while (true) {
    const int rc = archive_read_next_header(a, &entry);
    if (rc == ARCHIVE_OK || rc == ARCHIVE_WARN) {
      if (target_name == archive_entry_pathname(entry)) return true;
      archive_read_data_skip(a);
      continue;
    }
    if (rc == ARCHIVE_EOF) return false;
    // ARCHIVE_FATAL, ARCHIVE_FAILED, or unexpected code.
    const std::string err = archive_error_string(a)
                              ? archive_error_string(a) : "unknown";
    throw BundleError("archive_read_next_header error (looking for " +
                      target_name + "): " + err);
  }
}

// Reads all remaining bytes from the currently-positioned entry into a string.
std::string read_entry_bytes(archive* a) {
  std::string out;
  char        buf[65536];
  la_ssize_t  n;
  while ((n = archive_read_data(a, buf, sizeof(buf))) > 0) {
    out.append(buf, static_cast<size_t>(n));
  }
  if (n < 0) {
    const std::string err = archive_error_string(a)
                              ? archive_error_string(a) : "unknown";
    throw BundleError("archive_read_data error: " + err);
  }
  return out;
}

} // namespace

Reader::Reader(const std::string& bundle_path) : bundle_path_(bundle_path) {
  ArchiveReadHandle h(bundle_path_);
  if (!find_entry(h.get(), "manifest.json")) {
    throw BundleError("bundle missing manifest.json: " + bundle_path_);
  }
  const std::string bytes = read_entry_bytes(h.get());
  manifest_ = manifest_from_json(bytes);  // enforces schema major check
  log::debug("bundle opened: " + bundle_path_ +
             " schema=" + manifest_.schema_version +
             " events=" + std::to_string(manifest_.counts.events_total));
}

const ProcessTree& Reader::process_tree() {
  if (process_tree_loaded_) return process_tree_;

  ArchiveReadHandle h(bundle_path_);
  if (!find_entry(h.get(), "process_tree.json")) {
    throw BundleError("bundle missing process_tree.json: " + bundle_path_);
  }
  const std::string bytes = read_entry_bytes(h.get());
  process_tree_        = tree_from_json(bytes);
  process_tree_loaded_ = true;
  return process_tree_;
}

const std::vector<ArtifactRecord>& Reader::artifacts() {
  if (artifacts_loaded_) return artifacts_;

  ArchiveReadHandle h(bundle_path_);
  if (find_entry(h.get(), "artifacts.json")) {
    const std::string bytes = read_entry_bytes(h.get());
    artifacts_ = artifacts_from_json(bytes);
  }
  // Absent artifacts.json → the bundle had no artifact capture; empty is correct.
  artifacts_loaded_ = true;
  return artifacts_;
}

void Reader::for_each_event(
    const std::function<void(const nlohmann::json&)>& cb) {
  ArchiveReadHandle h(bundle_path_);
  if (!find_entry(h.get(), "events.ndjson")) {
    throw BundleError("bundle missing events.ndjson: " + bundle_path_);
  }

  std::string line;
  char        buf[65536];
  la_ssize_t  n;
  size_t      malformed = 0;

  auto flush_line = [&]() {
    if (line.empty()) return;
    try {
      const nlohmann::json j = nlohmann::json::parse(line);
      cb(j);
    } catch (const nlohmann::json::parse_error&) {
      ++malformed;
    }
    line.clear();
  };

  while ((n = archive_read_data(h.get(), buf, sizeof(buf))) > 0) {
    for (la_ssize_t i = 0; i < n; ++i) {
      if (buf[i] == '\n') {
        flush_line();
      } else {
        line.push_back(buf[i]);
      }
    }
  }
  if (n < 0) {
    const std::string err = archive_error_string(h.get())
                              ? archive_error_string(h.get()) : "unknown";
    throw BundleError("archive_read_data on events.ndjson failed: " + err);
  }
  flush_line();  // final line without trailing newline

  if (malformed > 0) {
    log::warn("skipped " + std::to_string(malformed) +
              " malformed event line(s) in " + bundle_path_);
  }
}

bool Reader::verify_integrity() {
  bool ok = true;

  // events.ndjson
  {
    ArchiveReadHandle h(bundle_path_);
    if (!find_entry(h.get(), "events.ndjson")) {
      throw BundleError("bundle missing events.ndjson: " + bundle_path_);
    }
    const std::string bytes = read_entry_bytes(h.get());
    const std::string got   = sha256_hex_of_bytes(bytes);
    if (got != manifest_.integrity.events_sha256) {
      log::warn("integrity mismatch: events.ndjson expected=" +
                manifest_.integrity.events_sha256 + " got=" + got);
      ok = false;
    }
  }

  // process_tree.json
  {
    ArchiveReadHandle h(bundle_path_);
    if (!find_entry(h.get(), "process_tree.json")) {
      throw BundleError("bundle missing process_tree.json: " + bundle_path_);
    }
    const std::string bytes = read_entry_bytes(h.get());
    const std::string got   = sha256_hex_of_bytes(bytes);
    if (got != manifest_.integrity.process_tree_sha256) {
      log::warn("integrity mismatch: process_tree.json expected=" +
                manifest_.integrity.process_tree_sha256 + " got=" + got);
      ok = false;
    }
  }

  return ok;
}

void Reader::verify_artifacts(VerifyReport& report) {
  // Feature off (no index declared) → nothing to check; defaults stay true.
  if (manifest_.integrity.artifacts_index_sha256.empty()) return;

  // 1. artifacts.json integrity against the manifest (itself signed).
  std::string index_bytes;
  {
    ArchiveReadHandle h(bundle_path_);
    if (!find_entry(h.get(), "artifacts.json")) {
      log::warn("manifest declares an artifacts index but artifacts.json is missing");
      report.artifacts_index_ok   = false;
      report.artifacts_content_ok = false;
      return;
    }
    index_bytes = read_entry_bytes(h.get());
  }
  const std::string got = sha256_hex_of_bytes(index_bytes);
  if (got != manifest_.integrity.artifacts_index_sha256) {
    log::warn("integrity mismatch: artifacts.json expected=" +
              manifest_.integrity.artifacts_index_sha256 + " got=" + got);
    report.artifacts_index_ok = false;
  }

  // 2. Per-artifact content. Build the set of expected content hashes (ok records)
  //    from the index, then stream-hash each artifacts/<sha> entry in one archive
  //    pass and confirm it matches both its own filename and the index. Flag any
  //    missing-expected or unexpected entry.
  std::vector<ArtifactRecord> records;
  try {
    records = artifacts_from_json(index_bytes);
  } catch (const BundleError& e) {
    log::warn(std::string("artifacts.json unparseable during verify: ") + e.what());
    report.artifacts_content_ok = false;
    return;
  }
  std::set<std::string> expected;
  for (const auto& r : records) {
    if (r.status == artifact_status::kOk && !r.sha256.empty()) expected.insert(r.sha256);
  }

  std::set<std::string> seen;
  static const std::string kPrefix = "artifacts/";
  ArchiveReadHandle h(bundle_path_);
  archive_entry* entry = nullptr;
  while (true) {
    const int rc = archive_read_next_header(h.get(), &entry);
    if (rc == ARCHIVE_EOF) break;
    if (rc != ARCHIVE_OK && rc != ARCHIVE_WARN) {
      const std::string err = archive_error_string(h.get())
                                ? archive_error_string(h.get()) : "unknown";
      throw BundleError("archive_read_next_header during artifact verify: " + err);
    }
    const char* pn = archive_entry_pathname(entry);
    const std::string name = pn ? pn : "";
    // Only artifact content entries: "artifacts/<sha>", not the dir itself.
    if (name.rfind(kPrefix, 0) != 0 || name == kPrefix) {
      archive_read_data_skip(h.get());
      continue;
    }
    const std::string base = name.substr(kPrefix.size());

    Sha256Streamer hasher;
    char       buf[65536];
    la_ssize_t n;
    while ((n = archive_read_data(h.get(), buf, sizeof(buf))) > 0) {
      hasher.update(buf, static_cast<size_t>(n));
    }
    if (n < 0) {
      const std::string err = archive_error_string(h.get())
                                ? archive_error_string(h.get()) : "unknown";
      throw BundleError("archive_read_data on " + name + " failed: " + err);
    }
    const std::string digest = hasher.finalize_hex();
    seen.insert(base);
    if (digest != base) {
      log::warn("artifact content mismatch: " + name + " hashes to " + digest);
      report.artifacts_content_ok = false;
    } else if (expected.find(base) == expected.end()) {
      log::warn("unexpected artifact entry not listed in index: " + name);
      report.artifacts_content_ok = false;
    }
  }
  for (const auto& sha : expected) {
    if (seen.find(sha) == seen.end()) {
      log::warn("artifact declared in index but missing from bundle: artifacts/" + sha);
      report.artifacts_content_ok = false;
    }
  }
}

VerifyReport Reader::verify() {
  VerifyReport report;

  // 1. Content integrity: recompute both hashes and compare to the manifest.
  //    verify_integrity() logs a warning per mismatch.
  report.integrity_ok = verify_integrity();

  // 1b. Artifact integrity (index hash + each artifact's content). No-op when the
  //     bundle has no artifact capture.
  verify_artifacts(report);

  // 2. Signature (when present). We reconstruct exactly what the writer signed
  //    (spec §6), which depends on sig.scope (see the branch below), then verify.
  //    The signed payload always includes the content hashes, so combined with
  //    step 1 (hashes match content) a valid signature means the content — and,
  //    for manifest-v1, the metadata — matches what was signed.
  report.signature_present = !manifest_.sig.algorithm.empty();
  if (report.signature_present) {
    // Reconstruct exactly what the writer signed. New bundles ("manifest-v1")
    // sign the canonical manifest (metadata + content hashes); legacy bundles
    // signed only the two content hashes. Branch so old bundles still verify.
    std::string signed_payload;
    if (manifest_.sig.scope == "manifest-v1") {
      signed_payload = manifest_signing_payload(manifest_);
    } else {
      signed_payload = manifest_.integrity.events_sha256 + "\n" +
                       manifest_.integrity.process_tree_sha256 + "\n";
    }
    report.signature_ok = verify_signature(manifest_.sig, signed_payload);
    if (report.signature_ok) {
      log::debug("bundle signature verified (Ed25519, scope=" +
                 (manifest_.sig.scope.empty() ? std::string("legacy")
                                              : manifest_.sig.scope) +
                 ", key " + pubkey_fingerprint(manifest_.sig.pubkey_b64) + ")");
    } else {
      log::warn("bundle signature INVALID (" + manifest_.sig.algorithm +
                "): signed content does not match the signature — bundle may be "
                "tampered or corrupt");
    }
  } else {
    // Spec §6: unsigned bundles are valid but the reader SHOULD notify the user.
    log::info("bundle is unsigned (no signature block present)");
  }

  return report;
}

} // namespace vishaya::bundle
