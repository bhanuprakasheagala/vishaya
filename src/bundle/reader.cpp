#include "bundle/reader.h"

#include "bundle/hash.h"
#include "bundle/sign.h"
#include "common/errors.h"
#include "common/log.h"

#include <archive.h>
#include <archive_entry.h>
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

VerifyReport Reader::verify() {
  VerifyReport report;

  // 1. Content integrity: recompute both hashes and compare to the manifest.
  //    verify_integrity() logs a warning per mismatch.
  report.integrity_ok = verify_integrity();

  // 2. Signature (when present). The signed payload is exactly what the writer
  //    signed (spec §6): the two stored hex digests, each followed by '\n'.
  //    Note we sign/verify the manifest's *stored* hashes; combined with step 1
  //    (stored hashes match content), a valid signature means the content
  //    matches what was signed.
  report.signature_present = !manifest_.sig.algorithm.empty();
  if (report.signature_present) {
    const std::string signed_payload =
        manifest_.integrity.events_sha256 + "\n" +
        manifest_.integrity.process_tree_sha256 + "\n";
    report.signature_ok = verify_signature(manifest_.sig, signed_payload);
    if (report.signature_ok) {
      log::debug("bundle signature verified (Ed25519, pubkey=" +
                 manifest_.sig.pubkey_b64.substr(0, 12) + "...)");
    } else {
      log::warn("bundle signature INVALID (" + manifest_.sig.algorithm +
                "): manifest hashes do not match the signature — bundle may be "
                "tampered or corrupt");
    }
  } else {
    // Spec §6: unsigned bundles are valid but the reader SHOULD notify the user.
    log::info("bundle is unsigned (no signature block present)");
  }

  return report;
}

} // namespace vishaya::bundle
