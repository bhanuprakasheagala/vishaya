#include "bundle/writer.h"

#include "bundle/hash.h"
#include "bundle/process_tree.h"
#include "bundle/schema_version.h"
#include "bundle/sign.h"
#include "common/errors.h"
#include "common/log.h"

#include <archive.h>
#include <archive_entry.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace vishaya::bundle {

namespace {

void write_string_to_file(const std::string& path, const std::string& content) {
  std::ofstream out(path, std::ios::binary);
  if (!out) throw BundleError("open for writing failed: " + path);
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  if (!out) throw BundleError("write failed: " + path);
}

uint64_t file_size(const std::string& path) {
  struct stat st{};
  if (::stat(path.c_str(), &st) != 0) {
    throw BundleError("stat failed: " + path + ": " + std::strerror(errno));
  }
  return static_cast<uint64_t>(st.st_size);
}

void add_bytes_entry(archive*           a,
                     const std::string& entry_path,
                     const void*        data,
                     size_t             size,
                     mode_t             mode = 0644) {
  archive_entry* entry = archive_entry_new();
  archive_entry_set_pathname(entry, entry_path.c_str());
  archive_entry_set_size(entry, static_cast<la_int64_t>(size));
  archive_entry_set_filetype(entry, AE_IFREG);
  archive_entry_set_perm(entry, mode);

  if (archive_write_header(a, entry) != ARCHIVE_OK) {
    const std::string err = archive_error_string(a) ? archive_error_string(a) : "";
    archive_entry_free(entry);
    throw BundleError("archive_write_header(" + entry_path + ") failed: " + err);
  }
  if (size > 0) {
    if (archive_write_data(a, data, size) < 0) {
      const std::string err = archive_error_string(a) ? archive_error_string(a) : "";
      archive_entry_free(entry);
      throw BundleError("archive_write_data(" + entry_path + ") failed: " + err);
    }
  }
  archive_entry_free(entry);
}

void add_file_entry_streaming(archive*           a,
                              const std::string& entry_path,
                              const std::string& disk_path,
                              mode_t             mode = 0644) {
  const uint64_t size = file_size(disk_path);
  archive_entry* entry = archive_entry_new();
  archive_entry_set_pathname(entry, entry_path.c_str());
  archive_entry_set_size(entry, static_cast<la_int64_t>(size));
  archive_entry_set_filetype(entry, AE_IFREG);
  archive_entry_set_perm(entry, mode);

  if (archive_write_header(a, entry) != ARCHIVE_OK) {
    const std::string err = archive_error_string(a) ? archive_error_string(a) : "";
    archive_entry_free(entry);
    throw BundleError("archive_write_header(" + entry_path + ") failed: " + err);
  }

  std::ifstream in(disk_path, std::ios::binary);
  if (!in) {
    archive_entry_free(entry);
    throw BundleError("open for streaming into archive failed: " + disk_path);
  }

  char buf[65536];
  while (in) {
    in.read(buf, sizeof(buf));
    const std::streamsize got = in.gcount();
    if (got > 0) {
      if (archive_write_data(a, buf, static_cast<size_t>(got)) < 0) {
        const std::string err = archive_error_string(a) ? archive_error_string(a) : "";
        archive_entry_free(entry);
        throw BundleError("archive_write_data streaming(" + entry_path +
                          ") failed: " + err);
      }
    }
  }
  archive_entry_free(entry);
}

void add_dir_entry(archive*           a,
                   const std::string& entry_path,
                   mode_t             mode = 0755) {
  archive_entry* entry = archive_entry_new();
  archive_entry_set_pathname(entry, entry_path.c_str());
  archive_entry_set_size(entry, 0);
  archive_entry_set_filetype(entry, AE_IFDIR);
  archive_entry_set_perm(entry, mode);
  if (archive_write_header(a, entry) != ARCHIVE_OK) {
    const std::string err = archive_error_string(a) ? archive_error_string(a) : "";
    archive_entry_free(entry);
    throw BundleError("archive_write_header(dir " + entry_path + ") failed: " + err);
  }
  archive_entry_free(entry);
}

} // namespace

void write_bundle(WriterInput& input) {
  const std::string events_path   = input.scratch_dir + "/events.ndjson";
  const std::string tree_path     = input.scratch_dir + "/process_tree.json";
  const std::string manifest_path = input.scratch_dir + "/manifest.json";
  const std::string tmp_bundle    = input.bundle_path + ".tmp";

  // 1. Reconstruct process tree, write it to scratch dir.
  const ProcessTree tree      = reconstruct_tree(events_path, input.root_pid);
  const std::string tree_json = tree_to_json(tree);
  write_string_to_file(tree_path, tree_json);
  input.manifest.counts.processes_seen = tree.processes.size();

  // 2. Compute integrity hashes.
  input.manifest.integrity.events_sha256       = sha256_hex_of_file(events_path);
  input.manifest.integrity.process_tree_sha256 = sha256_hex_of_file(tree_path);

  // 2b. Sign the two integrity hashes. Best-effort: a missing or unreadable key
  // just means the bundle is unsigned. The signed payload is the two hex digests
  // separated by a newline — stable, deterministic, and easy to reproduce offline.
  {
    std::string pem_key;
    if (load_or_generate_signing_key(pem_key)) {
      const std::string signed_payload =
          input.manifest.integrity.events_sha256 + "\n" +
          input.manifest.integrity.process_tree_sha256 + "\n";
      input.manifest.sig = sign_data(pem_key, signed_payload);
      if (!input.manifest.sig.algorithm.empty()) {
        log::info("bundle signed with Ed25519 key (pubkey=" +
                  input.manifest.sig.pubkey_b64.substr(0, 12) + "...)");
      }
    } else {
      log::warn("bundle signing skipped: could not load or generate signing key");
    }
  }

  // 3. Fill in schema/tool identity, serialize manifest.
  input.manifest.schema_version = kSchemaVersion;
  input.manifest.tool_name      = kToolName;
  input.manifest.tool_version   = kToolVersion;
  const std::string manifest_json = manifest_to_json(input.manifest);
  write_string_to_file(manifest_path, manifest_json);

  // 4. Build tar.zst archive at <path>.tmp.
  archive* a = archive_write_new();
  if (!a) throw BundleError("archive_write_new failed");

  auto cleanup_and_throw = [&](const std::string& msg) {
    archive_write_free(a);
    ::unlink(tmp_bundle.c_str());
    throw BundleError(msg);
  };

  if (archive_write_set_format_ustar(a) != ARCHIVE_OK) {
    cleanup_and_throw("archive_write_set_format_ustar failed");
  }
  if (archive_write_add_filter_zstd(a) != ARCHIVE_OK) {
    cleanup_and_throw("archive_write_add_filter_zstd failed");
  }
  if (archive_write_set_filter_option(a, "zstd", "compression-level", "3") != ARCHIVE_OK) {
    const std::string err = archive_error_string(a) ? archive_error_string(a) : "";
    cleanup_and_throw("zstd compression-level set failed: " + err);
  }
  if (archive_write_open_filename(a, tmp_bundle.c_str()) != ARCHIVE_OK) {
    const std::string err = archive_error_string(a) ? archive_error_string(a) : "";
    cleanup_and_throw("archive_write_open_filename failed: " + err);
  }

  try {
    // Order matters (spec §2): manifest.json first.
    add_bytes_entry(a, "manifest.json",
                    manifest_json.data(), manifest_json.size());
    add_file_entry_streaming(a, "events.ndjson", events_path);
    add_bytes_entry(a, "process_tree.json",
                    tree_json.data(), tree_json.size());
    add_dir_entry(a, "artifacts/");
  } catch (...) {
    archive_write_close(a);
    archive_write_free(a);
    ::unlink(tmp_bundle.c_str());
    throw;
  }

  if (archive_write_close(a) != ARCHIVE_OK) {
    const std::string err = archive_error_string(a) ? archive_error_string(a) : "";
    archive_write_free(a);
    ::unlink(tmp_bundle.c_str());
    throw BundleError("archive_write_close failed: " + err);
  }
  archive_write_free(a);

  // 5. fsync then atomic rename. fsync must succeed to guarantee durability
  // before the rename becomes visible.
  {
    const int fd = ::open(tmp_bundle.c_str(), O_RDONLY);
    if (fd < 0) {
      const int saved_errno = errno;
      ::unlink(tmp_bundle.c_str());
      throw BundleError(
          "open for fsync failed: " + std::string(std::strerror(saved_errno)));
    }
    if (::fsync(fd) != 0) {
      const int saved_errno = errno;
      ::close(fd);
      ::unlink(tmp_bundle.c_str());
      throw BundleError(
          "fsync failed: " + std::string(std::strerror(saved_errno)));
    }
    ::close(fd);
  }
  if (::rename(tmp_bundle.c_str(), input.bundle_path.c_str()) != 0) {
    const int saved_errno = errno;
    ::unlink(tmp_bundle.c_str());
    throw BundleError("rename to final bundle failed: " +
                      std::string(std::strerror(saved_errno)));
  }

  log::info("bundle written: " + input.bundle_path +
            " (events=" + std::to_string(input.manifest.counts.events_total) +
            ", processes=" + std::to_string(input.manifest.counts.processes_seen) + ")");
}

} // namespace vishaya::bundle
