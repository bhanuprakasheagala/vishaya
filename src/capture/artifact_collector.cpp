#include "capture/artifact_collector.h"

#include "bundle/hash.h"

#include <cerrno>
#include <cstdio>       // std::rename
#include <cstring>      // strnlen
#include <fcntl.h>
#include <map>
#include <sys/stat.h>
#include <unistd.h>

namespace vishaya::capture {

namespace {

// Bounded conversion of a fixed-size, NUL-terminated kernel char buffer to a
// std::string (defends against a missing terminator).
std::string bounded(const char* buf, size_t cap) {
  return std::string(buf, ::strnlen(buf, cap));
}

// A path is a usable artifact candidate only if absolute — relative / fd-relative
// paths need the target cwd + fd table to resolve (deferred; see C-02).
bool is_absolute(const std::string& p) { return !p.empty() && p[0] == '/'; }

} // namespace

ArtifactCollector::ArtifactCollector(ArtifactConfig cfg) : cfg_(cfg) {}

void ArtifactCollector::observe(const file_event& e) noexcept {
  try {
    if (e.ret < 0) return;  // only successful operations produced/renamed a file

    std::string path;
    if (e.kind == FILE_OPENAT) {
      // Write intent: created (O_CREAT) or opened for writing (O_WRONLY/O_RDWR).
      if ((e.flags & (O_CREAT | O_WRONLY | O_RDWR)) == 0) return;
      path = bounded(e.path_a, VISHAYA_PATH_LEN);
    } else if (e.kind == FILE_RENAMEAT2) {
      path = bounded(e.path_b, VISHAYA_PATH_LEN);  // destination = the file now present
    } else {
      return;  // unlinkat and everything else are not artifact producers
    }

    if (!is_absolute(path)) return;

    if (candidates_.size() >= cfg_.max_candidates) {
      truncated_ = true;
      return;
    }
    candidates_.insert(std::move(path));
  } catch (...) {
    // observe() is best-effort and must never disturb the capture pipeline; a
    // dropped candidate (e.g. on allocation failure) is acceptable.
  }
}

std::vector<bundle::ArtifactRecord> ArtifactCollector::finalize(
    const std::string& artifacts_dir) {
  std::vector<bundle::ArtifactRecord> records;
  std::map<std::string, size_t> by_sha;  // sha256 -> index into records (dedup)
  uint64_t total_bytes = 0;
  uint64_t ok_count    = 0;

  const std::string tmp_path = artifacts_dir + "/.staging.tmp";

  // candidates_ is a std::set → already sorted, so which files land under the
  // bounds is deterministic across runs.
  for (const std::string& path : candidates_) {
    bundle::ArtifactRecord rec;
    rec.source_paths.push_back(path);

    struct stat st{};
    if (::lstat(path.c_str(), &st) != 0) {
      rec.status = (errno == ENOENT) ? bundle::artifact_status::kMissing
                                     : bundle::artifact_status::kUnreadable;
      records.push_back(std::move(rec));
      continue;
    }
    if (S_ISLNK(st.st_mode)) {  // never follow: a target could symlink to /etc/shadow
      rec.status = bundle::artifact_status::kSymlink;
      records.push_back(std::move(rec));
      continue;
    }
    if (!S_ISREG(st.st_mode)) {  // dir / socket / fifo / device
      rec.status = bundle::artifact_status::kSpecial;
      records.push_back(std::move(rec));
      continue;
    }

    const uint64_t size = static_cast<uint64_t>(st.st_size);
    rec.size = size;
    rec.mode = static_cast<uint32_t>(st.st_mode & 07777);

    if (size > cfg_.max_file_bytes) {
      rec.status = bundle::artifact_status::kTooLarge;
      records.push_back(std::move(rec));
      continue;
    }
    if (ok_count >= cfg_.max_count || total_bytes + size > cfg_.max_total_bytes) {
      rec.status = bundle::artifact_status::kBoundExceeded;
      records.push_back(std::move(rec));
      continue;
    }

    // Copy + hash in a single read pass. O_NOFOLLOW guards a symlink swapped in
    // for the final component after the lstat above (TOCTOU); intermediate
    // symlinked directories are out of scope for v0.2.
    const int in_fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (in_fd < 0) {
      rec.status = (errno == ENOENT) ? bundle::artifact_status::kMissing
                                     : bundle::artifact_status::kUnreadable;
      records.push_back(std::move(rec));
      continue;
    }
    const int out_fd =
        ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out_fd < 0) {
      ::close(in_fd);
      rec.status = bundle::artifact_status::kUnreadable;
      records.push_back(std::move(rec));
      continue;
    }

    bundle::Sha256Streamer hasher;
    bool     io_ok     = true;
    bool     too_large = false;
    uint64_t copied    = 0;
    char     buf[65536];
    for (;;) {
      const ssize_t n = ::read(in_fd, buf, sizeof(buf));
      if (n < 0) {
        if (errno == EINTR) continue;
        io_ok = false;
        break;
      }
      if (n == 0) break;
      // Write the whole chunk (handle short writes).
      ssize_t off = 0;
      while (off < n) {
        const ssize_t w = ::write(out_fd, buf + off, static_cast<size_t>(n - off));
        if (w < 0) {
          if (errno == EINTR) continue;
          io_ok = false;
          break;
        }
        off += w;
      }
      if (!io_ok) break;
      hasher.update(buf, static_cast<size_t>(n));
      copied += static_cast<uint64_t>(n);
      // Hard cap during copy: the lstat size check above can be defeated by a
      // file that grows after we stat it, so enforce the per-file bound here too.
      if (copied > cfg_.max_file_bytes) {
        too_large = true;
        break;
      }
    }
    ::close(in_fd);
    ::close(out_fd);

    if (too_large) {
      ::unlink(tmp_path.c_str());
      rec.status = bundle::artifact_status::kTooLarge;
      records.push_back(std::move(rec));
      continue;
    }
    if (!io_ok) {
      ::unlink(tmp_path.c_str());
      rec.status = bundle::artifact_status::kUnreadable;
      records.push_back(std::move(rec));
      continue;
    }

    const std::string sha = hasher.finalize_hex();
    rec.size = copied;  // bytes actually captured (source may differ from lstat size)

    // Content dedup: identical content from a different path merges into the
    // existing record and is not recopied or recounted against the bounds.
    auto existing = by_sha.find(sha);
    if (existing != by_sha.end()) {
      ::unlink(tmp_path.c_str());
      records[existing->second].source_paths.push_back(path);
      continue;
    }

    const std::string final_path = artifacts_dir + "/" + sha;
    if (::rename(tmp_path.c_str(), final_path.c_str()) != 0) {
      ::unlink(tmp_path.c_str());
      rec.status = bundle::artifact_status::kUnreadable;
      records.push_back(std::move(rec));
      continue;
    }

    rec.sha256 = sha;
    rec.status = bundle::artifact_status::kOk;
    total_bytes += copied;
    ++ok_count;
    by_sha.emplace(sha, records.size());
    records.push_back(std::move(rec));
  }

  // Best-effort cleanup: the staging temp can remain if the final candidate
  // deduped or errored after it was written. It is never streamed into the
  // bundle (the writer only adds artifacts/<valid-sha>), but leave the dir tidy.
  ::unlink(tmp_path.c_str());
  return records;
}

} // namespace vishaya::capture
