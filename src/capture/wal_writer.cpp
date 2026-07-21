#include "capture/wal_writer.h"

#include "common/errors.h"
#include "common/log.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

namespace vishaya::capture {

namespace {

// Retry-safe full write. Handles EINTR and short writes correctly.
void write_all(int fd, const char* data, size_t len, const std::string& path) {
  size_t off = 0;
  while (off < len) {
    const ssize_t n = ::write(fd, data + off, len - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      throw CaptureError("wal_writer write(" + path +
                         ") failed: " + std::strerror(errno));
    }
    if (n == 0) {
      // Should not happen for regular files; treat as error.
      throw CaptureError("wal_writer write(" + path + ") returned 0");
    }
    off += static_cast<size_t>(n);
  }
}

} // namespace

WalWriter::WalWriter(const std::string& path) : path_(path) {
  fd_ = ::open(path.c_str(),
               O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
               0644);
  if (fd_ < 0) {
    throw CaptureError("wal_writer open(" + path + ") failed: " +
                       std::strerror(errno));
  }
  log::debug("wal opened: " + path);
}

WalWriter::~WalWriter() { close(); }

void WalWriter::write_line(std::string_view line) {
  if (fd_ < 0) {
    throw CaptureError("wal_writer: write_line on closed writer (" + path_ + ")");
  }
  if (line.empty()) return;

  // Single write() call for the line + newline together, satisfying the
  // atomicity guarantee documented in wal_writer.h.
  std::string buf;
  buf.reserve(line.size() + 1);
  buf.append(line);
  buf += '\n';
  write_all(fd_, buf.data(), buf.size(), path_);

  ++lines_written_;
}

void WalWriter::close() {
  if (fd_ < 0) return;
  ::close(fd_);
  fd_ = -1;
}

} // namespace vishaya::capture
