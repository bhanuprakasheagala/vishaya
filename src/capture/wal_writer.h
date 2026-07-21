#pragma once

/*
 * File Notes:
 * - WalWriter: append-only NDJSON writer for the scratch dir during capture.
 *   Each successful call to write_line appends "<json>\n" atomically at the
 *   POSIX level (single write syscall). Flushes on every write for durability
 *   under interruption.
 * - Not thread-safe. If the collector callback ever runs from multiple threads
 *   (it doesn't in libbpf ring_buffer__poll), wrap externally.
 */

#include <cstdint>
#include <string>
#include <string_view>

namespace vishaya::capture {

class WalWriter {
 public:
  // Opens (create/truncate) the WAL file. Throws vishaya::CaptureError on failure.
  explicit WalWriter(const std::string& path);
  ~WalWriter();

  WalWriter(const WalWriter&)            = delete;
  WalWriter& operator=(const WalWriter&) = delete;

  // Appends a single JSON line (does NOT prepend a newline; caller must not
  // include newlines in `line`). Returns without writing if `line` is empty.
  // Throws CaptureError on write failure.
  void write_line(std::string_view line);

  uint64_t lines_written() const noexcept { return lines_written_; }

  // Closes the underlying fd (also happens in destructor).
  void close();

 private:
  int      fd_             = -1;
  uint64_t lines_written_  = 0;
  std::string path_;
};

} // namespace vishaya::capture
