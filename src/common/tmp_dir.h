#pragma once

/*
 * File Notes:
 * - RAII scratch directory. Creates a unique directory under a caller-chosen
 *   base (default: /tmp) on construction; recursively removes it on
 *   destruction unless keep() has been called (useful for post-mortem
 *   debugging).
 * - Move-only.
 */

#include <string>

namespace vishaya::common {

class TmpDir {
 public:
  // Creates <base>/<prefix>-<uuid>/ with mode 0700.
  // base defaults to /tmp; prefix defaults to "vishaya".
  // Throws vishaya::Error on failure.
  explicit TmpDir(std::string prefix = "vishaya",
                  std::string base   = "/tmp");

  // Removes the directory recursively unless keep() was called. Logs a warning
  // on cleanup failure but does not throw.
  ~TmpDir();

  TmpDir(const TmpDir&)            = delete;
  TmpDir& operator=(const TmpDir&) = delete;
  TmpDir(TmpDir&& other) noexcept;
  TmpDir& operator=(TmpDir&& other) noexcept;

  // Suppress cleanup on destruction. Useful when the scratch dir should be
  // preserved for debugging a failed capture.
  void keep() noexcept { owned_ = false; }

  const std::string& path() const noexcept { return path_; }

 private:
  std::string path_;
  bool        owned_ = false;
};

} // namespace vishaya::common
