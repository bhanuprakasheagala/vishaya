#include "common/tmp_dir.h"

#include "common/errors.h"
#include "common/log.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <sys/stat.h>

namespace vishaya::common {

namespace {

std::string generate_suffix() {
  std::random_device                        rd;
  std::mt19937_64                           gen(rd());
  std::uniform_int_distribution<uint64_t>   dist;
  const uint64_t a = dist(gen);
  const uint64_t b = dist(gen);
  char buf[33];
  std::snprintf(buf, sizeof(buf), "%016lx%016lx",
                static_cast<unsigned long>(a),
                static_cast<unsigned long>(b));
  return std::string(buf);
}

} // namespace

TmpDir::TmpDir(std::string prefix, std::string base) {
  path_ = base + "/" + prefix + "-" + generate_suffix();
  if (::mkdir(path_.c_str(), 0700) != 0) {
    throw Error("mkdir(" + path_ + ") failed: " + std::strerror(errno));
  }
  owned_ = true;
  log::debug("tmpdir created: " + path_);
}

TmpDir::~TmpDir() {
  if (!owned_) return;
  std::error_code ec;
  const auto      removed = std::filesystem::remove_all(path_, ec);
  if (ec) {
    log::warn("tmpdir cleanup failed: " + path_ + ": " + ec.message());
  } else {
    log::debug("tmpdir removed: " + path_ +
               " (" + std::to_string(removed) + " entries)");
  }
}

TmpDir::TmpDir(TmpDir&& other) noexcept
    : path_(std::move(other.path_)), owned_(other.owned_) {
  other.owned_ = false;
}

TmpDir& TmpDir::operator=(TmpDir&& other) noexcept {
  if (this != &other) {
    if (owned_) {
      std::error_code ec;
      std::filesystem::remove_all(path_, ec);
    }
    path_        = std::move(other.path_);
    owned_       = other.owned_;
    other.owned_ = false;
  }
  return *this;
}

} // namespace vishaya::common
