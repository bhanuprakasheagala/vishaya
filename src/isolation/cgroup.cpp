#include "isolation/cgroup.h"

#include "common/errors.h"
#include "common/log.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

namespace vishaya::isolation {

namespace {

// Fails fast with a clear, actionable message if the path is not a cgroup v2
// unified hierarchy. Callers discover this before mkdir() so the error names
// the real cause rather than a generic ENOENT / EPERM from a later syscall.
void require_cgroupv2(const char* path) {
  struct statfs st{};
  if (::statfs(path, &st) != 0) {
    throw IsolationError(
        std::string("cannot stat cgroup root '") + path + "': " +
        std::strerror(errno));
  }
  // CGROUP2_SUPER_MAGIC = 0x63677270  (linux/magic.h)
  if (st.f_type != static_cast<decltype(st.f_type)>(0x63677270)) {
    throw IsolationError(
        std::string("cgroup v2 unified hierarchy not mounted at '") + path + "'.\n"
        "Vishaya requires cgroup v2. To enable it:\n"
        "  Ubuntu 22.04+, Fedora 31+, Arch Linux: cgroup v2 is the default;\n"
        "    confirm systemd is running and /sys/fs/cgroup is the unified hierarchy.\n"
        "  Ubuntu 20.04: add 'systemd.unified_cgroup_hierarchy=1' to\n"
        "    GRUB_CMDLINE_LINUX in /etc/default/grub, run update-grub, then reboot.\n"
        "  Override the cgroup root: export VISHAYA_CGROUP_ROOT=<cgroup2-mount-path>");
  }
}

// UUIDv4-ish. Not cryptographic; just uniqueness for the cgroup name.
std::string generate_uuid() {
  std::random_device                        rd;
  std::mt19937_64                           gen(rd());
  std::uniform_int_distribution<uint64_t>   dist;
  const uint64_t a = dist(gen);
  const uint64_t b = dist(gen);
  char buf[37];
  std::snprintf(buf, sizeof(buf),
                "%08lx-%04lx-%04lx-%04lx-%012lx",
                static_cast<unsigned long>((a >> 32) & 0xffffffffULL),
                static_cast<unsigned long>((a >> 16) & 0xffffULL),
                static_cast<unsigned long>(a         & 0xffffULL),
                static_cast<unsigned long>((b >> 48) & 0xffffULL),
                static_cast<unsigned long>(b         & 0x0000ffffffffffffULL));
  return std::string(buf);
}

uint64_t read_cgroup_id(const std::string& path) {
  struct stat st{};
  if (::stat(path.c_str(), &st) != 0) {
    throw IsolationError("stat(" + path + ") failed: " + std::strerror(errno));
  }
  return static_cast<uint64_t>(st.st_ino);
}

} // namespace

const char* Cgroup::root_path() {
  const char* env = std::getenv("VISHAYA_CGROUP_ROOT");
  return env ? env : "/sys/fs/cgroup";
}

Cgroup::Cgroup() {
  require_cgroupv2(root_path());
  const std::string uuid = generate_uuid();
  path_ = std::string(root_path()) + "/vishaya-" + uuid;

  if (::mkdir(path_.c_str(), 0755) != 0) {
    throw IsolationError(
        "mkdir(" + path_ + ") failed: " + std::strerror(errno) +
        " (root required; cgroup v2 unified hierarchy expected at " +
        root_path() + ")");
  }

  owned_ = true;
  id_    = read_cgroup_id(path_);
  log::debug("cgroup created: " + path_ + " (id=" + std::to_string(id_) + ")");
}

Cgroup::~Cgroup() {
  if (!owned_) return;
  if (::rmdir(path_.c_str()) != 0) {
    log::warn("cgroup cleanup failed: rmdir(" + path_ + "): " + std::strerror(errno));
  } else {
    log::debug("cgroup removed: " + path_);
  }
}

Cgroup::Cgroup(Cgroup&& other) noexcept
    : path_(std::move(other.path_)), id_(other.id_), owned_(other.owned_) {
  other.owned_ = false;
  other.id_    = 0;
}

Cgroup& Cgroup::operator=(Cgroup&& other) noexcept {
  if (this != &other) {
    if (owned_) {
      ::rmdir(path_.c_str());
    }
    path_        = std::move(other.path_);
    id_          = other.id_;
    owned_       = other.owned_;
    other.owned_ = false;
    other.id_    = 0;
  }
  return *this;
}

void Cgroup::attach_pid(pid_t pid) const {
  const std::string procs_path = path_ + "/cgroup.procs";
  std::ofstream     out(procs_path);
  if (!out) {
    throw IsolationError("open(" + procs_path + ") failed");
  }
  out << pid << '\n';
  out.flush();
  if (!out) {
    throw IsolationError(
        "write to " + procs_path + " failed (pid=" + std::to_string(pid) +
        "); target process may not exist or cgroup may be frozen");
  }
}

} // namespace vishaya::isolation
