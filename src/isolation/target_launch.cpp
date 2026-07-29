#include "isolation/target_launch.h"

#include "common/errors.h"
#include "common/log.h"
#include "isolation/cgroup.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

extern char** environ;

namespace vishaya::isolation {

namespace {

int build_unshare_flags(const NamespaceFlags& ns) {
  int flags = 0;
  if (ns.mount) flags |= CLONE_NEWNS;
  if (ns.pid)   flags |= CLONE_NEWPID;
  if (ns.net)   flags |= CLONE_NEWNET;
  if (ns.uts)   flags |= CLONE_NEWUTS;
  if (ns.ipc)   flags |= CLONE_NEWIPC;
  return flags;
}

// Builds a null-terminated argv from a binary path + args, with argv[0] set to
// basename(binary). storage owns the strings that argv points into.
std::vector<char*> make_c_argv(const std::string&              binary,
                               const std::vector<std::string>& args,
                               std::vector<std::string>&       storage) {
  const auto slash = binary.find_last_of('/');
  storage.push_back(slash == std::string::npos ? binary : binary.substr(slash + 1));
  for (const auto& a : args) storage.push_back(a);

  std::vector<char*> out;
  out.reserve(storage.size() + 1);
  for (auto& s : storage) out.push_back(s.data());
  out.push_back(nullptr);
  return out;
}

std::vector<char*> make_c_envp(const std::vector<std::string>& envp,
                               std::vector<std::string>&       storage) {
  for (const auto& e : envp) storage.push_back(e);
  std::vector<char*> out;
  out.reserve(storage.size() + 1);
  for (auto& s : storage) out.push_back(s.data());
  out.push_back(nullptr);
  return out;
}

} // namespace

LaunchResult launch_target(const LaunchOptions&   opts,
                           const NamespaceFlags&  ns,
                           const Cgroup&          cgroup) {
  int sync_pipe[2];
  if (::pipe2(sync_pipe, O_CLOEXEC) != 0) {
    throw IsolationError(std::string("pipe2 failed: ") + std::strerror(errno));
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    ::close(sync_pipe[0]);
    ::close(sync_pipe[1]);
    throw IsolationError(std::string("fork failed: ") + std::strerror(errno));
  }

  if (pid == 0) {
    // ---- Child ------------------------------------------------------------
    ::close(sync_pipe[1]);  // no write end in child

    // Wait for parent to attach us to the cgroup before we do anything.
    char sync_byte = 0;
    const ssize_t n = ::read(sync_pipe[0], &sync_byte, 1);
    if (n != 1 || sync_byte != '1') {
      ::_exit(126);
    }
    ::close(sync_pipe[0]);

    // Unshare requested namespaces (mount only, by default in v0.1).
    const int unshare_flags = build_unshare_flags(ns);
    if (unshare_flags != 0) {
      if (::unshare(unshare_flags) != 0) {
        ::_exit(127);
      }
    }

    // Prevent our mount changes from propagating back to the host. This is
    // defensive — nothing in v0.1 mounts inside the target, but future
    // additions (e.g., pivot_root) must not leak into the parent mount ns.
    if (ns.mount) {
      if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
        ::_exit(127);
      }
    }

    // Set working directory.
    const char* cwd = opts.cwd.empty() ? "/" : opts.cwd.c_str();
    if (::chdir(cwd) != 0) {
      ::_exit(127);
    }

    // Die when the launching process dies. Best-effort: some environments
    // (seccomp / restrictive LSMs) may reject PR_SET_PDEATHSIG; in that case
    // we continue anyway since it is a cleanup convenience, not a correctness
    // requirement. Parent still reaps via waitpid regardless.
    (void)::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

    // Build argv/envp and exec.
    std::vector<std::string> argv_storage;
    std::vector<std::string> envp_storage;
    auto argv = make_c_argv(opts.binary, opts.args, argv_storage);

    if (opts.envp.empty()) {
      // Intentional: with no explicit env the target inherits the tool's environment
      // so it runs realistically (most binaries need PATH/HOME/etc). This does expose
      // the tool's env to the target; callers wanting a scrubbed env pass opts.envp
      // (the hook a future `--clear-env` capture flag would use).
      ::execve(opts.binary.c_str(), argv.data(), environ);
    } else {
      auto envp = make_c_envp(opts.envp, envp_storage);
      ::execve(opts.binary.c_str(), argv.data(), envp.data());
    }
    // execve returned -> failure
    ::_exit(127);
  }

  // ---- Parent -----------------------------------------------------------
  ::close(sync_pipe[0]);  // no read end in parent

  try {
    cgroup.attach_pid(pid);
  } catch (const std::exception& e) {
    ::close(sync_pipe[1]);
    ::kill(pid, SIGKILL);
    ::waitpid(pid, nullptr, 0);
    throw IsolationError(std::string("cgroup attach failed: ") + e.what());
  }

  const char go = '1';
  if (::write(sync_pipe[1], &go, 1) != 1) {
    ::close(sync_pipe[1]);
    ::kill(pid, SIGKILL);
    ::waitpid(pid, nullptr, 0);
    throw IsolationError("sync pipe write failed; child never started");
  }
  ::close(sync_pipe[1]);

  log::info("target launched: pid=" + std::to_string(pid) +
            " binary=" + opts.binary +
            " cgroup_id=" + std::to_string(cgroup.id()));
  return LaunchResult{pid};
}

int wait_for_exit(pid_t host_pid) {
  int status = 0;
  while (true) {
    const pid_t r = ::waitpid(host_pid, &status, 0);
    if (r == host_pid) return status;
    if (r == -1 && errno == EINTR) continue;
    if (r == -1) {
      throw IsolationError(std::string("waitpid failed: ") + std::strerror(errno));
    }
  }
}

} // namespace vishaya::isolation
