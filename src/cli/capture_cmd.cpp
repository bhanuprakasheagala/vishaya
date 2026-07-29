#include "cli/capture_cmd.h"

#include "bundle/hash.h"
#include "bundle/manifest.h"
#include "bundle/writer.h"
#include "capture/session.h"
#include "common/errors.h"
#include "common/log.h"
#include "common/tmp_dir.h"
#include "isolation/cgroup.h"
#include "isolation/target_launch.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace vishaya::cli {

namespace {

std::atomic<bool> g_running{true};

void on_signal(int /*sig*/) { g_running = false; }

std::string iso_now_utc() {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const auto tt  = system_clock::to_time_t(now);
  const auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
  std::tm tm_utc{};
  gmtime_r(&tt, &tm_utc);
  std::ostringstream oss;
  oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%S")
      << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
  return oss.str();
}

uint64_t file_size_or_zero(const std::string& path) {
  struct stat st{};
  if (::stat(path.c_str(), &st) != 0) return 0;
  return static_cast<uint64_t>(st.st_size);
}

std::string uname_kernel() {
  struct utsname u{};
  if (::uname(&u) != 0) return "unknown";
  return u.release;
}

std::string uname_arch() {
  struct utsname u{};
  if (::uname(&u) != 0) return "unknown";
  return u.machine;
}

std::string gethostname_str() {
  char buf[256] = {};
  if (::gethostname(buf, sizeof(buf) - 1) != 0) return "unknown";
  return std::string(buf);
}

std::string distro_pretty_name() {
  std::ifstream in("/etc/os-release");
  if (!in) return "";
  std::string line;
  while (std::getline(in, line)) {
    static const std::string kPrefix = "PRETTY_NAME=";
    if (line.rfind(kPrefix, 0) != 0) continue;
    std::string v = line.substr(kPrefix.size());
    if (v.size() >= 2 &&
        ((v.front() == '"' && v.back() == '"') ||
         (v.front() == '\'' && v.back() == '\''))) {
      v = v.substr(1, v.size() - 2);
    }
    return v;
  }
  return "";
}

int envp_count() {
  int c = 0;
  for (char** e = environ; e && *e; ++e) ++c;
  return c;
}

} // namespace

int run_capture(const CaptureArgs& args) {
  if (::geteuid() != 0) {
    log::error("vishaya capture must run as root (eBPF + cgroup v2 require it)");
    return 1;
  }
  if (args.target.empty()) {
    log::error("--target is required");
    return 1;
  }
  // Validate the target up front so a bad path fails clearly here, rather than as
  // an opaque "target exited 127" after all the capture machinery is set up.
  {
    struct stat st{};
    if (::stat(args.target.c_str(), &st) != 0) {
      log::error("--target not found: " + args.target + " (" + std::strerror(errno) + ")");
      return 1;
    }
    if (!S_ISREG(st.st_mode)) {
      log::error("--target is not a regular file: " + args.target);
      return 1;
    }
    if (::access(args.target.c_str(), X_OK) != 0) {
      log::error("--target is not executable: " + args.target);
      return 1;
    }
  }

  std::signal(SIGINT,  on_signal);
  std::signal(SIGTERM, on_signal);

  const std::string started_at     = iso_now_utc();
  const auto        monotonic_start = std::chrono::steady_clock::now();

  // Clock anchor: sample CLOCK_MONOTONIC (the base of event ts_ns, which comes
  // from bpf_ktime_get_ns) together with CLOCK_REALTIME, so the reader can map
  // event timestamps to wall-clock: wall = realtime + (ts_ns - monotonic).
  // Sampled once — the realtime/monotonic offset is stable across a short
  // capture absent an NTP step. Left at 0 if the syscall fails (reader falls
  // back to relative timestamps).
  uint64_t clock_monotonic_ns = 0;
  uint64_t clock_realtime_ns  = 0;
  {
    struct timespec mono{};
    struct timespec real{};
    if (::clock_gettime(CLOCK_MONOTONIC, &mono) == 0 &&
        ::clock_gettime(CLOCK_REALTIME, &real) == 0) {
      clock_monotonic_ns = static_cast<uint64_t>(mono.tv_sec) * 1000000000ULL +
                           static_cast<uint64_t>(mono.tv_nsec);
      clock_realtime_ns  = static_cast<uint64_t>(real.tv_sec) * 1000000000ULL +
                           static_cast<uint64_t>(real.tv_nsec);
    }
  }

  try {
    common::TmpDir       scratch("vishaya-capture");
    isolation::Cgroup    cgroup;
    log::info("scratch=" + scratch.path() + " cgroup=" + cgroup.path());

    // Artifact capture (opt-in). The collector observes file_events during poll
    // and copies survivors after the target exits. Declared before the Session so
    // it outlives every poll() that feeds it.
    std::optional<capture::ArtifactCollector> collector;
    if (args.capture_artifacts) collector.emplace(args.artifact_cfg);

    // Session::Session loads the BPF object, attaches probes, then activates
    // cgroup scoping — all before the target is launched below, so the target's
    // first instruction is already inside the scoped, filtered cgroup. If the
    // BPF object cannot scope, construction throws unless --allow-host-wide is
    // set (we refuse to silently record unrelated host processes).
    capture::Session session(scratch.path(),
                             static_cast<uint32_t>(::getpid()),
                             cgroup.id(),
                             args.allow_host_wide);
    if (collector) session.set_artifact_collector(&*collector);

    // Launch target inside isolation (mount ns + cgroup, per v0.1 defaults).
    isolation::LaunchOptions opts;
    opts.binary = args.target;
    opts.args   = args.args;
    opts.cwd    = args.cwd;
    isolation::NamespaceFlags ns;  // v0.1 defaults: mount only

    const auto launch = isolation::launch_target(opts, ns, cgroup);
    log::info("target pid=" + std::to_string(launch.host_pid));

    // Poll ring buffer until the target exits or we are signalled.
    int   status = 0;
    while (g_running) {
      const pid_t r = ::waitpid(launch.host_pid, &status, WNOHANG);
      if (r == launch.host_pid) break;      // target exited
      if (r == -1 && errno != EINTR) {
        log::warn(std::string("waitpid: ") + std::strerror(errno));
        break;
      }
      session.poll(100);
    }

    if (!g_running) {
      log::warn("stopping capture on signal; killing target pid=" +
                std::to_string(launch.host_pid));
      ::kill(launch.host_pid, SIGKILL);
      ::waitpid(launch.host_pid, &status, 0);
    }

    // Drain any events emitted right at target exit before shutting down BPF.
    session.poll(50);
    session.poll(50);
    session.stop();

    // Snapshot surviving artifacts now that the target has exited (files it
    // created/modified that still exist). See ArtifactCollector::finalize.
    std::vector<bundle::ArtifactRecord> artifact_records;
    std::string                         artifacts_dir;
    if (collector) {
      artifacts_dir = scratch.path() + "/artifacts";
      ::mkdir(artifacts_dir.c_str(), 0755);  // spec §2: 0755; EEXIST is harmless
      artifact_records = collector->finalize(artifacts_dir);
    }

    const std::string ended_at        = iso_now_utc();
    const auto        monotonic_end   = std::chrono::steady_clock::now();
    const auto        duration_s      = std::chrono::duration_cast<std::chrono::seconds>(
                                            monotonic_end - monotonic_start).count();

    // Build the bundle.
    bundle::WriterInput input;
    input.scratch_dir                      = scratch.path();
    input.bundle_path                      = args.output;
    input.root_pid                         = launch.host_pid;
    input.manifest.capture.started_at      = started_at;
    input.manifest.capture.ended_at        = ended_at;
    input.manifest.capture.duration_seconds = static_cast<uint64_t>(
                                                std::max<long>(0, duration_s));
    input.manifest.capture.clock_realtime_ns  = clock_realtime_ns;
    input.manifest.capture.clock_monotonic_ns = clock_monotonic_ns;
    input.manifest.capture.host.kernel     = uname_kernel();
    input.manifest.capture.host.arch       = uname_arch();
    input.manifest.capture.host.distro     = distro_pretty_name();
    input.manifest.capture.host.hostname   = gethostname_str();
    input.manifest.target.path             = args.target;
    try {
      input.manifest.target.sha256 = bundle::sha256_hex_of_file(args.target);
    } catch (...) {
      input.manifest.target.sha256 = "";
    }
    input.manifest.target.size             = file_size_or_zero(args.target);
    input.manifest.target.args             = args.args;
    input.manifest.target.env_count        = envp_count();
    input.manifest.isolation.namespaces    = {"mnt"};
    input.manifest.isolation.cgroup_path   = cgroup.path();
    input.manifest.isolation.cgroup_id     = cgroup.id();
    input.manifest.coverage.families       = {"process", "file", "network"};
    if (args.enable_syscalls) input.manifest.coverage.families.push_back("syscall");
    input.manifest.coverage.syscalls_captured = args.enable_syscalls;
    input.manifest.coverage.network_layers    = {"socket", "dns", "http"};
    input.manifest.counts.events_total     = session.events_written();
    input.manifest.counts.events_dropped   = session.events_dropped();

    uint64_t ok_artifacts = 0;
    for (const auto& r : artifact_records)
      if (r.status == bundle::artifact_status::kOk) ++ok_artifacts;
    input.manifest.counts.artifacts_count      = ok_artifacts;
    input.manifest.coverage.artifacts_captured = static_cast<bool>(collector);
    input.artifacts_dir                        = artifacts_dir;
    input.capture_artifacts_enabled            = static_cast<bool>(collector);
    input.artifacts                            = std::move(artifact_records);

    if (collector && collector->candidates_truncated()) {
      log::warn("artifact candidate limit reached; some created/modified paths "
                "were not considered for capture");
    }

    bundle::write_bundle(input);

    log::info("bundle: " + args.output);
    return 0;
  } catch (const std::exception& e) {
    log::error(std::string("capture failed: ") + e.what());
    return 1;
  }
}

} // namespace vishaya::cli
