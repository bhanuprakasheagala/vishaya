#include "inspect/timeline.h"

#include "bundle/reader.h"
#include "common/errors.h"
#include "common/log.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace vishaya::inspect {

namespace {

// Format an absolute wall-clock instant (ns since the Unix epoch) as ISO-8601
// UTC with millisecond precision. Uses a local ostringstream so no iomanip state
// (setfill/setw) leaks into std::cout.
std::string format_wall_utc(uint64_t wall_ns) {
  const std::time_t secs = static_cast<std::time_t>(wall_ns / 1'000'000'000ULL);
  const uint64_t    ms   = (wall_ns % 1'000'000'000ULL) / 1'000'000ULL;
  std::tm tm_utc{};
  gmtime_r(&secs, &tm_utc);
  std::ostringstream oss;
  oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%S")
      << '.' << std::setfill('0') << std::setw(3) << ms << 'Z';
  return oss.str();
}

// Format a relative offset (ns from the first event) as "+S.mmm" seconds.
// Fallback when the bundle has no clock anchor (pre-anchor bundles).
std::string format_rel(uint64_t delta_ns) {
  const uint64_t s  = delta_ns / 1'000'000'000ULL;
  const uint64_t ms = (delta_ns % 1'000'000'000ULL) / 1'000'000ULL;
  std::ostringstream oss;
  oss << '+' << s << '.' << std::setfill('0') << std::setw(3) << ms;
  return oss.str();
}

std::string one_line_summary(const nlohmann::json& e) {
  const std::string family = e.value("family", "");
  const std::string kind   = e.value("kind", "");
  const auto&       data   = e.contains("data") ? e["data"] : nlohmann::json::object();

  std::ostringstream oss;
  if (family == "process") {
    if (kind == "exec") {
      oss << data.value("exec_path", "");
      const std::string cmdline = data.value("cmdline", "");
      if (!cmdline.empty()) oss << " (" << cmdline << ")";
    } else if (kind == "fork" || kind == "clone" || kind == "clone3" || kind == "vfork") {
      oss << "-> pid=" << data.value("child_pid", 0);
    } else if (kind == "exit") {
      oss << "code=" << data.value("exit_code", 0);
    }
  } else if (family == "file") {
    oss << data.value("path_a", "");
    const std::string b = data.value("path_b", "");
    if (!b.empty()) oss << " -> " << b;
  } else if (family == "network") {
    if (data.contains("remote") && data["remote"].is_object()) {
      const auto& r = data["remote"];
      const std::string addr = r.value("addr", "");
      const int         port = r.value("port", 0);
      if (!addr.empty()) oss << addr << ":" << port;
    }
    if (kind == "dns-query" || kind == "dns-answer") {
      const auto& dns = data.contains("dns") ? data["dns"] : nlohmann::json::object();
      oss << " " << dns.value("qtype", "") << " " << dns.value("qname", "");
    } else if (kind == "http-request") {
      const auto& http = data.contains("http") ? data["http"] : nlohmann::json::object();
      oss << " " << http.value("method", "") << " " << http.value("host", "")
          << http.value("path", "");
    }
  } else if (family == "syscall") {
    oss << data.value("syscall_name", "");
  }
  return oss.str();
}

} // namespace

int run_timeline(const std::string& bundle_path) {
  try {
    vishaya::bundle::Reader reader(bundle_path);
    reader.verify();  // spec §6/§9: verify integrity + signature at load (warns on failure)

    const auto&    cap = reader.manifest().capture;
    const bool     have_anchor =
        cap.clock_realtime_ns != 0 && cap.clock_monotonic_ns != 0;

    // Buffer all events and sort chronologically. The WAL is written in
    // ring-buffer delivery order, which is only approximately chronological
    // across CPUs; a global stable sort gives a true timeline while preserving
    // the order of synthetic events relative to their source (same ts_ns).
    std::vector<nlohmann::json> events;
    reader.for_each_event([&](const nlohmann::json& e) { events.push_back(e); });
    std::stable_sort(events.begin(), events.end(),
                     [](const nlohmann::json& a, const nlohmann::json& b) {
                       return a.value("ts_ns", uint64_t{0}) <
                              b.value("ts_ns", uint64_t{0});
                     });

    const uint64_t base_ts =
        events.empty() ? 0 : events.front().value("ts_ns", uint64_t{0});

    std::cout << "bundle: " << bundle_path << "\n\n";
    std::cout << std::left
              << std::setw(28)
              << (have_anchor ? "TIME (UTC)" : "TIME (+s from first event)")
              << std::setw(8)  << "PID"
              << std::setw(16) << "COMM"
              << std::setw(20) << "EVENT"
              << "DETAIL\n";
    std::cout << std::string(116, '-') << "\n";

    for (const auto& e : events) {
      const uint64_t ts = e.value("ts_ns", uint64_t{0});
      std::string tcol;
      if (have_anchor) {
        // wall = realtime_anchor + (ts_ns - monotonic_anchor). Signed math so an
        // event fired microseconds before the anchor sample can't underflow.
        const int64_t wall =
            static_cast<int64_t>(cap.clock_realtime_ns) +
            (static_cast<int64_t>(ts) - static_cast<int64_t>(cap.clock_monotonic_ns));
        tcol = format_wall_utc(wall < 0 ? 0 : static_cast<uint64_t>(wall));
      } else {
        tcol = format_rel(ts >= base_ts ? ts - base_ts : 0);
      }
      const std::string family_kind =
          e.value("family", "") + ":" + e.value("kind", "");
      std::cout << std::left
                << std::setw(28) << tcol
                << std::setw(8)  << e.value("tgid", 0)
                << std::setw(16) << e.value("comm", "")
                << std::setw(20) << family_kind
                << one_line_summary(e) << "\n";
    }

    if (events.empty()) {
      std::cout << "(no events)\n";
    } else {
      std::cout << "\n" << events.size() << " event(s)\n";
    }
    return 0;
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("timeline failed: ") + e.what());
    return 1;
  }
}

} // namespace vishaya::inspect
