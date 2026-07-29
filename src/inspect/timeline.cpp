#include "inspect/timeline.h"

#include "bundle/reader.h"
#include "common/errors.h"
#include "common/log.h"
#include "inspect/render.h"

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

// Extract ts_ns without ever throwing. Used in the sort comparator, where a
// json::type_error (thrown by .value() on a wrong-typed ts_ns in a hostile
// bundle) would propagate out of std::stable_sort. Non-numeric/absent → 0.
uint64_t safe_ts(const nlohmann::json& e) {
  const auto it = e.find("ts_ns");
  if (it == e.end() || !it->is_number()) return 0;
  if (it->is_number_unsigned()) return it->get<uint64_t>();
  const int64_t v = it->get<int64_t>();
  return v < 0 ? 0 : static_cast<uint64_t>(v);
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
  // The detail line is assembled from attacker-controlled fields (paths, cmdline,
  // DNS/HTTP names, addresses) — scrub before it can reach the terminal.
  return scrub_for_terminal(oss.str());
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
    // `timeline` must buffer every event to sort globally, so a hostile bundle with
    // an enormous event count could exhaust memory. Cap the buffer and note the
    // truncation; the streaming views (files/network) remain unbounded-input-safe.
    constexpr size_t kMaxTimelineEvents = 1'000'000;
    std::vector<nlohmann::json> events;
    bool truncated = false;
    reader.for_each_event([&](const nlohmann::json& e) {
      if (events.size() >= kMaxTimelineEvents) { truncated = true; return; }
      if (e.is_object()) events.push_back(e);  // ignore non-object lines
    });
    std::stable_sort(events.begin(), events.end(),
                     [](const nlohmann::json& a, const nlohmann::json& b) {
                       return safe_ts(a) < safe_ts(b);
                     });

    const uint64_t base_ts = events.empty() ? 0 : safe_ts(events.front());

    std::cout << "bundle: " << bundle_path << "\n\n";
    std::cout << std::left
              << std::setw(28)
              << (have_anchor ? "TIME (UTC)" : "TIME (+s from first event)")
              << std::setw(8)  << "PID"
              << std::setw(16) << "COMM"
              << std::setw(20) << "EVENT"
              << "DETAIL\n";
    std::cout << std::string(116, '-') << "\n";

    size_t shown = 0, skipped = 0;
    for (const auto& e : events) {
      // Skip (don't abort on) a malformed event; extract all fields before output.
      try {
        const uint64_t ts = safe_ts(e);
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
        const int32_t     tgid = e.value("tgid", 0);
        const std::string comm = scrub_for_terminal(e.value("comm", ""));
        const std::string family_kind = scrub_for_terminal(
            e.value("family", "") + ":" + e.value("kind", ""));
        const std::string detail = one_line_summary(e);  // already scrubbed
        std::cout << std::left
                  << std::setw(28) << tcol
                  << std::setw(8)  << tgid
                  << std::setw(16) << comm
                  << std::setw(20) << family_kind
                  << detail << "\n";
        ++shown;
      } catch (const nlohmann::json::exception&) {
        ++skipped;
      }
    }

    if (events.empty()) {
      std::cout << "(no events)\n";
    } else {
      std::cout << "\n" << shown << " event(s)\n";
    }
    if (skipped > 0)
      std::cout << "(" << skipped << " malformed event(s) skipped)\n";
    if (truncated)
      std::cout << "(timeline truncated to the first " << kMaxTimelineEvents
                << " events; use `files`/`network` for the full streamed views)\n";
    return 0;
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("timeline failed: ") + e.what());
    return 1;
  }
}

} // namespace vishaya::inspect
