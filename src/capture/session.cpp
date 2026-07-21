#include "capture/session.h"

#include "capture/event_to_json.h"
#include "capture/protocol_decoder.h"
#include "collector/collector.h"
#include "common/errors.h"
#include "common/log.h"

#include <span>
#include <string>

namespace vishaya::capture {

Session::Session(const std::string& scratch_dir,
                 uint32_t           self_tgid,
                 uint64_t           target_cgroup_id,
                 bool               allow_host_wide)
    : self_tgid_(self_tgid) {
  wal_       = std::make_unique<WalWriter>(scratch_dir + "/events.ndjson");
  collector_ = vishaya::collector::CreateCollector();

  const bool ok = collector_->Start(
      [this](std::span<const unsigned char> raw) {
        on_raw_event(raw.data(), raw.size());
      });

  if (!ok) {
    // Emit a diagnostic startup report if available before failing.
    vishaya::collector::CollectorStartupReport report{};
    if (collector_->ReadStartupReport(&report) && report.degraded) {
      log::error("collector startup degraded: " + report.degrade_reason);
    }
    throw CaptureError(
        "collector Start() failed; see prior log lines for the BPF load / attach reason");
  }

  // Mark started BEFORE any subsequent operation that could throw. This
  // guarantees the destructor will call Stop() on the collector even if a
  // later line in this constructor fails, preventing BPF resource leaks.
  started_ = true;

  // Activate cgroup-based scoping as the immediate next step after BPF attach so
  // no unrelated host events accumulate in the ring buffer before filtering
  // kicks in. target_cgroup_id == 0 means the caller explicitly asked for
  // host-wide capture (diagnostics), so scoping is skipped.
  if (target_cgroup_id != 0) {
    cgroup_filter_active_ = collector_->SetTargetCgroup(target_cgroup_id);
    if (!cgroup_filter_active_) {
      if (allow_host_wide) {
        log::warn(
            "target_cgroup_id map missing in loaded BPF object; capturing "
            "HOST-WIDE because --allow-host-wide was set. The bundle will "
            "include events from unrelated host processes.");
      } else {
        // Refuse to silently capture host-wide when scoping was requested. The
        // constructor throwing means ~Session will NOT run, so detach the
        // collector here to avoid leaving probes attached (wal_ is a member and
        // is closed by normal member destruction during unwinding).
        collector_->Stop();
        started_ = false;
        throw CaptureError(
            "cgroup scoping requested but the loaded BPF object has no "
            "target_cgroup_id map — refusing to silently capture host-wide. "
            "Rebuild the BPF object (scripts/linux.sh bpf), or pass "
            "--allow-host-wide to override.");
      }
    }
  }

  vishaya::collector::CollectorStartupReport report{};
  if (collector_->ReadStartupReport(&report)) {
    log::info("collector: backend=" + report.backend_name +
              " programs_attached=" + std::to_string(report.programs_attached) +
              "/" + std::to_string(report.programs_total) +
              " cgroup_scoping=" + (cgroup_filter_active_ ? "on" : "off"));
  }
}

Session::~Session() { stop(); }

void Session::poll(int timeout_ms) {
  if (!started_) return;
  collector_->PollOnce(timeout_ms);
}

void Session::stop() {
  if (started_ && collector_) {
    // Read kernel-side ring-buffer drop counter before Stop() closes the BPF
    // object. ringbuf_reserve_fail counts events the kernel discarded when the
    // ring buffer was full — they never reached userspace and are not counted
    // by the userspace events_dropped_ increment in on_raw_event().
    vishaya::collector::KernelBpfStats kstats{};
    if (collector_->ReadKernelBpfStats(&kstats)) {
      events_dropped_ += kstats.ringbuf_reserve_fail;
    }
    collector_->Stop();
    started_ = false;
  }
  wal_.reset();
  log::info("capture session stopped: events_written=" +
            std::to_string(events_written_) +
            " events_dropped=" + std::to_string(events_dropped_));
}

void Session::on_raw_event(const unsigned char* data, size_t size) {
  auto decoded = decoder_.Decode(std::span<const unsigned char>(data, size));
  if (!decoded.has_value()) {
    ++events_dropped_;
    return;
  }

  // Enrich process events with /proc data. Enricher is a no-op for other families.
  enricher_.Enrich(*decoded);

  try {
    const std::string line = event_to_json(*decoded);
    wal_->write_line(line);
    ++events_written_;

    // Emit any protocol-layer synthetic events (e.g. dns-query, dns-answer)
    // derived from the captured payload. These follow the original event so
    // they appear in the WAL in chronological order relative to the source.
    for (const std::string& synth : synthesize_protocol_events(*decoded)) {
      wal_->write_line(synth);
      ++events_written_;
    }
  } catch (const std::exception& e) {
    log::warn(std::string("WAL write failed, dropping event: ") + e.what());
    ++events_dropped_;
  }
}

} // namespace vishaya::capture
