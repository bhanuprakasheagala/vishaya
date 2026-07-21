#pragma once

/*
 * File Notes:
 * - Session: one capture from start to stop. Wraps the pre-existing
 *   vishaya::collector::Collector (BPF load + ring-buffer poll), adds decode +
 *   enrich, serializes each event to Vishaya-spec JSON, and appends to the
 *   scratch WAL (events.ndjson).
 * - When constructed with a non-zero target_cgroup_id, Session activates BPF
 *   cgroup filtering immediately after probe attach, so only the target cgroup's
 *   events land in the WAL. If the loaded BPF object cannot scope (no
 *   target_cgroup_id map), construction FAILS unless allow_host_wide is set —
 *   we never silently record unrelated host processes.
 */

#include "capture/wal_writer.h"
#include "decoder/decoder.h"
#include "enricher/enricher.h"

#include <cstdint>
#include <memory>
#include <string>

namespace vishaya::capture {

class Session {
 public:
  // Opens WAL at <scratch_dir>/events.ndjson; loads BPF; attaches probes.
  // If target_cgroup_id != 0, activates BPF cgroup filtering immediately after
  // probe attach so no unrelated host events land in the WAL. Pass 0 to request
  // host-wide capture explicitly (diagnostics / non-CLI callers).
  // If scoping is requested (target_cgroup_id != 0) but the loaded BPF object
  // has no target_cgroup_id map, construction throws CaptureError — unless
  // allow_host_wide is true, in which case it warns and captures host-wide.
  // self_tgid is used only for context; kernel self-suppression is set by the
  // underlying collector using getpid() directly.
  // Throws CaptureError on failure.
  Session(const std::string& scratch_dir,
          uint32_t           self_tgid,
          uint64_t           target_cgroup_id = 0,
          bool               allow_host_wide  = false);
  ~Session();

  Session(const Session&)            = delete;
  Session& operator=(const Session&) = delete;

  // True if BPF cgroup filtering is active on the loaded object. When false,
  // capture is host-wide (used for backward-compat detection).
  bool cgroup_filter_active() const noexcept { return cgroup_filter_active_; }

  // Poll the BPF ring buffer for up to timeout_ms. Each event surfaced is
  // decoded, enriched, serialized, and appended to the WAL.
  void poll(int timeout_ms);

  // Detach probes, free BPF handles, close WAL. Safe to call multiple times.
  void stop();

  uint64_t events_written() const noexcept { return events_written_; }
  uint64_t events_dropped() const noexcept { return events_dropped_; }

 private:
  // Callback invoked by the underlying collector for each raw event payload.
  void on_raw_event(const unsigned char* data, size_t size);

  std::unique_ptr<WalWriter> wal_;
  vishaya::collector::Collector*   collector_ = nullptr;  // borrowed singleton
  vishaya::collector::Decoder      decoder_;
  vishaya::collector::Enricher     enricher_;
  uint32_t                   self_tgid_             = 0;
  uint64_t                   events_written_        = 0;
  uint64_t                   events_dropped_        = 0;
  bool                       started_               = false;
  bool                       cgroup_filter_active_  = false;
};

} // namespace vishaya::capture
