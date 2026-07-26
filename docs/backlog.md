# Backlog — detailed reference archive

In-depth per-item analysis (description, notes, fix approach, target files) for every
review finding and follow-up. **Status and priority are NOT tracked here.** The single
authoritative tracker is [roadmap-decisions.md](roadmap-decisions.md) — its verdict table
(DONE / KEEP-v0.5 / KEEP-v1.0 / DEFER / CUT) and its Audit-items section. The
`STATUS | PRIORITY | EFFORT | source` token under each heading below is the *original
triage snapshot*, kept for historical context only; consult the decisions doc for the
current verdict.

## Legend (for reading the historical token under each heading)

**Priority:**
- `HIGH` — do before v0.5 announcement / conference talk
- `MEDIUM` — v0.5 → v1.0 window
- `LOW` — v1.0+ or nice-to-have

**Effort:**
- `S` — small, ≤ 1 week
- `M` — medium, 1-3 weeks
- `L` — large, 3+ weeks

**Source:**
- `review-1` — external code/design review, Aug 2026
- `self` — identified during development or self-review
- `user` — direct user request

## Status

Tracked authoritatively in [roadmap-decisions.md](roadmap-decisions.md) — its verdict
table (features A-01…I-02 + roadmap) and its Audit-items section (R2/R3). This document no
longer keeps a status table (it drifted); it is the detailed per-item reference only.

---

## Post-research reconciliation → folded into the decisions doc

The 2026-07 positioning research re-judged every feature against **verifiable +
target-scoped + single-file evidence**. Those keep / cut / defer calls, with reasoning,
now live in [roadmap-decisions.md](roadmap-decisions.md) (verdict table + "notable calls",
+ [research/2026-07-product-positioning.md](research/2026-07-product-positioning.md)). The
summary that used to live here was removed so the same reasoning isn't maintained twice.

---

## A. Architectural / correctness

### A-01. Sampling and rate-limiting absent

`OPEN` | `MEDIUM` | `M` | source: review-1

**Description:** A malicious target doing `while(1) socket()` overwhelms the ring buffer with no proactive backpressure or documented lossy mode. Sysdig's `.scap` encodes drops explicitly; Vishaya should too.

**Notes:** BPF-side counters (`BPF_STAT_RINGBUF_RESERVE_FAIL`) exist but only surface in stderr. Not present in the bundle manifest, so a bundle consumer has no way to know events were lost.

**Fix approach:**
1. Surface drop counts in `manifest.counts.events_dropped` (already declared but not populated from BPF stats).
2. Add per-family drop breakdown: `counts.events_dropped_process`, `..._file`, `..._network`, `..._syscall`.
3. Document a "lossy mode" contract in bundle-spec-v0.1.md: readers should treat `events_dropped > 0` as reduced confidence.
4. Optionally add per-family rate-limit knob in BPF (skip every Nth event of noisy kinds; opt-in via config).

**Target files:** `bpf/vishaya_common.bpf.h`, `src/collector/collector_libbpf.cpp`, `src/capture/session.cpp`, `src/cli/capture_cmd.cpp`, `docs/bundle-spec-v0.1.md`

---

### A-02. iovec-family payload capture blocks HTTPS

`OPEN` | `HIGH` | `M` | source: review-1

**Description:** `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`, `writev`, `readv` emit events but don't capture payload bytes. This is a hard blocker for TLS uprobe work (v0.5's headline feature) — `SSL_write` typically routes through `sendmsg`/`writev`.

**Notes:** Documented as a limitation in `event-reference.md`. Reviewer's insight: this isn't just a coverage gap, it's a v0.5 dependency.

**Fix approach:** Extend BPF probes to walk `msghdr.msg_iov` on enter (send-side) and save iovec pointers for exit-side capture (recv-side). Use existing `capture_send_payload` helper pattern. Bounded to first 128 bytes of first iovec (v0.1 sizing).

**Dependencies:** blocks G-02 (TLS uprobes).

**Target files:** `bpf/vishaya_network.bpf.c`, `bpf/vishaya_common.bpf.h`

---

### A-03. SHA-256 not evidence-grade; signing must be default

`IN-PROGRESS` | `HIGH` | `M` | source: review-1

**Update (2026-07-20, review-2):** Steps 1-4 below are DONE — signing with a local
Ed25519 key is already default in the writer, and the reader now verifies both integrity
hashes and the signature at load time (see R2-02). The remaining open work is step 5:
Sigstore/Rekor keyless signing (`--attest`) for a real third-party trust anchor. Until
then this is tamper-evidence, not identity attestation. Reclassify the remainder as its
own MEDIUM item when picked up.

**Description:** A SHA-256 computed by the same binary that writes the file is tamper-detection at best, not evidence. For court-admissible provenance the bundle needs a detached cryptographic signature computed at close time.

**Notes:** Enterprise-features.md has F1 (bundle signing) as Wave 1 optional; reviewer argues it must be default. Agreed. The `--no-sign` escape hatch is fine, but default should sign.

**Fix approach:**
1. Generate or load Ed25519 keypair at first Vishaya run; store private key at `~/.config/vishaya/keys/`.
2. Compute signature over the tar contents at close time.
3. Include signature entry (`manifest.sig`) as final tar entry after everything else.
4. Reader verifies at open time; failure is a loud warning, not silent.
5. Follow-on: Sigstore keyless signing (Rekor transparency log) as `--attest` flag.

**Dependencies:** none.

**Target files:** `src/bundle/writer.cpp`, `src/bundle/reader.cpp`, `src/bundle/manifest.{h,cpp}`, `src/cli/capture_cmd.cpp`, `docs/bundle-spec-v0.1.md` (schema addition — signature is additive per major-compat rule)

---

### A-04. Container awareness absent from v0.1

`OPEN` | `HIGH` | `M` | source: review-1

**Description:** No cgroup path or mount-ns inode on events. Fine for direct binary captures; breaks entirely when the target itself spawns containers (modern malware droppers commonly do this). Process tree becomes meaningless.

**Notes:** Should be Wave 2 for v0.5, not deferred to v1.0. Reviewer is right this is more urgent than I placed it.

**Fix approach:**
1. Add `container_id` and `mount_ns_ino` to the `event_header` struct in `event_schema.h`.
2. BPF-side: read from `task_struct` via BTF; extract cgroup path from `task->cgroups->subsys[cpuset_cgrp_id]->cgroup->kn`.
3. Userspace: enrich events by cross-referencing the target's cgroup with detected container runtimes (docker, podman, systemd-nspawn, k8s pods).
4. Emit as new event envelope fields (additive; old readers ignore).
5. Update `event-reference.md` common envelope docs.

**Dependencies:** none. Schema addition is v0.5 minor bump.

**Target files:** `include/event_schema.h`, `bpf/vishaya_common.bpf.h`, `src/capture/event_to_json.cpp`, `src/enricher/enricher.cpp`, `docs/event-reference.md`

---

### A-05. Namespace isolation is not a security boundary

`OPEN` | `HIGH` | `S` | source: review-1

**Description:** Cgroup + mount namespace prevents *accidental* host contamination but is trivially escapable by a capable adversary (cgroup notify-on-release, `/proc/self/exe` tricks, unprivileged user-ns bugs). Vishaya is a DFIR recorder for suspicious-but-not-adversarial binaries or sandbox detonation, NOT a hardened detonation chamber.

**Notes:** Currently `vision.md` doesn't say this loudly. Reviewer is right — misleading users on containment is worse than admitting a limitation.

**Fix approach:** Add a "Security boundary honesty" paragraph to `vision.md` non-goals section. Also mention in `getting-started.md` and `troubleshooting.md`.

**Suggested language:**
> Vishaya is not a hardened detonation chamber. Namespace and cgroup isolation prevent accidental host contamination but are trivially escapable by an adversarial target with root-adjacent capabilities. For adversarial malware analysis where the target is expected to actively evade, use hypervisor-based tools like DRAKVUF (Xen VMI) or a full VM sandbox. Vishaya's target audience is suspicious-but-not-actively-anti-sandbox binaries and lightweight forensic detonation.

**Dependencies:** none.

**Target files:** `docs/vision.md`, `docs/getting-started.md`, `docs/troubleshooting.md`

---

### A-06. Semantic event deduplication

`OPEN` | `MEDIUM` | `M` | source: user

**Description:** A target running a tight I/O loop (e.g., polling a socket at 10k events/sec) produces long runs of structurally identical events that overwhelm the bundle with no information gain. Unlike A-01 (ring-buffer rate limiting, which *drops* events and loses information), semantic deduplication *preserves* the information in compressed form: consecutive identical events are collapsed into a single entry carrying `count` and `duration_ns` alongside the original fields.

**Example:** 10,000 consecutive `file:openat` events on the same fd/path emitted as `{"family":"file","kind":"openat",...,"count":10000,"duration_ns":45000000}`.

**Notes:** This is distinct from A-01. A-01 fires under ring-buffer pressure and drops events; deduplication is semantic — it retains frequency metadata. Both mechanisms can coexist. Key invariant: deduplication must never merge events across different PIDs or across a span containing non-identical events; the resulting stream must remain chronologically correct. Readers that don't understand `count` treat a deduplicated entry as a single event — semantically close enough for most uses, exact for dedup-aware readers.

**Fix approach:**
1. Add a `DedupBuffer` class in `src/capture/` — accumulates a sliding window over the WAL stream; flushes on kind/pid/path change or when a configurable time threshold elapses.
2. Add optional `count` and `duration_ns` fields to all event families in `include/event_schema.h` (`count` defaults to 1 for non-deduplicated events).
3. Wire through `src/capture/session.cpp` between WAL read and JSON emit.
4. Expose as `--dedup-threshold N` flag in `src/cli/capture_cmd.cpp` (N = minimum repeat count before collapsing; off by default in v0.1 to preserve raw fidelity as the baseline experience).
5. Document new fields in `docs/event-reference.md`.

**Dependencies:** complements A-01; both address high-frequency targets.

**Target files:** new `src/capture/dedup_buffer.{h,cpp}`, `include/event_schema.h`, `src/capture/session.cpp`, `src/cli/capture_cmd.cpp`, `docs/event-reference.md`

---

## B. Product / positioning

### B-01. Competitive framing understates Tracee and Sysdig

`OPEN` | `MEDIUM` | `S` | source: review-1

**Description:** Tracee has `--capture` that dumps files + pcap. Sysdig has portable `.scap`. Vishaya's differentiator needs to be sharper than "target-scoped + single file" — otherwise a competitor could add scoping to Tracee in weeks.

**Notes:** Reviewer's "weekend" claim underestimates the pivot cost for Tracee (their entire architecture is EDR-adjacent, not case-oriented). But the framing critique stands: our public positioning needs to lean harder on the actual moat — the *combination* of target-scoped + portable + SDK-ready + signed + AI-consumable + CLI-first, none of which any single competitor has.

**Fix approach:** Sharpen `vision.md` §2 ("What makes it different") with explicit comparison to Tracee's --capture and Sysdig .scap. Not defensive — factual differentiation.

**Target files:** `docs/vision.md`

---

### B-02. No standard interchange (OCSF / STIX / MISP)

`OPEN` | `HIGH` | `M` | source: review-1

**Description:** Bundle is self-describing but has no OCSF, STIX, or MISP export. For the "analyst hands the bundle to a colleague" story to work end-to-end, the colleague also needs to be able to hand it to their SIEM.

**Notes:** In enterprise-features.md as Wave 3 (E1/E2/E7). Reviewer says v0.5 is the right time — agree. Reprioritize.

**Fix approach:** Ship `vishaya export --format ocsf|stix|misp` subcommand. Each format lives in its own module under `src/inspect/` or new `src/export/`. Start with OCSF (broadest SIEM support) and MISP (widest DFIR adoption).

**Dependencies:** benefits from A-03 (signed bundles for chain-of-custody in exported form).

**Target files:** new `src/export/` module, `src/cli/dispatcher.cpp`, `docs/event-reference.md`

---

### B-03. No determinism / reproducibility story

`OPEN` | `HIGH` | `M` | source: review-1

**Description:** Run same sample twice → get different timestamps, PIDs, address values. Meaningful `vishaya diff` requires normalization. Reproducibility is a core forensic property.

**Notes:** Genuine differentiator. Nobody in this space has this. Multiplies value of semantic diff (D-02).

**Fix approach:** Add `--normalize` mode with knobs:
- Map `ts_ns` → relative-from-target-start-ns
- Replace PIDs with stable ordinal IDs (target=1, first-child=2, ...)
- Strip host-specific fields (hostname, kernel uname patch level)
- Optional: canonicalize path randomness (`/tmp/xxxxxx` → `/tmp/<generated>`)
- Emit as `--output normalized.vishaya` or on-the-fly for inspect subcommands
Documented in `bundle-spec-v0.1.md` as a bundle-transformation, not a schema change.

**Dependencies:** enables D-02 (semantic diff).

**Target files:** new `src/bundle/normalize.{h,cpp}`, `src/cli/`, `docs/bundle-spec-v0.1.md`

---

### B-04. No integration with existing sandbox orchestrators

`OPEN` | `HIGH` | `M` | source: review-1 (priority bumped per review-1 §7)

**Description:** CAPE, Cuckoo, ANY.RUN all have analysis-report schemas. A `vishaya export --format cape` (or an --import on their side) gives Vishaya a real distribution channel.

**Notes:** In enterprise-features.md as E5. Reviewer's §7 framing: "Ship a sandbox adapter and an OCSF export and it stops being a niche tool and starts being infrastructure." Bumped from MEDIUM to HIGH.

**Fix approach:**
1. Reverse-engineer CAPE and Cuckoo3 report JSON schemas.
2. Ship `vishaya export --format cape` and `--format cuckoo`.
3. Reach out to CAPE maintainers about a Vishaya module for CAPE (they have a plugin system for capture backends).
4. Advertise the export ability in demos targeting existing Cuckoo users.

**Target files:** `src/export/`, outreach (not code)

---

## C. Implementation quality

### C-01. Kprobe/tracepoint mix uneven; consider LSM BPF for file ops

`OPEN` | `LOW` | `L` | source: review-1

**Description:** Process events use stable `sched_process_*` tracepoints. File events use raw `sys_enter_*/sys_exit_*` tracepoints (unstable ABI risk). LSM BPF (`fmod_ret`/`security_*`) on 5.15+ is more stable and gives richer context (dentry + inode).

**Notes:** LSM BPF requires `CONFIG_BPF_LSM=y` — not universal on distros. Should be an *additional* code path on kernels that support it, not a replacement.

**Fix approach:** Add LSM BPF probes for `security_file_open`, `security_inode_unlink`, `security_inode_rename` etc. Load conditionally based on kernel capability. Existing tracepoint probes remain as fallback.

**Dependencies:** enables C-02 (path resolution via dentry).

**Target files:** `bpf/vishaya_file.bpf.c` (LSM section), `src/collector/collector_libbpf.cpp` (conditional load)

---

### C-02. Path capture: no d_path reconstruction, no /proc/self/fd/N resolution

`OPEN` | `MEDIUM` | `M` | source: review-1

**Description:** Fixed 256-byte path buffers. Target opens files by fd + renames via `renameat(fd, ...)` produces meaningless paths. `/proc/self/fd/N` symbolic paths aren't resolved.

**Notes:** Real issue for advanced malware analysis. LSM BPF (C-01) gives dentry access, enabling proper reconstruction.

**Fix approach:**
1. In LSM BPF probes (once C-01 lands), use `bpf_d_path()` helper (kernel 5.10+) to reconstruct full paths from dentry.
2. Userspace enricher: cross-reference `/proc/<pid>/fd/N` for tracepoint probes to resolve fd → path.
3. Store both `path` and `path_resolved` fields when they differ.

**Dependencies:** C-01 (LSM BPF) enables this cleanly.

**Target files:** `bpf/vishaya_file.bpf.c`, `src/enricher/enricher.cpp`, `include/event_schema.h` (add `path_resolved` field), `docs/event-reference.md`

---

### C-03. Syscall probe: no per-event architecture

`OPEN` | `LOW` | `S` | source: review-1

**Description:** Cross-arch analyst opening an aarch64 bundle on x86_64 sees numeric syscall IDs with no indication they're aarch64-specific. Manifest has `capture.host.arch` but the syscall reader still has to remember to check.

**Notes:** Small fix. Emit architecture in each syscall event's `data`, or add a note in `event-reference.md` making the arch-check explicit.

**Fix approach:** Option A (small): document more prominently in `event-reference.md` §"family: syscall" that syscall numbers must be interpreted against `manifest.capture.host.arch`. Option B (larger): emit `syscall_name` via a userspace resolver using the arch table.

Recommend Option A now (documentation), Option B in v0.5 (syscall name enrichment).

**Target files:** `docs/event-reference.md` (immediate), later `src/enricher/enricher.cpp` (name resolution)

---

### C-04. Binary serialization format (FlatBuffers / Protobuf)

`REJECTED` | source: user

**Proposal:** Replace NDJSON events with a binary schema (FlatBuffers or Protocol Buffers) for near-zero serialization latency.

**Why rejected:** JSON-per-event is a deliberate design choice, not an implementation accident.
- Human readability is a feature: any analyst can `cat events.ndjson | jq` without installing tooling. This is core to the "tool-independent evidence format" positioning.
- zstd compression at level 3 already eliminates most of the size concern — compressed NDJSON is close to compact binary in practice for the data shapes we emit.
- Serialization latency is not the bottleneck in our pipeline. The bottleneck is BPF ring-buffer drain rate and WAL write throughput, neither of which is helped by a different serialization format.
- Adopting a binary format fragments the reader ecosystem before it exists. The spec (I-01) only becomes a standard if third-party readers can be written in an hour; binary schemas require generated code per language and version.
- If latency ever becomes a real bottleneck (profiling shows JSON serialize time in the critical path), the right move is binary format in the WAL only (internal) while keeping NDJSON in the bundle (external). But that is a micro-optimization for a future that doesn't exist yet.

---

## D. Force multipliers (Tier 1)

### D-01. Python/Rust SDK for bundle reading

`OPEN` | `HIGH` | `M` | source: review-1

**Description:** Reader ecosystem. libpcap made pcap the standard because writing a 20-line Python script against a capture is trivial. Vishaya has structured JSON but no idiomatic reader library.

**Notes:** Biggest strategic insight in the review. Turns Vishaya from "a tool" into "a substrate people build on."

**Fix approach:**
1. Python package `vishaya`: pure-Python or ctypes over libarchive + zstd + json. Idiomatic iterator: `for event in vishaya.read('case.vishaya'): ...`.
2. Publish to PyPI: `pip install vishaya`.
3. Rust crate for performance-sensitive consumers.
4. Documentation with 3-5 example scripts (IOC extraction, timeline visualization, filter by process).

**Estimated 2-3 weeks for Python SDK; Rust SDK follows.**

**Dependencies:** none. Uses existing bundle format.

**Target files:** new `sdk/python/` directory in this repo (or separate repo `vishaya-python`). Follow-on `sdk/rust/`.

---

### D-02. Semantic diff (`vishaya diff a.vishaya b.vishaya`)

`OPEN` | `HIGH` | `M` | source: review-1 (already in enterprise-features A2)

**Description:** Same sample run twice → show what changed. New files touched, new endpoints contacted, new syscall patterns.

**Notes:** Nobody has this for process traces. Enables "did the patch fix it?" and "did the sample behave differently in this VM?" workflows.

**Fix approach:** New subcommand. Compares two bundles' events + process trees + counts. Output as human-readable diff or `--format ndjson` for pipelines. Best when combined with B-03 (--normalize) for meaningful comparison.

**Dependencies:** benefits enormously from B-03 (--normalize).

**Target files:** new `src/inspect/diff.{h,cpp}`, `src/cli/dispatcher.cpp`

---

### D-03. Cryptographic chain-of-custody DEFAULT

`OPEN` | `HIGH` | `M` | source: review-1 (== A-03)

**Description:** Same item as A-03; consolidating here as a Tier 1 force multiplier because reviewer emphasized default vs opt-in.

**See A-03 for fix details.**

---

### D-04. MITRE ATT&CK post-processing pass

`OPEN` | `HIGH` | `L` | source: review-1 (already in enterprise-features A4)

**Description:** `vishaya analyze case.vishaya` reads events and tags observed techniques (T1055 process injection, T1071 C2 over HTTP, etc.). Rules in simple YAML, not another Sigma dialect.

**Notes:** Gets Vishaya into an analyst's actual workflow. Foundation for I1 (executive summary) and I4 (cross-capture correlation).

**Fix approach:**
1. Design YAML rule format (event-family + kind + field-match patterns → technique ID + rationale).
2. Ship starter rule set covering the top 20-30 techniques observable via process/file/network events.
3. `vishaya analyze` command emits a `mitre.json` sidecar in the bundle.
4. `vishaya inspect mitre bundle` shows matched techniques with citations to source events.

**Dependencies:** none for the analyzer; enables I1, I4.

**Target files:** new `src/analyze/` module, `rules/mitre/*.yaml`, `docs/mitre-rules.md` (new)

---

## E. DFIR fit (Tier 2)

### E-01. YARA on artifacts and payload prefixes

`OPEN` | `MEDIUM` | `M` | source: review-1 (already in enterprise-features A5)

**Description:** `vishaya scan case.vishaya --rules malware.yar`. Match against captured artifacts and against payload bytes in network events.

**Fix approach:** Depend on YARA C API. Post-capture scanner walks bundle contents, emits `yara-match` events into a sidecar.

**Dependencies:** artifact capture (in v0.5).

**Target files:** new `src/analyze/yara.{h,cpp}`

---

### E-02. Plaso super-timeline / MACtime CSV export

`OPEN` | `MEDIUM` | `S` | source: review-1

**Description:** DFIR analysts already have workflows built around Plaso/log2timeline. Meeting them where they are is more valuable than inventing a new format.

**Fix approach:** `vishaya export --format plaso-l2t-csv` — emit L2T format CSV. Same for MACtime bodyfile format. Well-documented external formats; small implementations.

**Target files:** `src/export/plaso.{h,cpp}` (or in `src/inspect/`)

---

### E-03. Bundle merging (`vishaya merge`)

`OPEN` | `LOW` | `M` | source: review-1

**Description:** Sample A drops sample B; B is captured separately. `vishaya merge a.vishaya b.vishaya -o combined.vishaya` produces a unified case.

**Notes:** Reviewer flagged this. My earlier take was "niche" — but for chained-execution malware analysis it's real. Bump to Medium in v1.0 timeframe.

**Fix approach:** Union event streams (chronological merge), union process trees (keeping A's root as canonical), combine artifacts dir with slug prefixing, sign the merged bundle.

**Dependencies:** A-03 (signing) for merged-bundle attestation.

**Target files:** new `src/bundle/merge.{h,cpp}`, `src/cli/dispatcher.cpp`

---

### E-04. Container-native capture (`--target-cgroup` / `--target-container`)

`OPEN` | `MEDIUM` | `M` | source: review-1

**Description:** Accept `--target-cgroup <path>` or `--target-container <id>` to attach to an already-running process. Enables capturing a pod under active attack.

**Fix approach:**
1. `--target-cgroup <path>`: skip cgroup creation; use the given path. Skip launch_target — just start Session with the given cgroup ID and stream until Ctrl-C or `--duration <s>`.
2. `--target-container <id>`: look up container's cgroup path via docker/podman/crictl.

**Dependencies:** A-04 (container awareness) for meaningful process tree.

**Target files:** `src/cli/capture_cmd.cpp`, `src/isolation/cgroup.cpp` (add "attach existing" mode)

---

## F. Ecosystem plays (Tier 3)

### F-01. OCSF exporter

`OPEN` | `HIGH` | `S` | source: review-1 (== B-02)

**Description:** `vishaya export --format ocsf` — half a day of code for enormous integration surface.

**See B-02 for fix approach.**

---

### F-02. MCP server for bundle inspection

`OPEN` | `MEDIUM` | `L` | source: review-1 (already in enterprise-features I5)

**Description:** MCP server that exposes bundle contents as tools/resources. Analyst points Claude/Cursor at a bundle and asks natural-language questions.

**Notes:** Reviewer is more bullish than my roadmap positioned this. Structured JSON bundle is a materially better LLM substrate than PCAP or Sysdig captures. Being first defines the niche.

**Fix approach:**
1. MCP server exposing `list_processes`, `get_files_written(pid)`, `get_network_flows`, `extract_iocs`, `search_events(query)` tools.
2. Read-only (no write actions on the analyst's system).
3. Local-only default; documented threat model around tool poisoning.
4. Documentation for connecting from Claude Desktop, Cursor, Continue.dev.

**Dependencies:** benefits from D-01 (SDK) if implemented in Python; benefits from D-04 (MITRE) for semantic queries.

**Target files:** new `mcp-server/` directory (probably Python for MCP ecosystem fit); or separate repo.

---

### F-03. Sandbox adapter for CAPE/Cuckoo/Any.run

`OPEN` | `MEDIUM` | `M` | source: review-1 (== B-04)

**See B-04 for fix approach.**

---

### F-04. Static single-page HTML viewer

`OPEN` | `HIGH` | `M` | source: review-1

**Description:** A single-file HTML that a `.vishaya` can be dropped into. Zero server, zero install. Non-CLI users can consume bundles.

**Notes:** Reviewer's most novel suggestion. This is what makes a bundle format actually shareable with non-analysts (execs, legal, external teams).

**Fix approach:**
1. Single-page app in vanilla JS or minimal framework (SvelteKit static export).
2. Uses browser-side libraries to decompress zstd and parse tar (both exist as WASM).
3. Renders: process tree, event timeline, files table, network table, artifact browser.
4. Ship as `vishaya-viewer.html` — a single ~500 KB file with all deps inlined.

**Dependencies:** stable bundle format (v1.0).

**Target files:** new `viewer/` directory (or separate repo `vishaya-viewer`). Build produces one HTML file distributed alongside releases.

---

### F-05. Interactive TUI reader

`CUT` (2026-07, see roadmap-decisions.md) | ~~`LOW` | `L`~~ | source: user

**CUT:** Low value for high cost (adds a UI dependency, `L` effort). A one-screen `summary`
view plus the one-shot `tree`/`files`/`network`/`timeline` commands cover hands-on terminal
use at far lower cost. Revisit only if there's real demand for interactive drill-down.

**Description:** Add an interactive terminal-UI mode for post-capture investigation. The current `vishaya tree / files / network / timeline` subcommands are one-shot outputs suitable for pipelines and scripts. An interactive TUI lets an analyst scroll, filter by event family or PID, jump to a timestamp, and drill into event detail — without opening a browser or leaving the terminal.

**Notes:** Complementary to F-04 (static HTML viewer), not a replacement. F-04 is the right choice for sharing bundles with non-CLI users and for reports; the TUI targets hands-on investigation at a terminal during live analysis. Libraries to evaluate: `ftxui` (header-only C++17, permissive license, cross-platform), `notcurses` (faster but heavier). Keep the TUI dep **optional** — build as a separate binary or behind a CMake feature flag so the main `vishaya` binary stays dep-free for environments that only need the capture path.

**Fix approach:**
1. New subcommand `vishaya inspect --interactive bundle.vishaya` (or alias `vishaya tui bundle.vishaya`).
2. Three-panel layout: process tree left, event list center (scrollable, paginated), event detail right.
3. Filter bar: by family (`process`, `file`, `network`, `syscall`), by PID, by time range.
4. Keyboard navigation: j/k scroll, g/G top/bottom, / search, f cycle family filter, q quit — Vim-compatible bindings.
5. Optional: ship as a separate `vishaya-tui` binary with `ftxui` statically linked, keeping the main binary dependency-free.

**Dependencies:** F-04 (HTML viewer) should ship first — it covers more use cases with lower complexity. TUI is follow-on work in the v1.0+ window.

**Target files:** new `src/tui/` directory, `CMakeLists.txt` (optional `BUILD_TUI` feature flag), `docs/getting-started.md` (note the optional TUI binary)

---

## G. Deeper technical bets (Tier 4)

### G-01. LSM BPF for file ops (== C-01)

`OPEN` | `LOW` | `L` | source: review-1

**Description:** Same as C-01. Kept here for Tier 4 grouping.

**See C-01 for fix approach.**

---

### G-02. TLS uprobe library

`OPEN` | `HIGH` | `L` | source: review-1 (already in enterprise-features C2)

**Description:** Hook `SSL_write`/`SSL_read` in libssl, and equivalents in NSS/GnuTLS/BoringSSL/Rustls. Emit plaintext to the same network family with `tls_decrypted=true`.

**Notes:** v0.5's headline feature. Hard to get right. Depends on A-02 (iovec payload capture) for full coverage.

**Fix approach:**
1. Start with OpenSSL (widest deployment): resolve symbol offsets from libssl.so via BTF or DWARF.
2. Attach uprobes on `SSL_read`/`SSL_write` return.
3. Capture plaintext bytes into new event kinds `tls-read` / `tls-write`.
4. Follow with BoringSSL (Chrome, Google), then GnuTLS, then NSS, then Go's crypto/tls (statically-linked variant is painful), then Rustls.

**Dependencies:** A-02 (iovec).

**Target files:** `bpf/vishaya_tls.bpf.c` (new), `src/capture/protocol_decoder.cpp` (TLS event handling)

---

### G-03. `--follow-exec-into` for droppers

`OPEN` | `LOW` | `M` | source: review-1

**Description:** Target that drops-and-executes `/tmp/xyz` isn't cleanly handled by the current single-binary model.

**Notes:** In current design, cgroup inheritance handles most cases — if the target's child execs into a new binary, it stays in our cgroup and is captured. The gap is when the target uses systemd/dbus/etc. to spawn a detached process in a different cgroup. Real but edge-case.

**Fix approach:** Add `--follow-exec-into <path-pattern>` flag that watches for exec events matching the pattern; when seen, dynamically place the newly-exec'd process into a linked cgroup (or extend the target cgroup filter to include).

**Priority:** Low because the common case (target's own exec chain) already works. Document the edge case for now.

**Target files:** `src/capture/session.cpp`, `bpf/vishaya_common.bpf.h` (cgroup filter extension)

---

## H. Documentation updates

### H-01. vision.md — security boundary honesty

`OPEN` | `HIGH` | `S` | source: self (from review-1 A-05)

**Description:** Add a bold "not a hardened detonation chamber" paragraph to `vision.md` non-goals.

**See A-05 for language.**

**Target files:** `docs/vision.md`, `docs/getting-started.md`, `docs/troubleshooting.md`

---

### H-02. enterprise-features.md — reorder + new features

`OPEN` | `HIGH` | `S` | source: self (from review-1 analysis)

**Description:** Update `enterprise-features.md` to reflect reprioritization:
- F1 (signing) → Wave 1 *default*, not optional
- New Wave 1 item: D-01 SDK (Python + Rust)
- New Wave 2 items: A-04 container awareness, B-03 --normalize, F-04 static HTML viewer
- A-02 iovec payload → Wave 2 (blocker for G-02)
- I5 (MCP server) → Wave 3

**Target files:** `docs/enterprise-features.md`

---

### H-03. event-reference.md — coverage caveats section

`OPEN` | `MEDIUM` | `S` | source: self (from review-1)

**Description:** Add explicit "Coverage caveats and known limitations" section listing:
- Path resolution: /proc/self/fd/N unresolved; renames via fd may produce garbage paths
- Syscall numbers architecture-specific (already noted; make prominent)
- Container context: not captured in v0.1; planned for v0.5
- Adversarial evasion: namespace escape possible; not a hardened sandbox

**Target files:** `docs/event-reference.md`

---

### H-04. bundle-spec-v0.1.md — clarify drop semantics + note additive fields

`OPEN` | `MEDIUM` | `S` | source: self (from review-1 A-01)

**Description:**
- Clarify `counts.events_dropped` semantic (BPF ring-buffer failures + userspace decode failures).
- Add per-family drop counts to schema.
- Note that future versions will add `container_context`, `signature`, `attestation` as additive fields per major-compat rule.
- Note that `manifest.sig` may appear as an additional tar entry in signed bundles.

**Target files:** `docs/bundle-spec-v0.1.md`

---

## I. Strategic framing / distribution

Items in this category come from review-1 §7 ("Bottom line"). They are strategic more than tactical — they change *how the same features are perceived* by users, and can be shipped independently of feature work.

### I-01. Publish bundle-spec-v0.1.md as an independent specification

`OPEN` | `HIGH` | `S` | source: review-1 §7

**Description:** "Formats win by being adopted; if only Vishaya reads `.vishaya`, it's just a file extension. If two independent readers exist, it's a format." Publish `bundle-spec-v0.1.md` as an independent spec (GitHub gist, IETF-style draft, or a separate repo like `vishaya-spec`) so third-party writers/readers can point at a stable reference outside the reference implementation's repo.

**Notes:** This is what turned PCAP into a standard rather than a Wireshark output format. Prerequisite step to any third-party ecosystem developing around Vishaya bundles.

**Fix approach:**
1. Copy `bundle-spec-v0.1.md` to a standalone location — options in order of increasing formality:
   - A GitHub gist under your account (easiest; treat as canonical)
   - A separate `vishaya-spec` repo under the project org
   - Submit as an IETF individual-submission draft (highest formality; slow)
2. Add a stable URL in `README.md` and `docs/bundle-spec-v0.1.md`: "Canonical spec: <url>"
3. Add a small "reference implementation compliance" note: Vishaya v0.1.x produces bundles conformant with spec v0.1.0.
4. Announce publicly (blog post, HN post, r/netsec) — the point is discoverability by potential third-party implementers.

**Dependencies:** none. Ship independently of code work.

**Target files:** new external repo/gist; `README.md`, `docs/bundle-spec-v0.1.md` for cross-links.

---

### I-02. Reframe pitch: "PCAP-equivalent for process behavior"

`REJECTED` (2026-07 research) | ~~`HIGH`~~ | source: review-1 §7

**REJECTED:** The positioning research found this tagline is the *literal marketing line* of
`.scap`/Stratoshark (CNCF/Sysdig) — adopting it invites a direct, losing comparison to an
incumbent. Repositioned instead around **verifiable + target-scoped + single-file evidence**
(applied to `README.md` and `docs/vision.md`; rationale in
[research/2026-07-product-positioning.md](research/2026-07-product-positioning.md)). Original
proposal preserved below for history.

**Description (superseded):** Current framing in `README.md` and `vision.md` reads as "another eBPF tool with a nice bundle format" — loses to Tracee + Tetragon on features. Reviewer's sharper reframing: **"the PCAP-equivalent for process behavior — a portable, verifiable, tool-independent evidence format for a single suspect binary."** This points at the actual gap in the ecosystem instead of a crowded feature comparison.

**Notes:** This is not a rewrite of the docs, just a tightening of the leading sentences and the taglines. The rest of `vision.md` already supports this framing; we just need to lead with it.

**Fix approach:**
1. Update `README.md` opening tagline to lead with the PCAP-analogy.
2. Update `docs/vision.md` §1 ("The problem") to explicitly make the PCAP-for-process-behavior comparison.
3. Update the elevator-pitch line in `docs/getting-started.md`.
4. When rebuilding the talk deck / any external material, lead with this line.
5. Suggested opening for README: "*Vishaya is a portable, verifiable, tool-independent evidence format for observing a single Linux binary — the PCAP-equivalent for process behavior. One command captures everything a target does; one file goes into the case; any compatible tool reads it.*"

**Dependencies:** benefits from I-01 (once the spec is external, "tool-independent" is a fact, not a hope).

**Target files:** `README.md`, `docs/vision.md`, `docs/getting-started.md`, `demo/talk-script.md`

---

## Review-1 §7 strategic framing (captured verbatim for future re-read)

The final review section made three "elevation moment" observations. Keeping them here so we don't lose them when picking up this backlog months from now:

> **On what elevates it from demo to tool:**
> "Add the SDK + the diff + the ATT&CK tagger and it stops being a demo and starts being an analyst tool."
>
> Corresponds to items: **D-01** (SDK) + **D-02** (semantic diff) + **D-04** (MITRE ATT&CK). All three are HIGH priority in the backlog for a reason — they are collectively the "not a demo anymore" line.

> **On what makes it credible in a DFIR/legal context:**
> "Sign bundles by default and it starts being credible in a real DFIR/legal context."
>
> Corresponds to: **A-03** (signing default). This is why A-03 must ship signing as default rather than as an opt-in flag.

> **On what elevates it from niche to infrastructure:**
> "Ship a sandbox adapter and an OCSF export and it stops being a niche tool and starts being infrastructure."
>
> Corresponds to: **B-04 / F-03** (Cuckoo/CAPE adapter) + **B-02 / F-01** (OCSF export). Bumped B-04 to HIGH based on this framing (see revised priority).

> **On what the real risk is:**
> "The real risk isn't technical — it's positioning. Right now the README and vision doc read as 'another eBPF tool with a nice bundle format.' That framing loses to Tracee + Tetragon on features. Reframing as 'the PCAP-equivalent for process behavior — a portable, verifiable, tool-independent evidence format for a single suspect binary' is much sharper and points at the actual gap in the ecosystem."
>
> Corresponds to: **I-02** (pitch reframe). This is why I-02 is HIGH — the perceived positioning changes what audience the tool reaches even without changing what the tool does.

> **On the format-as-standard move:**
> "One concrete recommendation before v0.5: publish the bundle-spec-v0.1.md as an independent spec (even a GitHub gist counts), separate from the reference implementation. Formats win by being adopted; if only Vishaya reads .vishaya, it's just a file extension. If two independent readers exist, it's a format."
>
> Corresponds to: **I-01** (independent spec). Prerequisite for anyone (else) building a `.vishaya` reader.

## Confirmation: review-1's tiered feature list matches existing backlog items

The reviewer's four-tier ranked feature list all map to existing backlog items. Reconfirming here to make sure nothing was lost in translation:

**Tier 1 (force multipliers, before v0.5):**
1. Deterministic replay + Python/Rust SDK → **D-01**
2. Semantic diff (`vishaya diff a.vishaya b.vishaya`) → **D-02**
3. Cryptographic chain of custody by default (Ed25519 + optional Sigstore/Rekor) → **A-03 / D-03**
4. MITRE ATT&CK post-processing tagger → **D-04**

**Tier 2 (sharpen DFIR fit):**
5. YARA on artifacts + payload prefixes → **E-01**
6. Plaso super-timeline / MACtime CSV export → **E-02**
7. Bundle merging → **E-03**
8. Container-native capture (`--target-cgroup`, `--target-container`) → **E-04**

**Tier 3 (ecosystem plays):**
9. OCSF exporter → **B-02 / F-01**
10. MCP server for bundles → **F-02**
11. Sandbox adapter (CAPE / Cuckoo / ANY.RUN) → **B-04 / F-03** (bumped to HIGH per §7 framing)
12. Static single-page HTML viewer → **F-04**

**Tier 4 (deeper technical bets):**
13. LSM BPF for file ops → **C-01 / G-01**
14. TLS uprobe library → **G-02**
15. `--follow-exec-into` for droppers → **G-03**

All 15 tier items are already tracked. The only additions from this new pass are **I-01** (publish spec independently) and **I-02** (reframe pitch as PCAP-for-process-behavior), plus the priority bump on **B-04** and the verbatim framing quotes above.

---

## Sequencing & workflow → see the decisions doc

Build order, priority, and per-item status live in
[roadmap-decisions.md](roadmap-decisions.md) — the v0.5 "core" set, the KEEP/DEFER/CUT
verdicts, and the Audit-items status. This backlog is the detailed reference for each
item's problem and fix approach, not a planner or status tracker. The
[`docs/roadmap.md`](roadmap.md) version-based roadmap is the external-facing view.

To work an item: find its verdict in the decisions doc, read the detailed write-up here for
the fix approach and target files, do the work, then update the verdict/notes in the
decisions doc (not here).

---

## Review-2 — deep code audit (2026-07-20)

A module-by-module audit against the documented v0.1 claims surfaced correctness/safety
issues below the v0.1 line (i.e. not features — the tool not yet doing its core job safely).
These are being fixed as a focused "make v0.1 true" batch, each with a per-fix review.
Source tag: `review-2`.

### R2-01. OOB read in protocol decoder — `payload_len` not clamped to buffer

`DONE` | `CRITICAL` | `S` | source: review-2

**Description:** `try_decode_dns` / `try_decode_http` used `network_event.payload_len`
as the parse bound, but the backing `payload_prefix[]` is a fixed
`VISHAYA_NET_PAYLOAD_LEN` (128) bytes. `payload_len` is set by the BPF probe and copied
verbatim by the decoder (`src/decoder/decoder.cpp` validates struct size but not this
field). A value > 128 (buggy/ABI-mismatched producer, decode skew, or memory corruption)
caused reads past the buffer — in the exact code path that parses untrusted target bytes.

**Fix:** Clamp to `std::min<size_t>(e.payload_len, VISHAYA_NET_PAYLOAD_LEN)` at both parse
sites; all downstream bounds already key off the clamped `plen`. No-op for conformant
bundles (BPF producer already clamps at capture time), so zero behavior change. Added
`<algorithm>`.

**Files:** `src/capture/protocol_decoder.cpp`. No format/schema/doc change (internal
reader-hardening; bundle output identical).

### R2-02. Reader never verified integrity hashes or signatures

`DONE` | `CRITICAL` | `M` | source: review-2 (overlaps A-03 / D-03)

**Description:** The writer computes SHA-256 integrity hashes AND signs every bundle by
default (Ed25519, `src/bundle/sign.cpp`), but the reader never checked either:
`Reader::verify_integrity()` existed but was called by nobody, and there was no signature
verification code at all. The tool shipped tamper-evidence it computed but never
validated — violating spec §3.2 ("readers MUST verify [the signature] when present") and
§9 (SHOULD verify integrity at load).

**Fix:**
- Added `verify_signature()` (Ed25519 via OpenSSL `EVP_DigestVerify`, mirrors the pure-
  null-md signing side) + `base64_decode()` in `src/bundle/sign.{h,cpp}`.
- Added `Reader::verify()` returning a `VerifyReport` (integrity + signature). Runs
  `verify_integrity()`, then verifies the signature over the exact writer-signed payload
  `<events_sha256>\n<process_tree_sha256>\n`. Logs WARN on integrity/signature failure,
  INFO on unsigned (spec §6 SHOULD-warn), debug on success. Non-fatal.
- Wired `reader.verify()` into all four inspect commands (`tree`/`files`/`network`/
  `timeline`) at load time. stdout output unchanged; verification logs to stderr only.
- Bumped CMake OpenSSL floor `1.1` → `1.1.1` (real floor for Ed25519 — pre-existing).

**Reviewed:** independent static review — crypto correct & leak-free, signed-payload
reconstruction byte-exact, unsigned bundles treated valid, no stdout regression.

**Follow-up (deferred):** `--no-verify` (perf escape hatch) and `--strict` (fatal on
failure) flags; a positive one-line verification summary in inspect output. Not blocking.

**Files:** `src/bundle/sign.{h,cpp}`, `src/bundle/reader.{h,cpp}`,
`src/inspect/{tree,files,network,timeline}.cpp`, `CMakeLists.txt`,
`docs/architecture.md` (§11 stale non-goal reconciled), `docs/roadmap.md` (v0.1 caps +
v1.0 attestation item clarified).

### R2-03. Exec event captured no data (path/argv missing)

`DONE` | `CRITICAL` | `M` | source: review-2

**Description:** `sched_process_exec` emitted only an event header — `filename`, `exec_path`,
`cmdline`, `cwd`, `parent_comm` were all zeroed. The single most important forensic fact
("what binary ran, with what arguments") relied entirely on userspace `/proc` enrichment,
which races and comes up empty for short-lived processes. For a DFIR capture tool this was
a core-function gap, not a feature gap.

**Fix (in-kernel, race-free capture at exec time):**
- New `capture_exec_context()` helper in `bpf/vishaya_common.bpf.h`: reads `cmdline` from
  the current task's argv block (`mm->arg_start..arg_end`, NUL→space to match the userspace
  convention, bounded to `VISHAYA_PATH_LEN`) and `parent_comm` from `real_parent->comm` via
  CO-RE.
- `on_sched_exec` now typed to `struct trace_event_raw_sched_process_exec*` and reads the
  executed path from the tracepoint `__data_loc` filename into `ev->filename`, then calls
  the helper.
- Enricher (`src/enricher/enricher.cpp`) keeps its fill-if-empty role (so BPF-captured
  cmdline/parent_comm are preserved) and gained an `exec_path = filename` fallback for
  processes that exit before `/proc/<pid>/exe` can be read.

**Provenance split:** `filename`/`cmdline`/`parent_comm` = reliable (kernel);
`exec_path`/`cwd`/`start_time_ticks` = best-effort (/proc), with `exec_path` falling back to
`filename`.

**Reviewed:** independent BPF static review — verifier-safe (clen mask-bounded, loop/index
in range), `__data_loc` + `BPF_CORE_READ*` patterns correct and consistent with existing
probes, kernel fields present on 5.15+, enricher preserves kernel data, no regression to
fork/exit/clone. Not compiled (Linux-only; Windows host) — load-time verifier pass still
to be confirmed on a Linux build host.

**Follow-up (deferred):** in-kernel `cwd` (needs LSM/`bpf_d_path`, not available from this
tracepoint) and start-time unit reconciliation (task `start_time` ns vs /proc ticks).

**Files:** `bpf/vishaya_process.bpf.c`, `bpf/vishaya_common.bpf.h`,
`src/enricher/enricher.cpp`, `docs/event-reference.md`, `docs/code-walkthrough.md`.

### R2-04. `is_network_probe_enabled` defaulted OFF (inconsistent footgun)

`DONE` | `HIGH` | `S` | source: review-2

**Description:** `is_network_probe_enabled` returned false when its toggle-map key was absent,
while `is_file_probe_enabled` / `is_process_probe_enabled` default true. Network is a
default-on family, so a missing/partially-applied `network_probe_enabled` map (or a newly
added network kind not listed in userspace `ApplyNetworkProbeConfig`) silently dropped all
network capture with no error — a footgun the file/process families don't have.

**Fix:** Made the absent-key case return true, matching the other default-on families.
Happy path unchanged (userspace populates all 23 kinds with 1). Disable path unchanged
(userspace explicitly writes 0). Syscall domain intentionally stays default-off (opt-in).

**Reviewed:** trivial 3-line change mirroring the existing file/process helpers; only the
absent-key case changes (OFF→ON), which is the correct default-on behavior. No doc change
(architecture §5 already documents network as default-on).

**Files:** `bpf/vishaya_common.bpf.h`.

### R2-05. Silent host-wide capture fallback when scoping unavailable

`DONE` | `HIGH` | `S` | source: review-2

**Description:** If the loaded BPF object lacked the `target_cgroup_id` map, `Session`
logged a warning and captured **host-wide** — recording every process on the host while the
bundle's manifest still claimed target-scoped isolation. For an evidence tool, silently
widening scope produces misleading bundles.

**Fix:** `Session` now throws `CaptureError` when scoping is requested (`target_cgroup_id
!= 0`) but `SetTargetCgroup` fails, unless the new `--allow-host-wide` flag is set (then it
warns and proceeds). The throwing constructor detaches the collector explicitly first
(the destructor doesn't run on a ctor throw). Happy path unchanged (map present → scoping
active → no throw). `target_cgroup_id == 0` still means explicit host-wide for non-CLI
callers. Also reconciled stale docs: `session.h` header comment (claimed "does NOT filter
by target cgroup"), the inaccurate "atomic step" comment in `capture_cmd.cpp`, and
`troubleshooting.md` (old "will still capture host-wide" guidance + a dead
`session.set_target_cgroup()` API reference).

**Reviewed:** self-review — throw-path cleanup correct (collector detached, `wal_` closed
via member destruction, `Cgroup`/`TmpDir` RAII unwind, target not yet launched so no
orphan); `CaptureError` caught by `run_capture`; new ctor param defaulted so no other
caller breaks (only one construction site).

**Follow-up (deferred):** record a `capture.host_wide` / scoping-status field in the
manifest so a consumer can tell a `--allow-host-wide` bundle from a scoped one (schema
addition; not done to avoid churn now).

**Files:** `src/capture/session.{h,cpp}`, `src/cli/capture_cmd.{h,cpp}`,
`src/cli/dispatcher.cpp`, `docs/troubleshooting.md`.

### R2-06. Process-tree reconstruction bugs (threads, double-edges, determinism)

`DONE` (partial — see R2-07) | `HIGH` | `M` | source: review-2

**Description:** `reconstruct_tree` had three defects: (1) `CLONE_THREAD` thread creations
were turned into phantom "child process" nodes (a thread's TID was seeded as a tgid),
polluting the tree for every multithreaded target; (2) a `fork()` surfaces via BOTH
`sched_process_fork` and `sys_exit_clone`, so children were double-counted; (3) the sort
had no tiebreaker, so equal timestamps gave nondeterministic order (contradicting the
"deterministic" claim).

**Fix:** Reworked to a single stream pass plus a deferred edge-resolution step. Records are
created only for tgids actually observed as a process event's `hdr.tgid` (real thread-group
leaders). fork/clone children are recorded as *candidate edges* and resolved at the end:
an edge is kept only if the child was itself observed as a process tgid (drops threads,
whose TID never appears as a tgid) and duplicate edges are collapsed. Sort is now
`(start_ts_ns, tgid)`. Child records take `ppid` from their own events (consistent with the
edge). Trade-off: a forked child whose *own* events were all dropped no longer gets a stub
record — only possible under event loss (already a reduced-confidence capture), and such a
child would otherwise be indistinguishable from a thread.

**Reviewed:** self-review — single-pass + resolution is correct for clean captures with no
regression (every real process emits at least its own exit under its tgid); inspect
tree/orphan logic still consistent; removed a dead `lineno` counter. Not compiled
(Linux-only host).

**Files:** `src/bundle/process_tree.{h,cpp}`, `docs/bundle-spec-v0.1.md`.

### R2-07. Process-tree PID/TGID reuse merges distinct processes

`OPEN` | `MEDIUM` | `M` | source: review-2 (split from R2-06)

**Description:** Records are keyed by tgid for the entire capture, so if a tgid is reused
(process A exits, later process B is assigned the same number) B's events merge into A's
record — wrong start time, comm, and exit. Rare for short detonation captures (pid_max is
large and churn is low), which is why it was split out of R2-06 rather than fixed blind.

**Fix approach:** Allow multiple generations per tgid. When a non-exit event arrives for a
tgid whose current record already has `end_ts_ns` set, archive that record and start a new
generation. Requires a completed-records list and generation-aware child-edge resolution.
Needs a Linux build host to validate against real reuse (event-ordering edge cases: an
out-of-order event after `exit` must not falsely split a record).

**Target files:** `src/bundle/process_tree.cpp`.

### R2-08. Timeline showed boot-relative ns; no global sort

`DONE` | `HIGH` | `M` | source: review-2

**Description:** `timeline` printed raw `bpf_ktime_get_ns()` values (CLOCK_MONOTONIC, boot-
relative) that can't be correlated to external evidence, and it relied on WAL file order
(only approximately chronological across CPUs). A fragile `setfill('0')` also risked leaking
into later columns.

**Fix (correct, not approximate):**
- Added a clock anchor to the manifest: `capture.clock_realtime_ns` + `clock_monotonic_ns`,
  sampled together at capture start (additive schema). `wall(event) = clock_realtime_ns +
  (ts_ns - clock_monotonic_ns)`.
- `timeline` now buffers + `stable_sort`s events by `ts_ns`, and prints absolute UTC when the
  anchor is present, falling back to `+S.mmm` relative time for pre-anchor bundles. Time
  formatting uses local ostringstreams (no iomanip state leak).
- Reconciled the over-claimed "strict chronological order" in `event-reference.md` and
  spec §8.4 to "approximately ordered; readers requiring strict order MUST sort" (§9.6),
  and documented the anchor + `ts_ns` mapping in the spec (§3) and event-reference envelope.

**Reviewed:** self-review — anchor math uses signed arithmetic (no underflow for pre-anchor
events); additive manifest fields default 0 with graceful fallback; sort is stable so
source/synthetic adjacency (shared ts_ns) is preserved. Not compiled (Linux-only host).

**Files:** `src/inspect/timeline.cpp`, `src/bundle/manifest.{h,cpp}`,
`src/cli/capture_cmd.cpp`, `docs/bundle-spec-v0.1.md`, `docs/event-reference.md`.

### R2-09. events.ndjson not canonically sorted at write time

`OPEN` | `MEDIUM` | `M` | source: review-2 (from R2-08)

**Description:** The writer emits `events.ndjson` in ring-buffer delivery order, only
approximately sorted by `ts_ns`. Spec §8.4 was relaxed from MUST to SHOULD to match. Each
reader currently sorts itself (timeline does). A canonical on-disk order would let all
readers — including third-party ones — trust the order and skip sorting, and would improve
reproducibility (relates to B-03 `--normalize`).

**Fix approach:** At finalize, sort `events.ndjson` by `ts_ns` before hashing (stable, to keep
source/synthetic adjacency). Buffers event lines in memory at finalize — fine for bounded
captures; consider an external merge sort if captures grow large. Then restore §8.4 to MUST.

**Target files:** `src/bundle/writer.cpp`, `docs/bundle-spec-v0.1.md`.

### R2-10. First real build: missing include + noisy warnings

`DONE` | `HIGH` | `S` | source: first compile on aarch64 Linux (UTM VM)

**Description:** The first actual compile (on ARM Linux) surfaced a pre-existing build blocker
that no amount of file-by-file static review caught, because the project had never been
compiled in this session (Linux-only; review host was Windows):
- **Blocker:** `src/capture/session.h` references `vishaya::collector::Collector*` but never
  included `collector/collector.h` nor forward-declared it; `session.cpp` includes
  `session.h` first, so `Collector` was undeclared. This was independent of the Review-2
  logic changes (the include set was unchanged). **Fix:** added
  `#include "collector/collector.h"` to `session.h` (header-light — no libbpf).
- **Warnings (cosmetic):** three `#pragma unroll` loops in the UNIX-sockaddr path copy
  (`vishaya_common.bpf.h`) can't be unrolled (data-dependent break) → 80+ `-Wpass-failed`
  warnings. Switched to `#pragma clang loop unroll(disable)` (identical codegen, bounded
  loop, verifier-fine on 5.3+). Marked the unused inherited `LogSyscallAllowlistPortability`
  `[[maybe_unused]]`.

**Confirmed good from this build:** the BPF object compiled and built
(`vishaya.bpf.o`), including the R2-03 exec-capture changes; `vishaya_bundle`,
`vishaya_inspect`, `vishaya_collector_core`, `isolation_probe`, `bundle_probe` all built —
so the R2-01/02/04/06/07/08 userspace changes compile. Remaining unverified until a clean
build completes: `vishaya_capture` (session.cpp) and `vishaya_cli` (capture_cmd.cpp clock
anchor + dispatcher flag), plus the BPF verifier load at runtime.

**Lesson:** cross-file include-graph / compile-order errors are invisible to per-file logic
review; they need a real compile. Treat "not compiled" findings (R2-03 especially) as
unverified until the Linux build + a capture run pass.

**Files:** `src/capture/session.h`, `bpf/vishaya_common.bpf.h`,
`src/collector/collector_libbpf.cpp`.

---

## Review-3 — external code review (2026-07, aarch64 focus)

An external reviewer flagged a set of issues; all were verified against the code. The two
gating ones are fixed below; the rest are confirmed and tracked (R3-*).

### R2-11 (C1). Network enter handlers overflowed the 512-byte BPF stack

`DONE` | `CRITICAL` | `M` | source: review-3 (verified)

**Description:** Every `on_sys_enter_*` in `vishaya_network.bpf.c` built
`struct network_state_value state = {}` (~656 bytes: a full 584-byte `network_event` + 9
`u64`) on the stack. The kernel verifier's per-frame limit is 512 bytes and all helpers are
`__always_inline`, so this is one frame → **every network program is rejected at load**, and
since `bpf_object__load()` is atomic, the whole object fails and capture never runs. The
`-bpf-stack-size=8192` flag only raises LLVM's compile limit, not the kernel cap — so it
compiled but never loaded. (The file/syscall paths already avoided this by stashing the
ringbuf pointer into the map; only network built the struct on the stack — the tell.) This
was a genuine miss in the Review-2 BPF audit.

**Fix:** Added a per-CPU scratch map `network_scratch` (`BPF_MAP_TYPE_PERCPU_ARRAY`,
max_entries=1, value=`network_state_value`) + `net_state_scratch()` helper in
`vishaya_common.bpf.h`. Every enter handler now assembles the state in the scratch slot via
a pointer (`state->…`, NULL-guarded) instead of a stack struct, then copies it into
`network_enter_state`. Semantics unchanged; `network_state_value`/`network_event` layouts
untouched, so userspace decode is unaffected.

**Reviewed:** independent BPF static review + spot-checks — NULL guard at all 23 call sites,
`memset`/ringbuf→map copy/`map_update` from a PTR_TO_MAP_VALUE all verify, every handler now
<200 B stack, no residual stack struct, collector needs no change (it resolves maps by name,
no enumeration). **Load-time verifier pass still to be confirmed on the VM.**

**Files:** `bpf/vishaya_common.bpf.h`, `bpf/vishaya_network.bpf.c`.

### R2-12 (H1). sendmmsg/recvmmsg byte accounting read wrong struct offsets

`DONE` | `HIGH` | `S` | source: review-3 (verified)

**Description:** `struct msghdr_min` omitted `msg_control`/`msg_controllen`/`msg_flags`, so it
was 32 bytes instead of the real 56. Consequently `mmsghdr_min` was 40 bytes (real: 64) →
wrong stride (every message after the first read garbage) and `msg_len` was read at offset 32
instead of 56 (so `bytes_transferred` for sendmmsg/recvmmsg was garbage even for one message).
Single `sendmsg`/`recvmsg` happened to work because `msg_iov`@16/`msg_iovlen`@24 fall within
the first 32 bytes.

**Fix:** Expanded `msghdr_min` to the full 56-byte LP64 layout → `mmsghdr_min` is now 64 bytes
with `msg_len`@56. Added `_Static_assert`s (56/64) to lock the ABI so a future edit can't
silently reintroduce the bug.

**Reviewed:** offsets verified against kernel `struct msghdr`/`mmsghdr`; downstream
`sum_mmsghdr_lengths`/`sum_mmsghdr_transfers` and the single-message reads now correct;
larger stack locals fine now that C1 moved `state` off-stack.

**Files:** `bpf/vishaya_common.bpf.h`.

### R2-13 (P2). Chain-of-custody hardening — sign the whole manifest + `vishaya verify`

`DONE` (Sigstore attestation still open) | `HIGH` | `M` | source: repositioning (Phase 2)

**Description:** Post-repositioning, verifiability is the product's headline, but signing only
covered the two content hashes — manifest metadata (counts, host, target, timestamps) was
unsigned (M1), there was no dedicated verify command, and no way to assert *who* signed.

**Fix:**
- **Sign the canonical manifest** (`sig.scope="manifest-v1"`): the signature now covers the
  whole manifest-minus-`sig` (deterministic compact JSON, keys sorted), which transitively
  covers content via `integrity.*_sha256`. New `manifest_signing_payload()`; writer reordered so
  schema/tool identity is set before signing. **Legacy two-hash bundles still verify** (reader
  branches on `sig.scope`).
- **`vishaya verify <bundle>`** — explicit stdout verdict (integrity + signature + key
  fingerprint), exit 0 only when verified.
- **`--verify-key <b64>`** — pin/assert the signing key (mismatch → FAILED).
- **Key fingerprint** (`pubkey_fingerprint()` = first 16 hex of SHA-256(raw key)) logged at
  capture and shown by `verify`.

**Verified by tests:** E10 (manifest-metadata tamper → signature INVALID — the new capability
the old scheme missed), E11/E12 (`verify` verdict + exit codes), E13 (`--verify-key` pin),
B14b (scope==manifest-v1). Symmetry audited: `manifest_from_json` parses every field
`manifest_to_json` writes, so writer/reader compute byte-identical signing payloads.

**Not compiled** (Linux-only host) — needs a VM build + `run-tests.sh` to confirm.

**Files:** `src/bundle/manifest.{h,cpp}`, `src/bundle/writer.cpp`, `src/bundle/sign.{h,cpp}`,
`src/bundle/reader.cpp`, `src/inspect/verify.{h,cpp}`, `src/cli/dispatcher.cpp`, `CMakeLists.txt`,
`docs/bundle-spec-v0.1.md`, `README.md`, `docs/roadmap.md`, `tests/`.

### R3-remaining. Confirmed review-3 findings (open)

All verified valid; deferred as follow-ups (not blocking the build):

- **H2** `MEDIUM`: `socket_fd_state` keyed by tgid → forked children reading inherited
  sockets, and pre-existing/`dup`'d fds, are missed for read/write/close/*v/*mmsg. Document;
  optionally seed inherited fds on fork.
- **H3** `LOW`: `iovec_min`/`msghdr_min` assume 64-bit userspace → 32-bit (compat) targets
  misdecode iovec byte counts/pointers. Document limitation.
- **M1** `HIGH` (chain-of-custody): **largely addressed by R2-13** — the whole manifest is now
  signed (metadata covered), the pubkey fingerprint is surfaced at capture, and `vishaya verify
  --verify-key` provides pinned-key verification. **Still open:** the key is self-generated and
  travels in-bundle, so this is tamper-evidence + pin-based authenticity, not third-party
  attestation. Remaining work = Sigstore/Rekor keyless attestation (v1.0 milestone).
- **M2** `MEDIUM`: `inspect/tree.cpp` `print_node` has no visited-set/depth cap → a crafted
  cyclic `process_tree.json` stack-overflows the analyzer (bundles are semi-trusted input).
  Add visited-set + depth bound; reconcile ppid-orphan vs children-edge parentage.
- **M3** `LOW-MED`: `verify_integrity()` slurps whole entries into memory to hash; stream it
  (reuse hash.cpp's chunked pattern) for multi-GB captures.
- **M4** `LOW-MED`: writer uses ustar (8 GB single-file cap); switch to
  `archive_write_set_format_pax_restricted` for large captures.
- **M5** `MEDIUM`: enrichment + container-ctx `/proc` reads run in the ring-buffer drain
  callback → back-pressure/drops under churn. Consider queue+worker if the G-load test shows
  drops.
- **M6** `LOW-MED`: microsecond host-wide window between probe attach and `SetTargetCgroup`
  (map defaults to 0=allow-all). Set `target_cgroup_id` before the attach loop to close it.
- **M7** `MEDIUM`: no checked-in `.vishaya` fixture, so `tests/` groups D/E skip without root.
  Ship a sample bundle (or generate via `bundle_probe`); `VISHAYA_TEST_BUNDLE` is already
  wired.
- **M8** (info): arm64 has no `sys_exit_vfork` tracepoint → `on_sys_exit_vfork` fails to
  attach and logs a line; expected, best-effort attach continues. Not a bug.
- **LOW batch**: dead allowlist maps/gates (return true); unused `network_state_value.sockaddr_len`
  field; misleading WAL "durability" claim; rename not dir-fsync'd; DNS not decoded over
  TCP/connected-UDP; silent `MAX_IOVEC_ENTRIES=8` undercount; hardcoded
  `coverage.network_layers`; `VISHAYA_DEFAULT_BPF_OBJECT` absolute source path (packaging).
