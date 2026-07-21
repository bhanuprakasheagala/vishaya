# Code Walkthrough

Module-by-module tour of the entire Vishaya codebase. Follow the flow from the kernel BPF probes up through the CLI. Every file mentioned here is worth opening as you read.

Prerequisite reading: [concepts.md](concepts.md) if you're new to eBPF/cgroups/namespaces, and [architecture.md](architecture.md) for the design-level view of the same territory.

## Repository layout

```
bpf/                       kernel-side eBPF probes
include/                   shared C ABI (BPF ↔ userspace)
src/
  common/                  logging, error types, RAII helpers
  collector/               inherited BPF load / attach / poll (namespace vishaya::collector)
  decoder/                 raw bytes → typed EventVariant (namespace vishaya::collector)
  enricher/                /proc-based enrichment for process events (namespace vishaya::collector)
  isolation/               cgroup v2 + mount namespace + target launch
  bundle/                  writer + reader for .vishaya files
  capture/                 Session, WAL writer, event → JSON, protocol decoder (DNS + HTTP)
  inspect/                 read-only subcommand implementations
  cli/                     argument parsing + subcommand dispatch + main()
scripts/                   build helper (linux.sh)
docs/                      you are here
```

Dependency direction (strict, one-way): `cli → capture / inspect → bundle / isolation → collector → common → bpf`.

## Kernel side (`bpf/`)

The BPF layer's job: attach to kernel tracepoints, filter events to just the target cgroup, populate typed event records, push them into a ring buffer for userspace to drain.

### `bpf/vishaya.bpf.c` — the aggregator

Ten lines. Includes the four probe files so they compile into a single BPF object:

```c
#include "vishaya_process.bpf.c"
#include "vishaya_file.bpf.c"
#include "vishaya_network.bpf.c"
#include "vishaya_syscall.bpf.c"
```

Each of those includes `vishaya_common.bpf.h`, whose header guard ensures the shared maps/helpers/license section are declared exactly once per translation unit.

### `bpf/vishaya_common.bpf.h` — maps, helpers, gates

This is the biggest and most important BPF file. It declares:

- **`events` map** — the ring buffer (16 MiB). Every probe reserves space here and submits event records.
- **`bpf_stats`** — per-CPU counters for kernel-side diagnostics (ring buffer reserve failures, state map collisions, etc.).
- **`file_probe_enabled` / `process_probe_enabled` / `syscall_probe_enabled` / `network_probe_enabled`** — runtime toggles keyed by event kind. Userspace sets these based on which domains it wants active.
- **`suppress_tgid`** — single-entry array holding the collector's own PID; probes drop events from this PID so Vishaya doesn't observe itself.
- **`target_cgroup_id`** — single-entry array holding the target's cgroup ID (Step 6). If zero, the cgroup filter is inactive.
- **`file_enter_state` / `syscall_enter_state` / `network_enter_state`** — LRU hash maps that hold enter-side syscall arguments until the exit tracepoint fires with the return value.
- **`socket_fd_state`** — hash map tracking which file descriptors are sockets, so read/write probes can distinguish socket I/O from regular file I/O.
- Helpers like `reserve_process_event()`, `reserve_file_event()`, `reserve_network_event()` that acquire ring-buffer space and populate the common `event_header`.

The two most important helpers:

**`is_event_allowed()`** is the single gate every probe calls at its top:
```c
static __always_inline bool is_event_allowed(void) {
  return is_not_suppressed_self() &&
         is_in_target_cgroup() &&
         is_current_pid_allowed() &&
         is_current_uid_allowed();
}
```

**`is_in_target_cgroup()`** implements the Step 6 target-scoped filter. If the `target_cgroup_id` map value is 0 (never set), returns true (all events allowed — backward-compat mode). Otherwise compares against `bpf_get_current_cgroup_id()`.

**`emit_network_exit_event()`** is the state-correlation function every network exit probe delegates to. It looks up the saved enter state, copies it into a fresh ring-buffer record, fills in `ret_code` and other exit-side fields, and — new in Step 9 — reads captured payload bytes from the recv buffer if the enter probe recorded a `payload_recv_ptr`.

**`capture_send_payload()`** captures up to `VISHAYA_NET_PAYLOAD_LEN` (128) bytes from a user-space buffer into a network event, called at enter time by send-side probes.

### The four probe files

Each attaches to kernel tracepoints for one event family:

- **`vishaya_process.bpf.c`** — `sched/sched_process_exec`, `sched/sched_process_fork`, `sched/sched_process_exit`, `syscalls/sys_exit_clone`, `syscalls/sys_exit_clone3`, `syscalls/sys_exit_vfork`. The exec handler captures the executed path (tracepoint `__data_loc` filename), the command line (argv block from `mm->arg_start..arg_end`, NUL→space) and the parent's `comm` in-kernel via the shared `capture_exec_context()` helper, so those fields survive even short-lived processes; fork/exit/clone just carry the child PID or exit code.
- **`vishaya_file.bpf.c`** — enter/exit pairs for `openat`, `unlinkat`, `renameat2`. Uses `file_enter_state` map to pair.
- **`vishaya_network.bpf.c`** — the big one (~830 lines). Enter/exit pairs for the 23 socket-related syscalls. Enter side saves user buffer pointers into `network_enter_state`; exit side pulls them out to read return-time data (received bytes, resolved sockaddr, etc.). Send-side probes (`sendto`, `write`) call `capture_send_payload()` at enter. Recv-side probes (`recvfrom`, `read`) save the buffer pointer for exit-time capture.
- **`vishaya_syscall.bpf.c`** — raw `sys_enter` and `sys_exit` tracepoints. High-volume; disabled by default.

## Shared ABI (`include/event_schema.h`)

C header included by both BPF and userspace. Declares:

- Event family enums (`enum vishaya_event_type`)
- Kind enums per family (`enum process_event_kind`, `enum file_event_kind`, etc.)
- Struct layouts: `event_header`, `process_event`, `file_event`, `syscall_event`, `network_event`, `network_endpoint`
- Buffer-size macros (`VISHAYA_COMM_LEN`, `VISHAYA_PATH_LEN`, `VISHAYA_UNIX_PATH_LEN`, `VISHAYA_NET_PAYLOAD_LEN`)

Wrapped in `extern "C"` for C++ consumers. This is the boundary contract — changing a struct here means recompiling BPF and userspace together.

## Userspace: the inherited collector

Three files, all under `namespace vishaya::collector`:

- **`src/collector/collector.h` / `collector_libbpf.cpp`** — the `Collector` abstract class and its libbpf implementation. Owns the BPF object lifecycle: opens the ELF file, loads programs into the kernel, iterates every program and attaches it to its tracepoint, sets up ring-buffer polling with a callback. `Start()` returns success/failure plus a rich startup report. `PollOnce(timeout_ms)` blocks in `ring_buffer__poll` up to the timeout, invoking the callback for each event surfaced. `SetTargetCgroup(cgroup_id)` (Step 6) writes to the target_cgroup_id map. `Stop()` detaches, frees, cleans up.
- **`src/decoder/decoder.h / decoder.cpp`** — one method, `Decode(raw_bytes)`, that validates the payload's type field and size, then memcpys into the appropriate typed struct and returns a `std::variant<process_event, file_event, syscall_event, network_event>` (typedef'd as `EventVariant`).
- **`src/enricher/enricher.h / enricher.cpp`** — for process events only, reads `/proc/<pid>/cmdline`, `cwd`, `exe`, etc. to fill in fields BPF couldn't populate. Uses a bounded LRU cache to avoid hammering /proc.

These modules pre-date the pivot to Vishaya but are treated as a stable inherited library. The `vishaya::collector` namespace was renamed from `event_logger` during the cleanup pass.

## Common utilities (`src/common/`)

Small, no external deps beyond stdlib:

- **`log.h / log.cpp`** — thread-safe logger. `vishaya::log::info(msg)`, `warn(msg)`, `error(msg)`, `debug(msg)`. Writes ISO-8601 timestamped lines to stderr with a level prefix. Log level set via `set_level()` (default Info; capture CLI's `-v` flag turns on Debug).
- **`errors.h`** — exception hierarchy: `vishaya::Error` (base), `IsolationError`, `BundleError`, `CaptureError`. All inherit from `std::runtime_error`.
- **`tmp_dir.h / tmp_dir.cpp`** — RAII scratch directory. Constructor creates `/tmp/<prefix>-<uuid>/` with mode 0700; destructor recursively removes it. `keep()` suppresses cleanup for debugging.

## Isolation (`src/isolation/`)

Everything to spawn a target inside a cgroup + mount namespace.

- **`cgroup.h / cgroup.cpp`** — the `Cgroup` class. Constructor `mkdir`s `/sys/fs/cgroup/vishaya-<uuid>/`, reads back the inode number as the cgroup ID (used later for BPF filtering). Destructor `rmdir`s. `attach_pid(pid)` writes the PID to `<path>/cgroup.procs`. Move-only, RAII.
- **`target_launch.h / target_launch.cpp`** — `launch_target(opts, ns, cgroup)`. Sets up a sync pipe, forks. Parent attaches child to cgroup, signals via pipe, returns. Child blocks on pipe read until signaled, then unshares mount ns, remounts `/` as `MS_PRIVATE` (so future mounts don't leak to host), chdirs, sets `PR_SET_PDEATHSIG` (best-effort), and `execve`s the target. `wait_for_exit(pid)` is the blocking waitpid with EINTR-retry.
- **`isolation_probe.cpp`** — standalone binary. Exercises Cgroup + launch_target with no eBPF involvement. Useful for debugging isolation issues.

## Bundle format (`src/bundle/`)

Everything to produce and consume `.vishaya` files.

- **`schema_version.h`** — the constants `kSchemaVersion = "0.1.0"`, `kToolName = "vishaya"`, `kToolVersion = "0.1.0"`. Single source of truth for versioning.
- **`manifest.h / manifest.cpp`** — the `Manifest` struct and its JSON ser/de. Layout mirrors [BUNDLE-SPEC-v0.1 §3](bundle-spec-v0.1.md). `manifest_from_json` enforces the schema-major compat rule: a bundle with major > reader's major is rejected with a clear error. Unknown fields are silently ignored.
- **`process_tree.h / process_tree.cpp`** — the `ProcessTree` struct and its JSON ser/de, plus `reconstruct_tree(events_path, root_pid)` which walks `events.ndjson` line by line, watches for process family events, and builds the lineage.
- **`writer.h / writer.cpp`** — `write_bundle(input)`. Reconstructs the process tree, computes SHA-256 hashes with OpenSSL EVP, fills in the manifest, builds the tar+zstd archive with libarchive (manifest.json goes in first per spec), fsyncs, atomic-renames.
- **`reader.h / reader.cpp`** — the `Reader` class. Opens a `.vishaya` file, parses `manifest.json` immediately (enforcing version compat), lazy-loads `process_tree.json`, streams `events.ndjson` through a callback for `for_each_event()`, and can recompute integrity hashes via `verify_integrity()`. Uses an internal RAII `ArchiveReadHandle` so libarchive handles never leak.
- **`bundle_probe.cpp`** — standalone smoke test that writes a synthetic 3-event bundle from a hand-authored NDJSON string. No eBPF, no isolation.

## Capture pipeline (`src/capture/`)

Where BPF meets bundle.

- **`wal_writer.h / wal_writer.cpp`** — the `WalWriter` class. Opens a file (`events.ndjson` in the scratch dir), exposes `write_line(sv)` which appends `<line>\n` with EINTR + partial-write retry logic. Two separate `write()` syscalls: one for the line, one for the newline. Non-thread-safe; the collector's ring-buffer callback is single-threaded.
- **`event_to_json.h / event_to_json.cpp`** — `event_to_json(EventVariant)` returns a single-line JSON string matching [BUNDLE-SPEC §4](bundle-spec-v0.1.md). Handles all four event families and their subtypes, including all 23 socket-level network kinds and IPv4/IPv6 endpoint rendering via `inet_ntop`.
- **`protocol_decoder.h / protocol_decoder.cpp`** — Step 9. `synthesize_protocol_events(event)` returns extra JSON events derived from the captured payload. Contains:
  - Full DNS wire-format parser with compression pointer support (`dns_parse_name`), question section parsing, answer section parsing with rdata formatting for A/AAAA/CNAME/NS/PTR, and DNS type name resolution.
  - HTTP plaintext detector: `looks_like_http_response` matches `HTTP/1.` prefix, `leading_http_method` matches 9 method names; parses method, path, version, Host header (case-insensitive) for requests; version, status code (validated 100–599), reason phrase for responses.
- **`session.h / session.cpp`** — the `Session` class. Ties everything together:
  1. Constructor: opens `WalWriter`, grabs the collector singleton via `CreateCollector()`, calls `Start(callback)` to load BPF, sets `started_ = true`, then calls `SetTargetCgroup(cgroup_id)` to activate Step-6 filtering.
  2. Callback (`on_raw_event`): decodes bytes, enriches process events, serializes to JSON, writes to WAL. Then calls `synthesize_protocol_events` and appends any synth events to the WAL.
  3. `poll(timeout_ms)` — delegates to `collector_->PollOnce`.
  4. `stop()` — detaches, closes WAL. Idempotent. Destructor calls `stop()`.

## Inspect subcommands (`src/inspect/`)

Each subcommand is one small file with a `run_X(bundle_path)` free function that opens a `Reader`, calls `for_each_event` (streaming) or reads `process_tree()` (lazy), and prints a tabular or tree view:

- **`tree.cpp`** — reconstructs the parent-child graph, prints with `├──` / `└──` box drawing, handles orphans reachable-check.
- **`files.cpp`** — table of file events. Rename events show `oldpath -> newpath`.
- **`network.cpp`** — table with per-kind formatting: DNS shows `A example.com -> 1.2.3.4`, HTTP shows `GET example.com/path`, socket events show byte counts.
- **`timeline.cpp`** — chronological one-line-per-event view with `family:kind` and a compact detail summary.

## CLI (`src/cli/`)

- **`dispatcher.h / dispatcher.cpp`** — CLI11-based subcommand router. Pre-scans argv for `-v` before parsing (so verbose applies during callbacks). Five subcommands: `capture` (real), `tree`, `files`, `network`, `timeline`. Each subcommand's callback stores its result in a local `result` variable; final `return result` propagates to process exit code.
- **`capture_cmd.h / capture_cmd.cpp`** — the `vishaya capture` subcommand. Requires root. Sets up signal handlers, creates `TmpDir` + `Cgroup`, constructs `Session` (which loads BPF and sets the cgroup filter atomically), calls `launch_target`, spins the waitpid+poll loop, drains events after target exit, builds the manifest (host info via `uname`, target SHA-256, isolation info, coverage), writes the bundle. All resources are RAII-cleaned on any exit path.
- **`main.cpp`** — 4 lines: `return vishaya::cli::dispatch(argc, argv);`.

## The runtime flow, end to end

**Capture path:**
```
user runs `sudo vishaya capture --target X -o Y.vishaya`
  → cli/main → cli/dispatch → capture_cmd::run_capture
    → TmpDir + Cgroup constructed
    → Session ctor
        → WalWriter opens scratch/events.ndjson
        → collector->Start(...) — BPF loaded and attached
        → collector->SetTargetCgroup(cgroup.id) — Step 6 filter active
    → launch_target(opts, ns, cgroup)
        → fork + sync pipe + cgroup attach + child unshare/mount/exec
    → loop: waitpid(WNOHANG) + session.poll(100)
        → each event: BPF ringbuf → collector callback → Session::on_raw_event
            → decode → enrich → event_to_json → WalWriter
            → synthesize_protocol_events → additional lines to WAL
    → target exits: two drain polls, session.stop() (detaches BPF, closes WAL)
    → bundle::write_bundle(input)
        → reconstruct_tree from events.ndjson
        → SHA-256 hashes of events.ndjson and process_tree.json
        → manifest_to_json → write manifest.json
        → libarchive: build tar.zst → fsync → atomic rename
    → TmpDir + Cgroup destructors clean up
```

**Inspect path:**
```
user runs `vishaya tree case.vishaya`
  → cli/main → cli/dispatch → inspect::run_tree
    → bundle::Reader ctor: opens archive, parses manifest
    → reader.process_tree() (lazy load)
    → walk tree, print ASCII
```

That's the whole product. If you understood this, you understand Vishaya.

## Where next

- [build.md](build.md) — CMake structure and dependency graph
- [event-reference.md](event-reference.md) — every event's JSON schema in detail
- [bundle-spec-v0.1.md](bundle-spec-v0.1.md) — the format spec, authoritative
