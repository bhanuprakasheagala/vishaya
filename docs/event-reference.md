# Event Reference

Every event Vishaya emits, its JSON shape, and where it comes from. This is the reference for tools building on top of `.vishaya` bundles.

For the wire-level format (tar layout, integrity rules, versioning), see [bundle-spec-v0.1.md](bundle-spec-v0.1.md). This document is the semantic reference layered on top of that.

## Common envelope

Every event, regardless of family, is a single JSON object per line in `events.ndjson`. The top-level envelope is identical across all events:

| Field | Type | Meaning |
|---|---|---|
| `ts_ns` | integer | `CLOCK_MONOTONIC` nanoseconds (`bpf_ktime_get_ns`) when the event fired. Map to wall-clock via the manifest anchor: `wall = capture.clock_realtime_ns + (ts_ns - capture.clock_monotonic_ns)`. |
| `family` | string | `process`, `file`, `network`, or `syscall` |
| `kind` | string | Family-specific subtype (see below) |
| `pid` | integer | Kernel PID (thread ID in Linux terminology) |
| `tgid` | integer | Kernel TGID — this is what userspace usually calls a "process ID" |
| `ppid` | integer | Parent TGID |
| `uid` | integer | Effective UID |
| `gid` | integer | Effective GID |
| `comm` | string | Task command name, up to 16 chars (Linux's `TASK_COMM_LEN`) |
| `container.cgroup_path` | string | Cgroup v2 path of the emitting process; empty string if unavailable |
| `container.mount_ns_ino` | integer | Mount namespace inode number; `0` if unavailable |
| `data` | object | Family+kind specific payload — every family has a different shape |

Events are written to `events.ndjson` in approximately chronological order — the kernel
ring buffer is drained in delivery order, which can reorder slightly across CPUs. A
synthetic protocol event (e.g. `dns-query`) immediately follows its source event. Readers
that need strict chronological order (e.g. the `timeline` view) MUST sort by `ts_ns`.

## family: `process`

Process lifecycle events from the `sched_process_*` tracepoints plus clone/vfork exit tracepoints.

**Kinds:** `exec`, `fork`, `exit`, `clone`, `clone3`, `vfork`.

**`data` fields (all optional; unset fields may be `0` or empty string):**

| Field | Type | Meaning |
|---|---|---|
| `exit_code` | integer | Process exit code (populated on `exit` events) |
| `child_pid` | integer | TGID of spawned child (populated on `fork`/`clone`/`clone3`/`vfork`) |
| `filename` | string | Executed path captured in-kernel from the exec tracepoint (kernel-resolved `bprm->filename`) |
| `exec_path` | string | Canonical absolute path from `/proc/<pid>/exe` while the process is alive; falls back to `filename` if it exited before enrichment |
| `cmdline` | string | Full command line, space-joined, up to `VISHAYA_PATH_LEN` |
| `cwd` | string | Current working directory at exec time |
| `parent_comm` | string | Parent process's `comm` |
| `start_time_ticks` | integer | Process start time in boot-based clock ticks, captured in-kernel (equivalent to `/proc/<pid>/stat` field 22) |

**Provenance (exec events).** `filename`, `cmdline`, `parent_comm`, and
`start_time_ticks` are captured in-kernel at exec time from the `sched_process_exec`
tracepoint and the current task (`mm` argv block, `real_parent->comm`,
`task->start_boottime`), so they are reliable even for processes that exit before
userspace enrichment runs. `exec_path` and `cwd` are best-effort from `/proc/<pid>/…`
and may be empty for very short-lived processes (except `exec_path`, which falls back
to `filename`). `cmdline` is truncated to `VISHAYA_PATH_LEN` bytes.

**PID-reuse guard.** Because `start_time_ticks` is captured in-kernel at event time,
userspace enrichment uses it as a race-free reference: before trusting any
`/proc/<pid>/…` field it re-reads the process's current start time and, if it disagrees
(the PID was recycled between capture and enrichment), skips the `/proc` reads rather
than attributing another process's `exec_path`/`cwd`/`cmdline` to this event. On kernels
without `task->start_boottime` the field is 0 and enrichment falls back to best-effort
`/proc` reads with no such guard.

Example:
```json
{
  "ts_ns": 1721390096100000000, "family": "process", "kind": "exec",
  "pid": 12345, "tgid": 12345, "ppid": 1, "uid": 1000, "gid": 1000, "comm": "curl",
  "data": {
    "filename": "/usr/bin/curl", "exec_path": "/usr/bin/curl",
    "cmdline": "curl https://example.com",
    "cwd": "/home/user", "parent_comm": "vishaya",
    "exit_code": 0, "child_pid": 0, "start_time_ticks": 12345678
  }
}
```

## family: `file`

File system operations from `openat`, `unlinkat`, `renameat2` syscalls, captured as enter/exit pairs so we get the return value alongside the arguments.

**Kinds:** `openat`, `unlinkat`, `renameat2`.

> These events also drive **artifact capture** (`vishaya capture --capture-artifacts`): a successful `openat` with write intent (`O_CREAT`/`O_WRONLY`/`O_RDWR`) or a `renameat2` destination, at an **absolute** path, marks that file for copying into the bundle's `artifacts/`. See [bundle-spec §5A](bundle-spec-v0.1.md).

| Field | Type | Meaning |
|---|---|---|
| `dfd` | integer | Directory file descriptor argument (`AT_FDCWD` = -100 usually) |
| `flags` | integer | Open flags / rename flags (syscall-specific) |
| `mode` | integer | Reused for syscall-specific context (e.g., `renameat2` newdfd) |
| `ret` | integer | Syscall return value: `fd` on success, `-errno` on failure |
| `path_a` | string | Primary path (openat target, unlinkat target, renameat2 oldpath) |
| `path_b` | string | Secondary path (renameat2 newpath); empty for other kinds |

Example:
```json
{
  "ts_ns": 1721390096200000000, "family": "file", "kind": "openat",
  "pid": 12345, "tgid": 12345, "ppid": 1, "uid": 1000, "gid": 1000, "comm": "curl",
  "data": {
    "dfd": -100, "flags": 524288, "mode": 0, "ret": 5,
    "path_a": "/etc/resolv.conf", "path_b": ""
  }
}
```

## family: `network`

Socket-level operations plus the synthesized DNS and HTTP events produced by the userspace protocol decoder.

### Socket-level kinds (23 total)

Emitted directly by BPF probes. Includes: `socket`, `socketpair`, `connect`, `accept`, `accept4`, `bind`, `listen`, `close`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `read`, `write`, `readv`, `writev`, `sendmmsg`, `recvmmsg`, `shutdown`, `getsockname`, `getpeername`, `setsockopt`, `getsockopt`.

`data` fields common to socket-level kinds:

| Field | Type | Meaning |
|---|---|---|
| `fd` | integer | Socket file descriptor |
| `peer_fd` | integer | Peer fd for socketpair; new fd for accept |
| `ret` | integer | Syscall return value |
| `domain` | integer | `AF_*` value (`AF_INET`=2, `AF_INET6`=10, `AF_UNIX`=1) |
| `sock_type` | integer | `SOCK_*` value (`SOCK_STREAM`=1, `SOCK_DGRAM`=2) |
| `protocol` | integer | Protocol number |
| `flags` | integer | syscall-specific flags |
| `backlog` | integer | listen backlog |
| `how` | integer | shutdown how value |
| `socket_id` | integer | Vishaya-internal socket identity token |
| `flow_id` | integer | Vishaya-internal flow identity token |
| `direction` | string | `inbound`, `outbound`, or `unknown` |
| `transport` | string | `tcp`, `udp`, `unix`, `raw`, or `unknown` |
| `bytes_requested` | integer | Bytes the syscall was asked to transfer |
| `bytes_transferred` | integer | Bytes actually transferred (syscall return value on success) |
| `bytes_captured` | integer | Bytes of payload captured in the event (0–128) |
| `bytes_truncated` | integer | Bytes of payload that would have been captured but exceeded the 128-byte limit |
| `local` | object | Local endpoint |
| `remote` | object | Remote endpoint |

**Endpoint object shape:**
```json
{ "family": "inet"|"inet6"|"unix"|"unspec"|"other",
  "port": 443,
  "addr": "1.2.3.4",         // IPv4 dotted-quad or IPv6 colon-hex; empty for non-IP families
  "path": "/tmp/sock" }      // AF_UNIX path; empty for IP families
```

### `kind: dns-query` and `kind: dns-answer`

Synthesized by the userspace protocol decoder from UDP:53 payloads captured on `sendto` / `recvfrom` events. See [protocol_decoder.cpp](../src/capture/protocol_decoder.cpp) for the parser.

`data` fields:

```json
{
  "transport": "udp",
  "remote": { "family": "inet", "addr": "1.1.1.1", "port": 53 },
  "dns": {
    "id": 12345,
    "qname": "api.example.com",
    "qtype": "A",             // or AAAA/CNAME/MX/NS/PTR/SRV/SOA/TXT/OPT/HTTPS/ANY, or "TYPE<n>"
    "qclass": "IN",           // or "OTHER"
    "answers": [              // present on dns-answer only (may be empty on NXDOMAIN)
      { "name": "api.example.com", "type": "A", "class": "IN",
        "ttl": 300, "rdata": "93.184.216.34" }
    ]
  }
}
```

Coverage caveats:
- Only queries via `sendto`/`recvfrom` are decoded. DNS over TCP:53 (rare) and DNS-over-HTTPS aren't decoded — those need Step 9's TCP path (partial) or HTTPS uprobes (deferred).
- Only the first question in the packet is parsed (real-world DNS queries have one question).
- Compression pointers are followed with a depth guard.
- Payloads > 128 bytes are truncated; long DNS responses may lose trailing answers.

### `kind: http-request` and `kind: http-response`

Synthesized by the userspace protocol decoder from TCP send/recv payloads that start with HTTP method/version markers.

**Request:**
```json
{
  "transport": "tcp",
  "remote": { "family": "inet", "addr": "1.2.3.4", "port": 80 },
  "http": {
    "method": "GET",
    "path": "/api/v1/users",
    "version": "HTTP/1.1",
    "host": "api.example.com"     // absent if Host header not in captured payload
  }
}
```

**Response:**
```json
{
  "transport": "tcp",
  "remote": { "family": "inet", "addr": "1.2.3.4", "port": 80 },
  "http": {
    "version": "HTTP/1.1",
    "status_code": 200,
    "status_reason": "OK"
  }
}
```

Coverage caveats:
- Recognized methods: GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS, CONNECT, TRACE.
- HTTPS traffic is not decoded (payload is encrypted). HTTPS connections still appear as socket-level events (with endpoint and byte counts).
- Payload capture (up to 128 bytes) fires on all send/recv paths: `sendto`, `recvfrom`, `read`, `write`, `readv`, `writev`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`.

## family: `syscall`

Raw syscall enter/exit tracing. Off by default. Enable with `--enable-syscalls` on `vishaya capture`. Present in bundle only if `manifest.coverage.syscalls_captured` is true.

**Kinds:** `sys_enter`, `sys_exit`.

| Field | Type | Meaning |
|---|---|---|
| `syscall_nr` | integer | Kernel syscall number (architecture-specific!) |
| `syscall_name` | string | Empty in v0.1 (name resolution is a future v0.5 enrichment) |
| `args` | array of 3 integers | First 3 syscall arguments |
| `ret` | integer or null | Syscall return value on `sys_exit`; `null` on `sys_enter` |

Warnings:
- **Syscall numbers are architecture-specific.** A syscall number that means `read` on x86_64 means something completely different on aarch64. If you're analyzing syscall events, cross-reference with `capture.host.arch` in the manifest.
- **High volume.** A busy target can emit millions of syscall events per second. Ring buffer overflow is a real concern; watch `manifest.counts.events_dropped`.
- **Only 3 args captured.** BPF verifier constraints mean we can't safely grab all 6 syscall args. Fields beyond arg2 are unavailable.

## Event ordering guarantees

- **Chronological within family.** Events of the same family are strictly ordered by `ts_ns`.
- **Chronological across families.** Same guarantee across the whole `events.ndjson` file.
- **Synthesized events** (dns-query/answer, http-request/response) share `ts_ns` with their source socket event and appear immediately after it in the file. Order between the source and synth event is deterministic (source first).

## What isn't captured (yet)

Known limitations to document to your users if you build tooling on top of Vishaya:

- No HTTPS plaintext (needs uprobe into TLS libraries; deferred to v0.5).
- No file content — only the metadata about file operations (path, flags, ret). Artifact-file bundling is planned for v0.5.
- No memory forensics — Volatility exists for that.
- No syscall argument beyond arg2.
- No thread IDs distinct from process IDs beyond the `pid` field.

## How to know when to trust a field

If you're writing a tool that reads `.vishaya` bundles:

- **Always check `manifest.coverage.families`** — if `network` isn't listed, don't expect network events.
- **Always check `manifest.coverage.network_layers`** — if it doesn't include `dns`, don't expect `dns-query`/`dns-answer`.
- **`manifest.counts.events_dropped > 0`** means the ring buffer overflowed; some events were lost. Adjust confidence accordingly.
- **`manifest.integrity.events_sha256`** should match the recomputed SHA-256 of `events.ndjson` bytes as they appear in the tar. Mismatch means tampering or corruption; treat the bundle as suspect.
