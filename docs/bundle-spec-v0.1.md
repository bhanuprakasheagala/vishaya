# `.vishaya` Bundle Format — Specification v0.1

This is the authoritative reference for the `.vishaya` bundle format at version `0.1.0`. It defines exactly what a compliant writer produces and what a compliant reader consumes.

**Stability:** v0.x is explicitly pre-release. Field additions may occur; field removals or type changes will not. v1.0.0 is the first frozen major.

**Reference implementation:** the Vishaya CLI in this repository. Third-party writers/readers may implement this spec independently.

---

## 1. Container

A `.vishaya` bundle is a single file:

- **Outer format:** `tar` archive, compressed with `zstd`
- **File suffix:** `.vishaya` (mandatory), or `.vishaya.tmp` during atomic write
- **Compression level:** `zstd` level 3 (default; balances speed and size)
- **Tar variant:** POSIX ustar (no vendor extensions, no long-name workarounds beyond ustar spec)
- **MIME type (proposed):** `application/vnd.vishaya+tar+zstd`

Rationale for tar+zstd: universally available on Linux, streamable in both directions, no schema needed at container level, human-inspectable with standard tools (`zstd -d < case.vishaya | tar -tv`).

---

## 2. Tar layout

Every bundle contains these entries, at these exact paths:

```
manifest.json           # required — always first entry in tar
events.ndjson           # required
process_tree.json       # required
artifacts/              # required directory (may be empty in v0.1)
```

**Ordering rule:** `manifest.json` MUST be the first entry in the tar stream. This allows streaming readers to validate schema version before decompressing the rest.

**No extra entries** are permitted at the tar root in v0.1. Future spec versions may add entries; readers MUST skip unknown entries and MUST NOT error on them.

**Directory permissions:** `artifacts/` is `0755`. Files are `0644`. Owner/group are irrelevant (readers MUST NOT check).

---

## 3. `manifest.json`

Single top-level JSON object. UTF-8 encoded, no BOM. Pretty-printed (2-space indent) for human inspection; whitespace is not semantic.

### 3.1 Schema

```json
{
  "schema_version": "0.1.0",
  "tool": {
    "name":    "vishaya",
    "version": "0.1.0"
  },
  "capture": {
    "started_at":         "2026-07-19T12:34:56.789Z",
    "ended_at":           "2026-07-19T12:35:41.123Z",
    "duration_seconds":   45,
    "clock_realtime_ns":  1721390096789000000,
    "clock_monotonic_ns": 45678901234,
    "host": {
      "kernel":     "6.8.0-40-generic",
      "arch":       "x86_64",
      "distro":     "Ubuntu 24.04.1 LTS",
      "hostname":   "capture-host-42"
    }
  },
  "target": {
    "path":     "/absolute/path/to/sample.elf",
    "sha256":   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "size":     45312,
    "args":     ["--flag", "value"],
    "env_count": 42
  },
  "isolation": {
    "namespaces":  ["mnt"],
    "cgroup_path": "/sys/fs/cgroup/vishaya-8f3a2c14-4b19-4d5e-9b7c-1e2f3a4b5c6d",
    "cgroup_id":   1234567
  },
  "coverage": {
    "families":         ["process", "file", "network"],
    "syscalls_captured": false,
    "network_layers":    ["socket", "dns", "http"]
  },
  "counts": {
    "events_total":    12456,
    "events_dropped":  0,
    "processes_seen":  7,
    "artifacts_count": 0
  },
  "integrity": {
    "events_sha256":       "a1b2c3d4...",
    "process_tree_sha256": "e5f6a7b8..."
  },
  "sig": {
    "algorithm":  "Ed25519",
    "pubkey_b64": "MCowBQYDK2VdAyEA...",
    "sig_b64":    "abc123..."
  }
}
```

### 3.2 Field reference

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schema_version` | string (semver) | yes | Bundle format version. `0.1.0` for this spec. |
| `tool.name` | string | yes | Producer identity. `vishaya` for the reference implementation; MAY be another value for third-party producers. |
| `tool.version` | string (semver) | yes | Producer version. |
| `capture.started_at` | string (RFC 3339, UTC) | yes | Capture start timestamp. |
| `capture.ended_at` | string (RFC 3339, UTC) | yes | Capture end timestamp. |
| `capture.duration_seconds` | integer | yes | Convenience field; MUST equal `ended_at - started_at`. |
| `capture.clock_realtime_ns` | integer | recommended | `CLOCK_REALTIME` (ns since Unix epoch) sampled at capture start. `0` if unavailable. |
| `capture.clock_monotonic_ns` | integer | recommended | `CLOCK_MONOTONIC` (ns) sampled at the same instant as `clock_realtime_ns`. Event `ts_ns` share this monotonic base, so `wall(event) = clock_realtime_ns + (event.ts_ns - clock_monotonic_ns)`. Both fields `0` means no anchor; readers fall back to relative timestamps. |
| `capture.host.kernel` | string | yes | `uname -r` output at capture time. |
| `capture.host.arch` | string | yes | `uname -m` output at capture time. |
| `capture.host.distro` | string | recommended | Best-effort distro identity (`/etc/os-release` `PRETTY_NAME`). Empty string if unavailable. |
| `capture.host.hostname` | string | yes | `gethostname()` at capture time. |
| `target.path` | string | yes | Absolute path of the target binary as given at capture. |
| `target.sha256` | string (hex, 64 chars) | yes | SHA-256 of the target binary at capture start. |
| `target.size` | integer | yes | Size of target binary in bytes. |
| `target.args` | array of strings | yes | Argv passed to the target (excluding argv[0]). |
| `target.env_count` | integer | yes | Number of environment variables passed to target. Values not recorded (privacy). |
| `isolation.namespaces` | array of strings | yes | Subset of `["pid", "net", "mnt", "user"]`. |
| `isolation.cgroup_path` | string | yes | Absolute path of the target's cgroup at capture time. |
| `isolation.cgroup_id` | integer | yes | Kernel cgroup ID used for probe filtering. |
| `coverage.families` | array of strings | yes | Subset of `["process", "file", "network", "syscall"]`. |
| `coverage.syscalls_captured` | boolean | yes | Redundant with `families` for readability. |
| `coverage.network_layers` | array of strings | yes if `network` in families | Subset of `["socket", "dns", "http", "https"]`. |
| `counts.events_total` | integer | yes | Total events in `events.ndjson`. |
| `counts.events_dropped` | integer | yes | Events dropped due to ring buffer overflow. `0` for clean captures. |
| `counts.processes_seen` | integer | yes | Number of distinct processes in `process_tree.json`. |
| `counts.artifacts_count` | integer | yes | Number of files in `artifacts/`. `0` in v0.1. |
| `integrity.events_sha256` | string (hex, 64) | yes | SHA-256 of `events.ndjson` as stored in the tar. |
| `integrity.process_tree_sha256` | string (hex, 64) | yes | SHA-256 of `process_tree.json` as stored in the tar. |
| `sig` | object | no | Ed25519 signature block. Absent when signing is unavailable. Readers MUST NOT require this field and MUST verify it when present. |
| `sig.algorithm` | string | yes (if `sig` present) | Signature algorithm. `Ed25519` in v0.1. |
| `sig.pubkey_b64` | string (base64) | yes (if `sig` present) | Ed25519 raw public key, base64-encoded (44 chars, 32 bytes decoded). |
| `sig.sig_b64` | string (base64) | yes (if `sig` present) | Ed25519 signature over `<events_sha256>\n<process_tree_sha256>\n`, base64-encoded (88 chars, 64 bytes decoded). |

Unknown top-level or nested fields MUST be ignored by readers.

---

## 4. `events.ndjson`

Newline-delimited JSON. UTF-8, LF line endings only (no CRLF). One event per line. No blank lines. Order is chronological by `ts_ns` (ascending).

### 4.1 Common envelope

Every event line is a JSON object with these top-level fields:

```json
{
  "ts_ns":     1721390096123456789,
  "family":    "process",
  "kind":      "exec",
  "pid":       12345,
  "tgid":      12345,
  "ppid":      1,
  "uid":       1000,
  "gid":       1000,
  "comm":      "sample.elf",
  "container": { "cgroup_path": "/sys/fs/cgroup/vishaya-8f3a2c14/sample.elf", "mount_ns_ino": 4026531840 },
  "data":      { … family-specific … }
}
```

| Field | Type | Meaning |
|---|---|---|
| `ts_ns` | integer | Kernel monotonic nanoseconds at event time |
| `family` | string | `process` \| `file` \| `network` \| `syscall` |
| `kind` | string | Family-specific subtype (see below) |
| `pid` | integer | Kernel PID (thread ID) |
| `tgid` | integer | Kernel TGID (process ID) |
| `ppid` | integer | Parent TGID |
| `uid` | integer | Effective UID |
| `gid` | integer | Effective GID |
| `comm` | string | `TASK_COMM_LEN`-truncated task name (up to 16 chars) |
| `container.cgroup_path` | string | Cgroup v2 path of the emitting process; empty string if unavailable |
| `container.mount_ns_ino` | integer | Mount namespace inode number; `0` if unavailable |
| `data` | object | Family+kind specific payload (see below) |

Unknown families or kinds MUST be preserved by tools that copy or filter events, and SHOULD be tolerated (skipped with a debug log) by tools that render events.

### 4.2 `family: "process"`

**Kinds:** `exec`, `fork`, `exit`, `clone`, `clone3`, `vfork`.

```json
"data": {
  "exit_code":        0,
  "child_pid":        12346,
  "filename":         "/path/to/binary",
  "exec_path":        "/absolute/resolved/path",
  "cmdline":          "sample.elf --flag value",
  "cwd":              "/working/dir",
  "parent_comm":      "sh",
  "start_time_ticks": 123456789
}
```

Fields are best-effort; any field MAY be empty string or `0` when the source event doesn't populate it. Readers MUST tolerate missing fields.

### 4.3 `family: "file"`

**Kinds (v0.1):** `openat`, `unlinkat`, `renameat2`.

```json
"data": {
  "dfd":    -100,
  "flags":  0,
  "mode":   0,
  "ret":    3,
  "path_a": "/etc/passwd",
  "path_b": ""
}
```

`path_a` is the primary path (e.g., openat target, unlinkat target, renameat2 oldpath). `path_b` is the secondary path (e.g., renameat2 newpath); empty for kinds that don't have one. `ret` is the syscall return (fd, error, or 0).

### 4.4 `family: "network"`

**Kinds (v0.1):** `socket`, `socketpair`, `connect`, `accept`, `accept4`, `bind`, `listen`, `close`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `read`, `write`, `readv`, `writev`, `sendmmsg`, `recvmmsg`, `shutdown`, `getsockname`, `getpeername`, `setsockopt`, `getsockopt`, `dns-query`, `dns-answer`, `http-request`, `http-response`.

#### 4.4.1 Socket-level kinds (all except dns-*, http-*)

```json
"data": {
  "fd":                3,
  "peer_fd":           -1,
  "ret":               0,
  "domain":            2,
  "sock_type":         1,
  "protocol":          6,
  "flags":             0,
  "backlog":           0,
  "how":               0,
  "socket_id":         1234,
  "flow_id":           5678,
  "direction":         "outbound",
  "transport":         "tcp",
  "bytes_requested":   4096,
  "bytes_transferred": 4096,
  "bytes_captured":    0,
  "bytes_truncated":   0,
  "local":  { "family": "inet",  "addr": "0.0.0.0",  "port": 0,   "path": "" },
  "remote": { "family": "inet",  "addr": "1.2.3.4",  "port": 443, "path": "" }
}
```

`endpoint.family` is one of `unspec` | `inet` | `inet6` | `unix` | `other`. `path` is used for AF_UNIX only. `transport` is one of `unknown` | `tcp` | `udp` | `unix` | `raw`. `direction` is one of `unknown` | `inbound` | `outbound`.

Fields that don't apply to a given `kind` MAY be `0`, `""`, or omitted. Readers MUST tolerate this.

#### 4.4.2 `kind: "dns-query"` and `kind: "dns-answer"`

Emitted by the userspace decoder after parsing UDP:53 payload captured by socket-level probes.

```json
"data": {
  "transport": "udp",
  "remote":    { "family": "inet", "addr": "1.1.1.1", "port": 53 },
  "dns": {
    "id":        12345,
    "qname":     "api.example.com",
    "qtype":     "A",
    "qclass":    "IN",
    "answers": [
      { "name": "api.example.com", "type": "A",  "ttl": 300, "rdata": "1.2.3.4" },
      { "name": "api.example.com", "type": "A",  "ttl": 300, "rdata": "1.2.3.5" }
    ]
  }
}
```

For `dns-query`, `dns.answers` is omitted or empty. For `dns-answer`, `dns.answers` is populated (may be empty on NXDOMAIN etc.). Standard DNS type names (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `PTR`, `SRV`, `NS`, `SOA`); unknown types use `"TYPE<n>"` form.

#### 4.4.3 `kind: "http-request"` and `kind: "http-response"`

Emitted by the userspace decoder after detecting HTTP method line + Host header (request) or status line (response) in the first N bytes of TCP send/recv payloads.

```json
"data": {
  "transport": "tcp",
  "remote":    { "family": "inet", "addr": "1.2.3.4", "port": 80 },
  "http": {
    "method":  "GET",
    "path":    "/api/v1/users",
    "version": "HTTP/1.1",
    "host":    "api.example.com"
  }
}
```

For `http-response`:

```json
"http": {
  "version":       "HTTP/1.1",
  "status_code":   200,
  "status_reason": "OK"
}
```

Only plaintext HTTP is captured in v0.1. HTTPS connections are recorded at the socket level (with endpoint and byte counts) but not decoded.

### 4.5 `family: "syscall"` (opt-in)

Present only if `coverage.syscalls_captured` is `true`.

**Kinds:** `sys_enter`, `sys_exit`.

```json
"data": {
  "syscall_nr":   62,
  "syscall_name": "kill",
  "args":         [1234, 15, 0],
  "ret":          null
}
```

`args` is an array of up to 3 integers (current probe limit). `ret` is present for `sys_exit` only; `null` for `sys_enter`. `syscall_name` MAY be empty string if the producer couldn't resolve the number.

---

## 5. `process_tree.json`

Single top-level JSON object.

```json
{
  "root_pid":  12345,
  "processes": [
    {
      "pid":           12345,
      "tgid":          12345,
      "ppid":          1,
      "comm":          "sample.elf",
      "exec_path":     "/path/to/sample.elf",
      "cmdline":       "sample.elf --flag value",
      "cwd":           "/working/dir",
      "uid":           1000,
      "gid":           1000,
      "start_ts_ns":   1721390096123456789,
      "end_ts_ns":     1721390141987654321,
      "exit_code":     0,
      "children":      [12346, 12347]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `root_pid` | TGID of the target (the process launched by `vishaya capture`) |
| `processes` | Array of all processes seen during the capture (target + descendants) |
| `processes[].start_ts_ns` | `ts_ns` of the `exec`/`fork`/`clone` event that created this process |
| `processes[].end_ts_ns` | `ts_ns` of the `exit` event, or `null` if still running when capture ended |
| `processes[].exit_code` | Exit code, or `null` if not exited |
| `processes[].children` | TGIDs of direct child processes (also in `processes`) |

The tree represents *processes* (thread-group leaders), not threads: a `children` entry is
always a distinct process TGID that appears in `processes`. Threads created via
`CLONE_THREAD` share their leader's TGID and are not separate nodes.

Reconstruction is deterministic from `events.ndjson`; the tree is materialized for convenience, not as new information.

---

## 6. Integrity

- `integrity.events_sha256` is the SHA-256 of the raw bytes of `events.ndjson` as stored in the tar (uncompressed, exactly as unpacked).
- `integrity.process_tree_sha256` is the SHA-256 of the raw bytes of `process_tree.json` as stored in the tar.
- Compliant readers SHOULD verify both hashes at load time. Failure MUST produce a clear warning and MAY be treated as fatal depending on tool configuration.
- When `sig` is present, the signed payload is the ASCII string `<events_sha256>\n<process_tree_sha256>\n` (two hex digests, each followed by a newline). The signing key is auto-generated on first run at `~/.config/vishaya/keys/signing.key` (Ed25519, PEM format, `0600` permissions). A bundle without `sig` is unsigned but otherwise valid; readers SHOULD warn the user.

---

## 7. Compatibility rules

- Bundle major version `>` reader major version → reader MUST refuse with a clear error.
- Bundle major version `≤` reader major version → reader MUST accept and MUST ignore fields, kinds, families, and tar entries it does not recognize.
- Field removals and type changes across minor versions of the same major are forbidden.
- Field additions across minor versions are permitted.
- The `unknown fields are ignored` rule applies uniformly to `manifest.json`, event `data` objects, and process records.

---

## 8. Producer requirements

A compliant writer:

1. MUST write `manifest.json` as the first tar entry.
2. MUST write all four required entries listed in §2.
3. MUST populate every field marked `required` in §3.2.
4. SHOULD emit events in ascending `ts_ns` order in `events.ndjson`. The v0.1 reference writer emits in kernel ring-buffer delivery order, which is approximately but not strictly sorted across CPUs; consumers needing strict order MUST sort (see §9.6). A future version may canonicalize the on-disk order.
5. MUST compute and populate `integrity.events_sha256` and `integrity.process_tree_sha256` correctly.
6. MUST write to `<path>.tmp`, fsync, and atomically rename to `<path>` on completion.
7. MUST NOT include personally-identifying data beyond what is explicitly permitted (uid/gid yes; env values no).
8. MAY populate optional and recommended fields.
9. MAY use a `tool.name` other than `vishaya`, but the format itself remains `.vishaya`.

---

## 9. Consumer requirements

A compliant reader:

1. MUST validate `manifest.schema_version` before parsing any other content.
2. MUST reject bundles with a newer major version than the reader supports.
3. MUST tolerate and ignore unknown fields, event kinds, families, and tar entries within a supported major.
4. SHOULD verify integrity hashes at load time.
5. SHOULD present hash verification failures visibly.
6. MUST sort events by `ts_ns` if it requires strict chronological order (the on-disk order is only approximately sorted — see §8.4). To map `ts_ns` to wall-clock, use the `capture.clock_realtime_ns` / `capture.clock_monotonic_ns` anchor.

---

## 10. Non-normative example (tiny worked example)

A minimal 3-event bundle captured from `curl https://example.com`:

`manifest.json` — as in §3.1.

`events.ndjson`:
```
{"ts_ns":1721390096100000000,"family":"process","kind":"exec","pid":12345,"tgid":12345,"ppid":1,"uid":1000,"gid":1000,"comm":"curl","data":{"exec_path":"/usr/bin/curl","cmdline":"curl https://example.com","cwd":"/home/user","filename":"/usr/bin/curl","exit_code":0,"child_pid":0,"parent_comm":"vishaya","start_time_ticks":0}}
{"ts_ns":1721390096200000000,"family":"network","kind":"connect","pid":12345,"tgid":12345,"ppid":1,"uid":1000,"gid":1000,"comm":"curl","data":{"fd":3,"ret":0,"transport":"tcp","direction":"outbound","local":{"family":"inet","addr":"0.0.0.0","port":0,"path":""},"remote":{"family":"inet","addr":"93.184.216.34","port":443,"path":""},"socket_id":1,"flow_id":1,"bytes_requested":0,"bytes_transferred":0}}
{"ts_ns":1721390096500000000,"family":"process","kind":"exit","pid":12345,"tgid":12345,"ppid":1,"uid":1000,"gid":1000,"comm":"curl","data":{"exit_code":0,"child_pid":0,"filename":"","exec_path":"","cmdline":"","cwd":"","parent_comm":"","start_time_ticks":0}}
```

`process_tree.json`:
```json
{
  "root_pid": 12345,
  "processes": [
    {
      "pid": 12345, "tgid": 12345, "ppid": 1,
      "comm": "curl", "exec_path": "/usr/bin/curl",
      "cmdline": "curl https://example.com", "cwd": "/home/user",
      "uid": 1000, "gid": 1000,
      "start_ts_ns": 1721390096100000000,
      "end_ts_ns":   1721390096500000000,
      "exit_code":   0,
      "children":    []
    }
  ]
}
```

---

## 11. Appendix — rationale (non-normative)

- **Why tar+zstd?** Universally available on Linux, streamable, no schema needed at container level, human-inspectable with standard tools. Zstd offers ~2x better compression than gzip at comparable speed and is now default in the Linux kernel.
- **Why NDJSON, not a binary event format?** Human-readable, greppable, easy to reason about, trivially validated. Binary format (Cap'n Proto / FlatBuffers) is deferred to a later spec version if event volume becomes a bottleneck.
- **Why `manifest.json` first?** Streaming readers can validate schema version before decompressing gigabytes of events.
- **Why require monotonic timestamps?** Enables simple bisect, timeline rendering, and diff operations without a full sort pass at load time.
- **Why hash events.ndjson and process_tree.json separately (not the tar as a whole)?** Enables partial integrity checks and forensic salvage of a truncated bundle.
- **Why Ed25519 (not OpenPGP/JOSE/cosign)?** Ed25519 is fast, deterministic, and available via OpenSSL ≥1.1 which is already a project dependency. The key is auto-generated to zero the friction cost. The signature and public key travel inside the manifest so consumers can verify without a PKI lookup. Third-party key infrastructure can be layered on top by re-signing the manifest.
