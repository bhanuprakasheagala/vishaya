# Vishaya

**A portable, verifiable evidence format for Linux process behavior — the PCAP of what a program does.**

Vishaya captures everything a single Linux binary — and every process it spawns — does at the kernel level: processes, files, and network. It packages the whole run into one self-contained, signed `.vishaya` file you can hand to a colleague, archive for years, and re-open with any compatible tool. No agent on the analyst's machine, no database, no cloud.

*Vishaya* (विषय, Sanskrit — "the subject-matter of investigation").

---

## The idea

`.pcap` did this for network packets: capture once into one portable file, then read it forever with any tool. Vishaya does the same for **process behavior**.

```bash
# Capture — one command, one file (root required)
sudo vishaya capture --target /bin/sh --output case.vishaya -- -c 'curl http://example.com'

# Inspect — anywhere, later, no root, no daemon
vishaya tree     case.vishaya
vishaya timeline case.vishaya
```

```
$ vishaya tree case.vishaya
bundle: case.vishaya
target: pid=48213 exec=/bin/sh cmdline="sh -c curl http://example.com"

└── sh (pid=48213 exec=/bin/sh)
    └── curl (pid=48219 exec=/usr/bin/curl exit=0)
```

```
$ vishaya timeline case.vishaya
bundle: case.vishaya

TIME (UTC)                  PID     COMM     EVENT                 DETAIL
------------------------------------------------------------------------------------
2026-07-21T09:14:02.104Z    48213   sh       process:exec          /bin/sh (sh -c curl http://example.com)
2026-07-21T09:14:02.140Z    48219   curl     process:exec          /usr/bin/curl (curl http://example.com)
2026-07-21T09:14:02.151Z    48219   curl     network:dns-query     127.0.0.53:53 A example.com
2026-07-21T09:14:02.167Z    48219   curl     network:dns-answer    127.0.0.53:53 A example.com
2026-07-21T09:14:02.170Z    48219   curl     network:http-request  93.184.216.34:80 GET example.com/
2026-07-21T09:14:02.205Z    48219   curl     process:exit          code=0
```

The bundle is just `tar.zst` — you don't even need Vishaya to read it:

```bash
zstd -dc case.vishaya | tar -xO events.ndjson | jq
```

---

## What makes it different

Plenty of tools trace Linux processes. The specific combination is the gap Vishaya fills:

- **Target-scoped, not fleet-wide.** Falco, Tetragon, and Tracee watch every process on every host. Vishaya observes exactly one target and its descendants, filtered at the kernel by cgroup — so a capture is a *case*, not a firehose.
- **The file is the product.** No database, no SIEM ingest, no service on the analyst's machine. Capture on one host; analyze on another, months later.
- **Verifiable by default.** Every bundle carries SHA-256 integrity hashes and an Ed25519 signature, both checked when the bundle is opened. Tamper-evident out of the box.
- **An open format, not a proprietary output.** `.vishaya` is a documented spec, and a bundle is plain `tar.zst` + NDJSON + JSON. Third-party readers are welcome — a 20-line script can read one.
- **eBPF-native, CLI-first. No daemon, no cloud.** Install a binary, run it, get a file. Nothing phones home.

Vishaya is a recorder — not an EDR, a SIEM, or a fleet monitor, and it doesn't try to be.

---

## What a capture contains

A `.vishaya` file is a `tar.zst` archive:

| Entry | Contents |
|---|---|
| `manifest.json` | Capture metadata: schema/tool version, host kernel & arch, target path + SHA-256, isolation info, event counts, integrity hashes, and signature |
| `events.ndjson` | One JSON event per line — process (exec/fork/exit/clone), file (openat/unlinkat/renameat2), network (socket lifecycle + decoded DNS + plaintext HTTP), optional raw syscalls |
| `process_tree.json` | Reconstructed process lineage rooted at the target |
| `artifacts/` | Reserved for captured dropped files (v0.5+) |

Process events carry the executed path and full command line, resolved from the kernel at exec time. Network payloads are decoded in userspace into `dns-query`/`dns-answer` and `http-request`/`http-response` events. Event timestamps map to wall-clock via a clock anchor in the manifest. See the [bundle spec](docs/bundle-spec-v0.1.md) for the exact schema.

---

## Install & build

Linux only, by design — kernel 5.15+ with eBPF + CO-RE, cgroup v2, and `/sys/kernel/btf/vmlinux` present. Root is required for `capture`; inspection needs no privileges.

```bash
./scripts/linux.sh check    # host preflight + package-install hints
./scripts/linux.sh all      # build userspace + BPF object
```

Dependencies: clang/LLVM, bpftool, libbpf (BPF build); CMake 3.20+, a C++20 compiler, libzstd, libarchive, nlohmann-json ≥ 3.9, CLI11 ≥ 2.2, OpenSSL ≥ 1.1.1 (userspace). The preflight prints exact package names for Debian/Ubuntu, Fedora, and Arch. Full walkthrough: [getting-started.md](docs/getting-started.md).

The build produces:

- `build/vishaya` — the CLI (capture + inspect)
- `build/isolation_probe`, `build/bundle_probe` — standalone smoke tests

## Usage

```bash
# Capture a target's activity (root)
sudo ./build/vishaya capture --target /usr/bin/curl \
    --output /tmp/curl.vishaya -- https://example.com

# Inspect the bundle (no root)
./build/vishaya tree     /tmp/curl.vishaya
./build/vishaya files    /tmp/curl.vishaya
./build/vishaya network  /tmp/curl.vishaya
./build/vishaya timeline /tmp/curl.vishaya
```

Add `--enable-syscalls` to a capture for raw syscall events (high volume; off by default).

---

## Status

**v0.1 — pre-release.** The capture pipeline, bundle format, signing/verification, and inspect commands are implemented and documented. The `.vishaya` schema is **not yet frozen** — it evolves additively until **v1.0**, which freezes the format so external tools can rely on it.

Working today: target-scoped capture (cgroup v2 + mount namespace), process/file/network events, DNS and plaintext-HTTP decoding, bundles signed and verified at load time, and the `tree`/`files`/`network`/`timeline` inspect views. On the roadmap: artifact capture, bundle diffing, HTTPS plaintext via TLS-library uprobes, and a reader SDK — see [roadmap.md](docs/roadmap.md).

**Scope.** The cgroup + mount-namespace boundary prevents *accidental* host contamination; it is **not** a hardened detonation chamber, and a determined adversary with root-adjacent capability can escape it. The default bundle signature uses a locally generated key — it is tamper-evidence, not third-party attestation (keyless/Sigstore attestation is planned). For malware that actively evades sandboxes, use VM/hypervisor-based tooling; Vishaya targets suspicious-but-not-anti-sandbox binaries and lightweight forensic detonation.

## Documentation

Full documentation lives in **[docs/](docs/index.md)**. Good entry points:

- [getting-started.md](docs/getting-started.md) — install, build, first capture, first inspect
- [vision.md](docs/vision.md) — what Vishaya is, and the deliberate non-goals
- [bundle-spec-v0.1.md](docs/bundle-spec-v0.1.md) — the `.vishaya` format, for anyone building a reader
- [roadmap.md](docs/roadmap.md) — what's shipped, what's next, what's out of scope
