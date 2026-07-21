# Vishaya

A portable forensic capture format for Linux, focused on scoped observation of a single target process and its descendants.

*Vishaya* (विषय, Sanskrit — "the subject-matter of investigation"). Each capture is a `.vishaya` bundle: a self-contained, portable, versioned record of everything a target process (and its children) did on a Linux host during the capture window.

## What it does

Think of `.vishaya` as **PCAP for process behavior**. Just as `.pcap` lets network analysts capture, share, and re-analyze packet traces with any compatible tool, `.vishaya` does the same for what a single Linux binary — and everything it spawns — does at the kernel level.

One command captures every process, file, and network operation the target performs, decodes DNS queries and plaintext HTTP traffic, reconstructs the process tree, and packages everything into a single portable file with integrity hashes and provenance metadata. The bundle then travels: any machine with a compatible reader can inspect it, months or years later, with no dependency on the machine that captured it.

The specific combination is what doesn't already exist on Linux:

- **Target-scoped, not fleet-wide.** Falco, Tetragon, and Tracee watch every process on every host. Vishaya observes exactly one target and its descendants — cgroup-filtered at the kernel level.
- **Portable single-file bundle.** No database, no SIEM ingestion, no service on the analyst's machine. The bundle is the product.
- **Open specification.** `.vishaya` is designed as an interchange format, not a proprietary output. Third-party readers and writers are welcome and encouraged.
- **eBPF-native, CLI-first, no daemon, no cloud.** Install a binary, run it locally, get a file. Nothing phones home.

Not an EDR. Not a SIEM. Not a fleet monitor. See [docs/vision.md](docs/vision.md) for the deliberate non-goals.

## Documentation

Start with [docs/index.md](docs/index.md) for the full doc set. Highlights:

- [docs/getting-started.md](docs/getting-started.md) — install, build, first capture, first inspect
- [docs/vision.md](docs/vision.md) — product vision and design principles
- [docs/concepts.md](docs/concepts.md) — background primer for readers new to eBPF/cgroups/namespaces/DFIR
- [docs/architecture.md](docs/architecture.md) — v0.1 architecture, dependency graph, design decisions
- [docs/flow.md](docs/flow.md) — end-to-end sequence diagrams for capture and inspect paths
- [docs/code-walkthrough.md](docs/code-walkthrough.md) — module-by-module tour of the implementation
- [docs/event-reference.md](docs/event-reference.md) — every event family and JSON schema
- [docs/bundle-spec-v0.1.md](docs/bundle-spec-v0.1.md) — authoritative bundle format specification
- [docs/build.md](docs/build.md) — CMake structure, dependency graph, extension guide
- [docs/troubleshooting.md](docs/troubleshooting.md) — common failures at build/capture/inspect time
- [docs/roadmap.md](docs/roadmap.md) — v0.1, v0.5, v1.0+ plans and non-goals
- [docs/enterprise-features.md](docs/enterprise-features.md) — detailed feature plan for enterprise adoption
- [docs/backlog.md](docs/backlog.md) — working tracker for review findings with status per item
- [docs/glossary.md](docs/glossary.md) — terms and acronyms reference

## Requirements

- Linux kernel with eBPF + CO-RE support (5.15+ recommended)
- `/sys/kernel/btf/vmlinux` present (BTF debug info)
- cgroup v2 unified hierarchy (systemd default on modern distros)
- Root privileges for `vishaya capture` (eBPF + cgroup + namespaces)

## Dependencies

- **BPF build:** clang / LLVM, bpftool, libbpf
- **Userspace build:** CMake 3.20+, C++20 compiler, pkg-config
- **Libraries:** libzstd, libarchive, nlohmann-json (≥3.9), CLI11 (≥2.2), OpenSSL libcrypto

Run `./scripts/linux.sh check` for a host preflight and package install hints.

## Build

```bash
./scripts/linux.sh all         # userspace + BPF object
```

Or manually:

```bash
cmake -S . -B build
cmake --build build -j
./scripts/linux.sh bpf         # generates bpf/vishaya.bpf.o
```

Products of the build:
- `build/vishaya` — the CLI (capture + inspect subcommands)
- `build/isolation_probe` — standalone smoke test for the isolation subsystem
- `build/bundle_probe` — standalone smoke test for the bundle writer

## Usage

```bash
# Capture a target's activity (root required)
sudo ./build/vishaya capture --target /usr/bin/curl \
    --output /tmp/curl.vishaya -- https://example.com

# Inspect the captured bundle (no root)
./build/vishaya tree     /tmp/curl.vishaya
./build/vishaya files    /tmp/curl.vishaya
./build/vishaya network  /tmp/curl.vishaya
./build/vishaya timeline /tmp/curl.vishaya

# Inspect the bundle by hand
zstd -d < /tmp/curl.vishaya | tar -tv
zstd -d < /tmp/curl.vishaya | tar -xO manifest.json | jq
```

## What a `.vishaya` bundle contains

A `.vishaya` file is a `tar.zst` archive:

- `manifest.json` — capture metadata: schema version, tool version, host kernel/arch, target binary + SHA-256, isolation info, event counts, integrity hashes
- `events.ndjson` — one JSON event per line: process (exec/fork/exit/clone), file (openat/unlinkat/renameat2), network (socket lifecycle + DNS + HTTP), optional syscall
- `process_tree.json` — reconstructed process lineage rooted at the target
- `artifacts/` — reserved for dropped-file capture (empty in v0.1)

See [docs/bundle-spec-v0.1.md](docs/bundle-spec-v0.1.md) for the full spec.

## v0.1 status

- Target-scoped capture via cgroup v2 + mount namespace isolation
- Process, file, network (socket + DNS + plaintext HTTP) events
- Optional raw syscall capture via `--enable-syscalls`
- CLI-first, no daemons, no cloud dependencies
- Bundle format is pre-release: v1.0.0 will freeze the schema

## Non-goals (permanent)

- Not an EDR, SIEM, or fleet monitor
- No runtime alerting, blocking, or policy enforcement
- No Windows/macOS
- No cloud dependencies

## License

Kernel-side BPF probes are GPL-2.0 (required by the kernel). Userspace source files carry their individual licenses.
