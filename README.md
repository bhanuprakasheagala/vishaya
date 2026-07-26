# Vishaya

**A verifiable, target-scoped forensic evidence bundle for a single suspect Linux binary.**

Vishaya captures everything a single Linux binary — and every process it spawns — does at the kernel level: processes, files, and network. It packages the whole run into one self-contained, signed `.vishaya` file you can hand to a colleague, archive for years, and re-open — and cryptographically verify — with any compatible tool. No agent on the analyst's machine, no database, no cloud.

*Vishaya* (विषय, Sanskrit — "the subject-matter of investigation").

---

## The idea

One command runs a suspect binary inside a scoped boundary and records everything it — and every process it spawns — does at the kernel level, into a single **signed** file. Any machine can open that file later, **verify it wasn't altered**, and inspect it. No agent, no database, no cloud.

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

## Try it now (no root, no build)

The repo ships real sample captures in [`samples/`](samples/). Because a bundle is just
`tar.zst` + JSON, you can read one with tools you already have:

```bash
zstd -dc samples/04-http-curl.vishaya | tar -xO events.ndjson | jq
```

Or, once you've built the CLI:

```bash
vishaya summary  samples/04-http-curl.vishaya        # one-screen verdict — start here
vishaya tree     samples/02-shell-pipeline.vishaya   # process tree
vishaya network  samples/04-http-curl.vishaya        # decoded DNS + HTTP
vishaya verify   samples/04-http-curl.vishaya        # integrity + signature verdict
```

`capture` needs root + eBPF; **inspection and verification need neither.** See
[samples/README.md](samples/README.md).

---

## What makes it different

Plenty of tools trace Linux processes, and a portable capture format already exists (Sysdig/CNCF's `.scap`, viewable in Stratoshark). Vishaya's edge isn't "a capture format" — it's the combination none of them offer:

- **Verifiable evidence, not just telemetry.** Every bundle is SHA-256 integrity-hashed and Ed25519-signed, and the reader checks both when the bundle is opened. `.scap`, Tracee's `--capture`, and CAPE's output are all unsigned. Verifiable *integrity* — not the act of capturing — is what lets you trust an artifact as evidence. (Today's key is self-generated: tamper-evidence + pinned-key verification, not third-party attestation — that's the v1.0 Sigstore milestone.)
- **Target-scoped, not host- or fleet-wide.** Falco, Tetragon, Tracee, and even `.scap` observe the whole host or container. Vishaya observes exactly one target and its descendants, filtered at the kernel by cgroup — so a capture is a *case*, not a firehose.
- **One self-contained file.** Not a database, not a SIEM stream, not a directory tree keyed to a tool's internal IDs (Tracee's `out/` tree, CAPE's `storage/analyses/<id>/`). One `.vishaya` you hand to a colleague, archive, and re-open years later.
- **An open format, not a proprietary output.** `.vishaya` is a documented spec, and a bundle is plain `tar.zst` + NDJSON + JSON. Third-party readers are welcome — a 20-line script can read one.
- **Robust by format.** A flat, append-only NDJSON event log — no deeply nested document to overflow or silently truncate.
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
./build/vishaya summary  /tmp/curl.vishaya    # one-screen verdict — start here
./build/vishaya tree     /tmp/curl.vishaya
./build/vishaya files    /tmp/curl.vishaya
./build/vishaya network  /tmp/curl.vishaya
./build/vishaya timeline /tmp/curl.vishaya

# Compare two runs of the same sample — what changed? (exit 0 = identical, 1 = differs)
./build/vishaya diff     run-a.vishaya run-b.vishaya

# Verify integrity + signature (no root); optionally pin the signing key
./build/vishaya verify   /tmp/curl.vishaya
./build/vishaya verify   /tmp/curl.vishaya --verify-key <base64-ed25519-pubkey>
```

Add `--enable-syscalls` to a capture for raw syscall events (high volume; off by default).

---

## Status

**v0.1 — pre-release.** The capture pipeline, bundle format, signing/verification, and inspect commands are implemented and documented. The `.vishaya` schema isn't frozen yet, but it's **safe to build a reader against today**: within the 0.x series the format is **additive-only** — existing fields, entries, and event kinds won't be removed, renamed, or retyped, only new optional ones added (see the [spec's stability commitment](docs/bundle-spec-v0.1.md)). **v1.0** formally freezes it.

Working today: target-scoped capture (cgroup v2 + mount namespace), process/file/network events, DNS and plaintext-HTTP decoding, bundles signed and verified at load time, and the `tree`/`files`/`network`/`timeline` inspect views. On the roadmap: artifact capture, bundle diffing, HTTPS plaintext via TLS-library uprobes, and a reader SDK — see [roadmap.md](docs/roadmap.md).

**Honest about scope.** Vishaya is the flight recorder, not the aircraft: it produces the evidence, it does not provide the containment. The cgroup + mount-namespace scope prevents *accidental* host contamination; it is **not** a hardened detonation chamber, and a determined, root-adjacent sample can escape it. For genuinely adversarial malware, run Vishaya **inside a VM/hypervisor sandbox** (a full VM, DRAKVUF, a Cuckoo/CAPE guest) — that's the chamber; Vishaya is the black box inside it. The default bundle signature uses a locally generated key — tamper-evidence + pinned-key verification, not third-party attestation (keyless/Sigstore attestation is the v1.0 milestone).

## Non-goals (permanent)

- Not an EDR, SIEM, or fleet monitor — no runtime alerting, blocking, or policy enforcement
- No Windows or macOS — Linux only
- No cloud service, telemetry, or phone-home
- No kernel module — eBPF only

## Documentation

Full documentation lives in **[docs/](docs/index.md)**. Good entry points:

- [getting-started.md](docs/getting-started.md) — install, build, first capture, first inspect
- [vision.md](docs/vision.md) — what Vishaya is, and the deliberate non-goals
- [bundle-spec-v0.1.md](docs/bundle-spec-v0.1.md) — the `.vishaya` format, for anyone building a reader
- [roadmap.md](docs/roadmap.md) — what's shipped, what's next, what's out of scope

## License

Kernel-side BPF probes are GPL-2.0 (required by the kernel). Userspace source files carry their individual licenses.
