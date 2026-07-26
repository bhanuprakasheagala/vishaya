# Roadmap

What's shipped, what's coming, what's out of scope. Written for potential users deciding whether to build on Vishaya and for contributors looking for high-leverage places to help.

Dates are intentional targets, not commitments. Everything is best-effort until v1.0.

> **Reprioritized 2026-07 after a positioning research pass** ([research/2026-07-product-positioning.md](research/2026-07-product-positioning.md)). The differentiator is **verifiable + target-scoped + single-file evidence**, not "a portable capture format" (that niche is taken by `.scap`/Stratoshark). So v0.5 now leads with **chain-of-custody hardening** and **STIX export**; SCAP interop is **dropped**; MCP/LLM stay deferred; the web UI is **downgraded** (Stratoshark already owns "Wireshark-for-syscalls").

## v0.1 — current

**Status:** Builds and runs on Linux (aarch64 verified on a UTM VM); basic capture/inspect confirmed. Post-review fixes landed (exec capture, reader verification, BPF stack + mmsg layout, process-tree, wall-clock timeline). Per-feature status and open correctness/robustness items are tracked in [roadmap-decisions.md](roadmap-decisions.md) (detailed write-ups in [backlog.md](backlog.md)).

Capabilities:
- Target-scoped capture (cgroup v2 + mount namespace isolation)
- Process, file, network events by default; syscall opt-in
- DNS query/answer + plaintext HTTP request/response decoded from payload
- Single `.vishaya` bundle output: manifest + events + process tree + integrity hashes
- Bundles signed by default with a local Ed25519 key; reader verifies integrity
  hashes and signature at load time (tamper-evidence, not third-party attestation)
- CLI subcommands: `capture`, `tree`, `files`, `network`, `timeline`
- Standalone smoke tests: `isolation_probe`, `bundle_probe`
- Complete documentation set

Known limitations:
- No HTTPS plaintext (encrypted, needs TLS-library uprobes)
- No `sendmsg`/`recvmsg`/`sendmmsg`/`recvmmsg` payload capture (iovec paths uncovered)
- No artifact extraction (dropped files, memory dumps)
- No bundle diffing
- No `syscall_name` resolution (syscall events show number only)
- Bundle format is pre-release; schema will evolve additively until v1.0

## v0.5 — real forensic use

**Target:** first named IR firm, CERT, or researcher uses Vishaya in an actual investigation.

Additions (ordered by the repositioning — the first two are what make the pitch true):

**Chain-of-custody hardening (priority — makes "verifiable" honest)** — *shipped 2026-07*
- ✅ Sign the *entire* manifest (`sig.scope="manifest-v1"`), not just the two content hashes, so counts/host/target/timestamps are covered too (legacy two-hash bundles still verify).
- ✅ Print the signing-key fingerprint at capture time for out-of-band recording.
- ✅ Dedicated `vishaya verify <bundle>` with a loud, explicit verdict (integrity + signature).
- ✅ Pinned / trusted-key verification (`vishaya verify --verify-key`), so a consumer can assert *who* signed.
- Remaining: the key is still self-generated (tamper-evidence, not attestation) — see the v1.0 Sigstore/Rekor milestone.

**STIX 2.x export**
- `vishaya export --format stix` — emit STIX 2.x Observed-Data / Malware objects.
- Bridges into existing DFIR/CTI pipelines instead of asking them to adopt a new format. STIX/MAEC is the malware-behavior lingua franca; we export to it rather than invent one.
- OCSF export is a later maybe, only if a consumer needs it.

**Robustness (talk-worthy)**
- Regression test + demo: a recursive-fork / high-volume target whose capture stays valid and self-reports drops, where nested-JSON sandboxes silently truncate (arXiv 2511.04472, CVE-2025-61301/-61303). Flat append-only NDJSON is the design property that makes this hold.

**Artifact capture**
- Files created/modified/deleted by the target are copied to `artifacts/` in the bundle
- Bounded (configurable size limit per file, total limit per capture)
- Each artifact has a companion metadata record: original path, size, SHA-256, event ID that created it

**Bundle diffing** — *shipped 2026-07*
- ✅ `vishaya diff a.vishaya b.vishaya` — **semantic** comparison (compares behaviour sets, not raw events, so PIDs/timestamps/addresses don't create noise).
- Shows, per category: executed binaries, files created/deleted/renamed, DNS names, HTTP requests, and network endpoints only-in-A vs only-in-B. Exit 0 = identical, 1 = differs.
- Useful for detecting environment-sensitive malware behavior across runs.
- Follow-on (deferred, B-03): a `--normalize` bundle transform for path-randomness canonicalization; the diff already normalizes identifiers by comparing semantic sets.

**DNS + HTTP enhancements**
- `sendmsg`/`recvmsg` payload capture (adds iovec walking in BPF)
- HTTP header enrichment (User-Agent, Content-Type)
- DNS TTL correlation across query/answer pairs

**HTTPS plaintext (opt-in)**
- Uprobes into OpenSSL and BoringSSL (`SSL_read` / `SSL_write`)
- Emit `tls-read` / `tls-write` events with plaintext
- v0.5 scope: OpenSSL + BoringSSL only. GnuTLS, NSS, Go crypto/tls, Rust rustls deferred to later versions.

**Packaging**
- Debian and RPM packages
- Single static binary distribution
- systemd unit for background captures (optional)

**Better UX**
- `vishaya --version` shows tool version + supported schema major
- `vishaya capture --dry-run` prints what would be captured without running the target
- ✅ `vishaya summary` — one-screen verdict (trust + target + counts + tree + network + files) — *shipped 2026-07*
- Colored output where appropriate (with `--no-color` opt-out)

**Bundle format extensions**
- New `artifacts.json` sidecar listing captured artifacts with metadata
- New `dns.json` sidecar with deduplicated resolutions (query → answer map)
- Schema bumped to v0.5.0; readers with `0.1.0` reader still accept via major-version rule

## v1.0 — format freeze

**Target:** the moment external tools can confidently consume `.vishaya` bundles knowing the format won't break under them.

Additions:

**Schema freeze**
- All fields declared stable
- Any breaking change requires a v2.0.0 major bump
- Third-party writer/reader implementations viable

**Attestation / third-party trust (builds on v0.1 signing)**
- v0.1 already signs bundles with a local Ed25519 key and verifies at load, but the
  key is self-generated (tamper-evidence only, no identity).
- Cosign / Sigstore (keyless, Rekor transparency log) integration for real provenance
- Reader verifies the signature against a trust anchor and prints WHO signed

**Coverage expansion**
- Additional file syscalls: `openat2`, `unlink`, `rename`, `symlink*`, `chmod*`, `chown*`, `mknod*`
- Container context in event envelope (namespace IDs, container ID if detectable)
- Kernel module load/unload events (LSM hook)

**MITRE ATT&CK mapping**
- Post-capture analysis assigns ATT&CK technique IDs to events
- Stored in a `mitre.json` sidecar; not a runtime cost

**YARA integration**
- Scan captured artifacts against YARA rule sets during finalize
- Matches recorded in an `iocs.json` sidecar

**Viewer (downgraded — optional, not a differentiator)**
- Stratoshark already delivers the "Wireshark-for-syscalls" GUI experience, so a full web UI is not where Vishaya stands out. A *small* static single-file HTML viewer (drop a `.vishaya` in, no server) is the most it's worth — useful for sharing a case with non-CLI colleagues, nothing more.
- Deliberately optional; CLI remains primary. Do not invest here ahead of chain-of-custody, STIX export, or robustness.

## v2.0 — ecosystem

**Target:** Vishaya becomes the format others build on.

Deliberately speculative. Things I *might* build if the format catches on:

**MCP server for AI analyst workflows** *(deferred — reinforced by 2026-07 research; not where the gap is, and no AI in the v1 line)*
- Model Context Protocol server exposing `.vishaya` bundles as tools/resources
- Analysts drop a bundle into Claude Desktop and chat: "what persistence did this establish?"
- Complementary to the CLI, not a replacement

**LLM-powered summarization** *(deferred — same reasoning)*
- Post-capture summary agent that reads the bundle and produces plain-English case notes
- Marked as best-effort AI output, not authoritative

**Sandbox orchestrator adapters** *(kept — genuine distribution channel)*
- Cuckoo3 / CAPE / custom pipelines can plug in as `.vishaya` producers
- Adapters live in this repo as optional modules; core stays lean

**Cross-capture correlation** *(kept)*
- Given N bundles, find shared indicators (endpoints, tools, TTPs)
- Useful for tracking a malware family across samples

**~~SCAP interop (embed `.scap` in the bundle)~~ — DROPPED (2026-07 research)**
- Embedding a Sysdig `.scap` for Stratoshark interop means competing on the incumbent's own turf for little payoff. Vishaya's value is verifiable + scoped + single-file, not `.scap` compatibility. Cut.

## Explicitly not planned (ever)

To keep scope disciplined, these are permanent non-goals:

- **Runtime alerting / policy enforcement** — that's an EDR. Falco and Tetragon do this well.
- **Fleet monitoring** — Vishaya captures one target per invocation. If you want continuous monitoring across a fleet, use a different tool.
- **Windows / macOS support** — Linux-only, forever. Different OSes need different tools.
- **Cloud service** — no SaaS, no hosted analysis, no telemetry back to any server.
- **Kernel modules** — eBPF only. Vishaya will never require loading a kernel module.
- **Ptrace-based fallback** — if a system doesn't support eBPF, Vishaya doesn't work there. No degraded modes.

## How to influence the roadmap

Open an issue with a concrete use case. "I need X because Y" is far more actionable than "please add X". If your use case is well-defined and fits the product vision, it'll get prioritized.

Contributions welcome for anything in v0.5. Anything in v1.0+ needs a design discussion first.
