# Vishaya

**A verifiable, target-scoped forensic evidence bundle for a single suspect Linux binary.**

*Vishaya* (विषय, Sanskrit) — "the subject-matter of investigation."

Each capture is a Vishaya: a self-contained, signed bundle recording what a specific target process (and everything it spawned) did on a Linux host. The tool runs the target inside an isolation boundary, captures via eBPF, and writes the whole session to a single, integrity-checked file that any analyst, on any machine, can open, **verify**, and inspect — years later.

> **Positioning note (2026-07).** A portable, multi-tool *capture format* already exists — Sysdig/CNCF's `.scap`, now readable in Stratoshark ("Wireshark for syscalls"). So Vishaya's edge is **not** "a portable capture format." It is the combination none of them offer: **verifiable (signed, tamper-evident) + target-scoped (one binary, not host- or fleet-wide) + a single self-contained evidence file.**

---

## 1. What this is

Three parts, deliberately small:

1. **A capture engine** — attaches eBPF probes, launches a target inside a scoped isolation boundary (Linux namespaces + cgroups), records the target's process tree and its activity.
2. **A portable bundle** — the `.vishaya` file. Single file. Self-contained. Versioned. Contains a manifest, event stream, process tree, and any captured artifacts.
3. **A CLI** — reads a `.vishaya` bundle: a one-screen `summary`, structured views (process tree, files, network, timeline), `verify` (integrity + signature), `diff` (compare two captures), and `artifacts` (list captured files). Inspection needs no root.

That's the whole product. Everything else is deferred until it's genuinely needed.

## 2. What makes it different

Not trying to compete with anything. The specific combination below is what no existing tool offers — and the ordering reflects where the real, defensible gap is:

- **Verifiable evidence, not just telemetry.** Every bundle is integrity-hashed and Ed25519-signed, and the reader checks both at open time. No competing eBPF capture output signs itself: `.scap` has no signing/manifest, Tracee `--capture` writes unsigned loose files, CAPE writes unsigned per-task directories. Verifiable *integrity* — not the act of capturing — is what lets an artifact be trusted as evidence. *This is the headline.* (Self-generated key today = tamper-evidence + pinned-key verification; third-party attestation is the v1.0 Sigstore milestone.)
- **Target-scoped, not host- or fleet-wide.** Falco, Tetragon, Tracee, and even `.scap` observe the whole host or container. Vishaya captures exactly one process tree — the suspect you asked about. A capture is a *case*, not a firehose.
- **One self-contained file.** Not a database, not a SIEM stream, not a directory tree keyed to a tool's internal IDs (Tracee's `out/` tree, CAPE's `storage/analyses/<id>/`). One `.vishaya` file you hand to a colleague, archive, and re-open years later.
- **Robust by format.** The event log is flat, append-only NDJSON — no deep nesting to overflow. Recent work shows sandboxes/EDRs silently truncate deeply-nested behavioral reports (arXiv 2511.04472, CVE-2025-61301/-61303); a flat NDJSON stream has no such limit to attack.
- **CLI-first, no daemons, no server, no cloud dependencies.** Install a binary. Run it locally. Done.
- **Clean, minimal architecture.** Small surface area on purpose; extensible via additive event families + schema versioning, but the core stays small.

None of these are groundbreaking individually. The combination — *verifiable + scoped + single-file* — is what's genuinely not being built.

## 3. Design principles

Non-negotiable, in priority order:

1. **Scoped capture over fleet monitoring.** Capture a specific target and its descendants, not the world.
2. **The bundle is verifiable evidence.** Portable, versioned, self-describing — and signed + integrity-checked so a consumer can trust it wasn't altered. Everything else exists to produce and consume trustworthy bundles.
3. **CLI-first.** Analyst uses a terminal. No web UI, no daemon required, no dashboard.
4. **Minimal, no cloud dependencies.** Runs on one Linux host. No external services required, ever.
5. **eBPF-native, Linux-only.** Requires modern kernels with CO-RE/BTF. Nothing older is supported. This bounds engineering scope and lets us do the Linux case well.
6. **Extensible by design, not by anticipation.** Event families and bundle sections are versioned and additive; adding a new probe or a new artifact type later must not break older bundles. But we do not build for hypothetical future features today.

## 4. The `.vishaya` bundle

A single file (initial implementation: `tar.zst`). Contents:

- `manifest.json` — schema version, capture-tool version, kernel version, target binary hash, capture timestamp, capture duration, tool provenance.
- `events.ndjson` — events emitted by the eBPF probes, one per line, reusing the existing event schema.
- `process_tree.json` — reconstructed process lineage of the target and its descendants.
- `artifacts/` — files created, modified, or dropped by the target (opt-in, bounded).

Guarantees:
- **Verifiable** — content is SHA-256 integrity-hashed and Ed25519-signed; the reader checks both at open time and reports the result. *Honest scope today:* the signing key is locally generated and its public half travels in the bundle, so this is strong tamper-**evidence**, not third-party attestation. True attestation (Sigstore/Rekor, pinned trusted keys) is the v1.0 credibility milestone — see the roadmap.
- **Self-describing** — carries its own schema version and decoder hints.
- **Tool-independent** — no dependency on a specific runtime environment; anyone with the CLI (or the documented spec) can read it.
- **Robust** — flat append-only NDJSON event log; no nested-document depth limit to overflow or truncate.
- **Long-lived** — a bundle produced today should still be readable years from now with a newer CLI.

## 5. Target user

Someone who has a suspicious Linux binary and wants a portable, verifiable record of what it did — dropped from a compromised host, pulled from a malware corpus, or being evaluated before deployment. They run `vishaya capture --target ./sample.elf`, get a `.vishaya` file, and inspect or hand it off.

**Mental model: Vishaya is the flight recorder, not the aircraft.** It does not provide the containment — it produces the evidence from *inside* whatever containment you already trust. For a benign or suspicious-but-not-anti-sandbox binary, run it directly. For a genuinely adversarial sample, run Vishaya **inside your existing VM/hypervisor sandbox** (a full VM, DRAKVUF, a Cuckoo/CAPE guest): the sandbox is the detonation chamber; Vishaya is the black box that comes out with a signed, portable, tool-independent account of the run. This is why it complements sandbox orchestrators rather than competing with them.

That's the whole persona. Analyst working on a specific binary, wanting a case file — not an ops team monitoring a fleet, and not a hardened detonation chamber.

## 6. Non-goals

Explicit, to prevent scope creep:

- Not an EDR. Not a SIEM. Not a fleet monitor.
- **Not a containment boundary** — Vishaya records from inside whatever containment you already trust; it is not itself a hardened detonation chamber (the flight-recorder model in §5).
- No runtime alerting, blocking, or policy enforcement.
- No Windows.
- No cloud dependencies. No SaaS.
- No dashboard or web UI in v1.
- Not aiming to replace Cuckoo, CAPE, Tracee, Stratoshark, or DRAKVUF. Vishaya complements them — it runs inside them and exports to them; different scope, different job.
- No paid dependencies. No LLM/AI integration (kept as architectural headroom, not core scope).

## 7. Roadmap

Kept deliberately short here — the authoritative, decision-annotated roadmap (with the
post-research keep/cut/defer calls) lives in [roadmap.md](roadmap.md).