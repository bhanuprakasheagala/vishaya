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

## 8. Product evolution ideas to sharpen uniqueness

The core proposition is already strong: a single, scoped, portable, verifiable bundle for a suspect Linux binary. The next step is to make the project feel more like a forensic product than a protocol plus CLI. The following additions would improve usability, differentiation, and real-world trust without changing the mission.

### 8.1 Case narrative / triage summary

The bundle should not only store raw events; it should also produce a human-readable summary of the most important actions. A `case-report` or `assess` mode could automatically call out:

- what binary was executed and under what arguments
- which files were created, modified, renamed, or dropped
- which network destinations were contacted
- whether the target spawned a shell, downloaded content, or attempted persistence
- what looks high-value versus low-value for the analyst

This turns raw telemetry into a small investigation story and gives the project a more polished, analyst-facing feel.

### 8.2 Semantic behavior intelligence

The project already excels at process/file/network events. The next quality leap is behavior classification: identifying what the sample did, not just what events it emitted. Examples:

- network exfiltration vs normal web fetch
- shell execution leading to command-and-control activity
- file staging followed by persistence attempts
- artifact creation and later rename/delete behavior
- repeated suspicious process lineage over multiple runs

A risk-scored behavior summary would be especially useful for malware triage and repeated case comparison.

### 8.3 Stronger chain-of-custody and provenance

For real investigative use, the bundle should carry more than event logs and a signature. Add case metadata such as:

- case ID / evidence ID
- collection time and investigator identity
- who verified the bundle
- previous/next evidence references
- optional attestation-backed verification through trusted keys or Sigstore-style provenance

This matters because a good evidence bundle is not only tamper-evident — it also clearly communicates who created it and under what chain of custody it was handled.

### 8.4 A lightweight HTML or local browser viewer

The CLI is the right default, but a very small static viewer would make the project much more approachable for non-CLI stakeholders. A browser-based summary could show:

- verification verdict
- process tree
- summary facts
- file and network tables
- timeline highlights
- suspicious behavior cards

This remains optional, but it is a strong communication tool for sharing a case with colleagues or stakeholders.

### 8.5 Standard export formats for ecosystem interoperability

To increase practical value, Vishaya should be able to export summaries in common forensic and security formats, for example:

- STIX 2.x
- OCSF / normalized event output
- CSV or markdown case reports
- MISP-compatible indicators

This would help integrate the evidence into broader IR and CTI workflows without requiring teams to re-implement a custom parser.

### 8.6 A gallery of “evidence stories”

The repository already includes sample bundles; those could be turned into a gallery of real examples, such as:

- command execution with network access
- shell pipeline activity
- file lifecycle and rename behavior
- suspicious outbound HTTP contact
- persistence attempts

This would make the project far easier to understand for newcomers and would show exactly what kind of questions Vishaya answers best.

### 8.7 UX improvements that reduce friction

A few polish features would make the product feel much more mature:

- `vishaya --version` showing schema major plus tool version
- `capture --dry-run`
- richer JSON output for automation
- better shell completion scripts
- `--no-color` and more concise default output
- improved summary cards for high-value findings

These are not core features, but they are the difference between a technical project and a usable product.

### 8.8 Decision framework for Step 1: case summary / behavior intelligence

This is the first enhancement worth doing because it addresses the biggest product gap: raw evidence is useful, but analysts need a short, trustworthy narrative before they dive into the event stream. The best version of this feature is not a new capture model or a deep AI classifier; it is a small, inspect-time summary layer that turns existing telemetry into a succinct case story.

#### What it takes

The project already has the ingredients for this feature:

- the event stream already contains process, file, network, and syscall observations
- process lineage is reconstructed in the bundle and already available for inspection
- the current `summary` output already aggregates DNS/HTTP/file creation and descendant counts
- the code path is already `O(N)` over the stream, with bounded display output and no extra persisted data model

That means Step 1 is not “start from zero”; it is to formalize the heuristics and present them as a case-oriented summary. The implementation should focus on a bounded list of high-value signal types, such as:

- shell execution observed
- network contact to suspicious host(s)
- HTTP or DNS activity observed
- file creation, rename, or deletion patterns
- descendant process count / process lineage expansion
- persistence or staging indicators when present

This should remain intentionally conservative and explicit. We should report observed behavior as `observed` or `suspected`, not as a hard conclusion like `malware confirmed`.

#### Why the ROI is high

The return is high because it improves the product at the exact place where users make a decision: the first few seconds of a case review. Analysts rarely need more than a short overview before deciding whether to inspect deeper. A case summary makes Vishaya feel like a real forensic product, not just a protocol + CLI. It also makes demos and onboarding much easier: a user can immediately see the story without having to understand the full event schema.

For adoption, this matters more than raw feature count. The user experience becomes:

- run capture
- open bundle
- see a defensible quick verdict and highlights
- drill into process tree, network, files, timeline only if needed

That is a much stronger product identity than “we can parse a lot of events.”

#### Will it add weight or affect performance?

If implemented correctly, the answer is no in any material way:

- no capture-time overhead beyond the existing event scan
- no meaningful bundle size increase
- no new data model required at write time
- no new dependency or external service
- output remains bounded and small, even for large captures

The right design is a read-time summary pass that uses the existing event stream, not a new per-event telemetry model. In other words, the cost is highly bounded and largely proportional to the already existing `summary` processing. This keeps the feature additive and low-risk while preserving the project's fast CLI-first workflow.

The only way this feature becomes heavy is if we add expensive per-event classification, large stored metadata, or a new bundle schema just to support summary generation. That should be avoided. Keep it as an inspect-side heuristic layer: cheap, deterministic, and clearly labeled as evidence interpretation rather than proof.

#### Recommended implementation stance

The best version of Step 1 should be:

- heuristic and advisory
- bounded and explainable
- output-first, not schema-first
- present in `summary` as a short highlights block
- safe to add without changing default behavior or breaking older bundles

This preserves the project's existing principles: minimal scope, low risk, additive value, and strong forensic trust. It also makes the project feel more mature without drifting into heavier infrastructure or speculative intelligence features.

### 8.9 The strongest product story

The best strategic angle for Vishaya is this:

> Vishaya is not a host monitor or fleet sensor. It is a portable forensic evidence bundle for a single suspect Linux target, signed, scoped, and inspectable by anyone without root or a daemon.

This identity is compelling because it is narrow, honest, and unusually useful. The next wave of work should focus on making that identity feel more obviously “forensic product” and less like a raw event collector.

This direction would preserve the project's existing strengths while making it easier to explain, easier to trust, and easier to use in real investigations.