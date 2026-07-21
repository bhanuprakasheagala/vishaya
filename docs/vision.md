# Vishaya

**A portable forensic capture format for Linux, focused on scoped observation of a single target process and its descendants.**

*Vishaya* (विषय, Sanskrit) — "the subject-matter of investigation."

Each capture is a Vishaya: a self-contained, portable bundle recording what a specific target process (and everything it spawned) did on a Linux host. The tool runs the target inside an isolation boundary, captures via eBPF, and writes the whole session to a single file that any analyst, on any machine, can open and inspect.

---

## 1. What this is

Three parts, deliberately small:

1. **A capture engine** — attaches eBPF probes, launches a target inside a scoped isolation boundary (Linux namespaces + cgroups), records the target's process tree and its activity.
2. **A portable bundle** — the `.vishaya` file. Single file. Self-contained. Versioned. Contains a manifest, event stream, process tree, and any captured artifacts.
3. **A CLI** — reads a `.vishaya` bundle and prints structured views: process tree, files touched, network endpoints, timeline.

That's the whole product. Everything else is deferred until it's genuinely needed.

## 2. What makes it different

Not trying to compete with anything. But the specific combination below is not something that currently exists in the eBPF/DFIR space:

- **Target-scoped, not host-wide.** Existing eBPF tools (Falco, Tracee, Tetragon, Sysdig, Elkeid) monitor everything on a host. Vishaya captures exactly one process tree — the one you asked about.
- **Portable, self-contained single-file bundle.** Not a database. Not a stream to a SIEM. Not tied to a specific vendor toolchain. Just a file you can hand to a colleague.
- **Case-oriented, not fleet-oriented.** The mental model is "here's one investigation, in one file" — not "here's a stream of events from many hosts."
- **CLI-first, no daemons, no server, no cloud dependencies.** Install a binary. Run it locally. Done.
- **Clean, minimal architecture.** Small surface area on purpose. Extensible via event-family additions and schema versioning, but the core stays small.

None of these are groundbreaking individually. The combination is what's genuinely not being built.

## 3. Design principles

Non-negotiable, in priority order:

1. **Scoped capture over fleet monitoring.** Capture a specific target and its descendants, not the world.
2. **The bundle is the product.** Portable, versioned, self-describing. Everything else exists to produce and consume bundles.
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

Portability guarantees:
- **Self-describing** — carries its own schema version and decoder hints.
- **Integrity-hashed** — contents are checksummed; tampering is detectable.
- **Tool-independent** — no dependency on a specific runtime environment; anyone with the CLI can read it.
- **Long-lived** — a bundle produced today should still be readable years from now with a newer CLI.

## 5. Target user

Someone who has a suspicious Linux binary and wants to know what it does — dropped from a compromised host, pulled from a malware corpus, or being evaluated before deployment. They run `vishaya capture --target ./sample.elf`, get a `.vishaya` file, and inspect it with the CLI.

That's the whole persona. Analyst working on a specific binary, not an ops team monitoring a fleet.

## 6. Non-goals

Explicit, to prevent scope creep:

- Not an EDR. Not a SIEM. Not a fleet monitor.
- No runtime alerting, blocking, or policy enforcement.
- No Windows.
- No cloud dependencies. No SaaS.
- No dashboard or web UI in v1.
- Not aiming to replace Cuckoo, CAPE, Tracee, Stratoshark, or any other existing tool. Different scope, different job.
- No paid dependencies. No LLM/AI integration in v1 (kept as architectural headroom, not core scope).

## 7. Roadmap

Two horizons only. Everything beyond v0.5 is explicitly deferred.

### v0.1 — Conference demo (~60 days)

- `.vishaya` bundle format v0.1 spec — small, deliberately narrow.
- Existing collector emits a bundle instead of streaming NDJSON.
- Minimal CLI: `capture`, `tree`, `files`, `network`, `timeline`.
- Target-scoping via namespace + cgroup wrapper.
- Sample captures from benign test binaries for the demo.

### v0.5 — Actually useful (later)

- Bundle diffing (`vishaya diff a.vishaya b.vishaya`).
- Artifact extraction (dropped files bundled alongside events).
- DNS resolution capture and correlation.
- Integrity hashing built in.
- Single-binary distribution + deb/rpm packages.

### Deferred (architecture allows, but not deciding now)

- LLM / MCP integration
- SCAP interop
- OCSF export
- Extended event families (container context, syscall payload capture)
- Web UI or richer inspection tools
- Sandbox orchestrator adapters

The bundle-versioned + event-family-extensible architecture makes each of these additive rather than rewrites. That's the whole point of getting the foundation right early.

## 8. Success (personal scope)

- The tool is built, works, and produces genuinely useful captures.
- A conference talk is delivered showing it live end-to-end.
- The code is clean, small, and easy to explain to another engineer.
- Deep learning of eBPF, Linux namespaces/cgroups, DFIR workflows, and forensic-format design happens along the way.

That's the whole goal. Not a launch. Not a market entry. A well-built, unique thing worth showing.
