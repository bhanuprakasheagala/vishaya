# Roadmap & Backlog — Feature Decisions (2026-07)

A deliberate, attribute-weighted pass over **every** backlog item (A-01…I-02) and roadmap
feature, deciding what earns a place in the product and what doesn't.

**This is the single authoritative tracker for status and priority.** The verdict table
below is the source of truth for what is DONE / KEEP-v0.5 / KEEP-v1.0 / DEFER / CUT.
[`backlog.md`](backlog.md) is a *detailed reference archive* — it holds the in-depth
per-item analysis (problem, fix approach, target files) but no longer tracks status; the
`STATUS | PRIORITY | EFFORT` token under each backlog heading is the original triage
snapshot, superseded by the table here.

## How each item was judged

Weighed together, not by any single axis:

- **User value** — does a DFIR / malware analyst actually benefit, and how often?
- **Positioning fit** — does it strengthen *verifiable + target-scoped + single-file evidence*? (per [research/2026-07-product-positioning.md](research/2026-07-product-positioning.md))
- **Differentiation** — a moat, or a commodity/checkbox anyone has?
- **Effort** — S (≤1wk) / M (1-3wk) / L (3wk+).
- **Complexity & maintenance risk** — ongoing burden, footguns, scope creep.
- **Minimalism** — the product is deliberately small; every feature must earn its surface area.

Verdicts: **DONE**, **KEEP-v0.5**, **KEEP-v1.0**, **DEFER** (real, revisit later), **CUT** (low value / poor fit).

---

## Verdict table

| ID | Feature | Value | Effort | Verdict | Rationale (short) |
|---|---|---|---|---|---|
| A-03/D-03 | Chain-of-custody signing | High | M | **DONE** | Headline. Manifest-signed + `verify` + pin shipped (R2-13); Sigstore = v1.0. |
| A-05 | Security-boundary honesty (docs) | High | S | **DONE** | Applied to vision/README/spec this session. Trust = credibility. |
| B-01 | Sharpen competitive framing | Med | S | **DONE** | Covered by the repositioning. |
| H-01..H-04 | Doc updates (honesty, caveats, spec) | Med | S | **DONE** | Landed across the review passes. |
| C-04 | Binary event format | — | — | **CUT (kept)** | NDJSON is now a *robustness* feature (anti-truncation), not a weakness. |
| I-02 | "PCAP-for-process-behavior" pitch | — | — | **CUT** | It's `.scap`'s own line; repositioned. |
| — | **Artifact capture** (dropped files) | High | M | **DONE (v0.5)** | Shipped: `--capture-artifacts` copies created/modified files into `artifacts/<sha256>`, indexed by `artifacts.json`, integrity-verified by `verify`; `vishaya artifacts` lists them. Schema 0.2.0. v0.2 = end-of-capture snapshot (created-then-deleted recorded as `missing_at_finalize`); copy-on-close deferred. Unblocks YARA. |
| B-03 | `--normalize` (determinism) | High | M | **KEEP-v0.5** | Genuine differentiator ("nobody has this"); makes diff meaningful; a forensic property. |
| D-02 | Semantic `diff` | High | M | **DONE (v0.5)** | Shipped: `vishaya diff` compares behaviour sets (execs/files/DNS/HTTP/endpoints); normalizes identifiers by construction. |
| B-02→STIX | STIX 2.x export | High | M | **KEEP-v0.5** | Bridge to CTI/DFIR pipelines; export to the lingua franca, don't invent one. |
| E-02 | Plaso/MACtime CSV export | Med | S | **KEEP-v0.5** | Cheap; meets DFIR analysts in log2timeline. Complements STIX (timeline vs CTI). |
| G-02 + A-02 | TLS-uprobe HTTPS plaintext (+iovec) | High | L | **KEEP-v0.5** | Decrypted C2 is a headline malware-analysis capability; A-02 is its prerequisite. |
| D-01 (Py) | Python reader SDK | High | S–M | **KEEP-v0.5** | ~Cheap (tar+zstd+json); turns the format into a substrate (research finding #3). |
| I-01 | Publish the spec independently | Med | S | **KEEP-v0.5** | "Two readers make it a format." Supports tool-independence + the SDK. |
| — | **Packaging** (static binary, deb/rpm) | High | M | **KEEP-v0.5** | "Install a binary, run it." Adoption + distribution. |
| — | **`summary` view + trust header** | High | S–M | **DONE (v0.5)** | Shipped: `vishaya summary` — one-screen trust + target + counts + tree + network + files. |
| — | **Sample `.vishaya` fixtures** | High | S | **DONE (tooling)** | `samples/` + `.gitignore` + docs wired; user generates+commits on the VM once. |
| A-01 | Lossy-mode contract in spec | Med | S | **KEEP-v0.5** | Document `events_dropped>0 = reduced confidence`; honesty. (Drop counts already surfaced.) |
| C-03a | Syscall arch doc note | Low | S | **KEEP-v0.5** | Trivial correctness/clarity in event-reference. |
| A-01 | Proactive BPF rate-limiting | Low | M | **CUT** | Honest drop reporting + dedup cover the need; kernel complexity not worth it. |
| B-02 | MISP export | Low | M | **CUT** | STIX already covers CTI interchange; MISP is narrower, extra surface. |
| D-01 (Rust) | Rust reader SDK | Low | M | **CUT** | YAGNI — no perf-sensitive consumer exists. Revisit only on real demand. |
| F-05 | Interactive TUI reader | Low | L | **CUT** | `summary` + one-shot CLI covers hands-on use at far lower cost; adds a UI dep. |
| B-04/F-03 | Sandbox adapter (CAPE/Cuckoo export) | Med | M | **KEEP-v1.0** | Real distribution channel; do after the core case-file story is solid. |
| D-04 | MITRE ATT&CK mapping | High | L | **KEEP-v1.0** | "Demo → analyst tool" lever; genuinely used. Large; start with a small starter ruleset. |
| E-01 | YARA on artifacts/payloads | Med–High | M | **KEEP-v1.0** | Core DFIR IOC matching; needs artifact capture first. |
| C-02 | Path resolution (/proc/fd; d_path) | Med–High | M | **KEEP-v1.0** | fd-relative paths are garbage today; real for advanced malware. /proc/fd part first. |
| A-04 | Container awareness on events | Med | M | **KEEP-v1.0** | Matters when the target spawns nested containers; envelope fields partly exist. |
| A-06 | Semantic dedup (count/duration_ns) | Med | M | **DEFER** | Nice info-preserving compression for noisy targets; off-by-default; not first-release. |
| E-04 | Container-native capture (attach) | Med | M | **DEFER** | Extends the model from launch→attach; real but a later scope expansion. |
| C-01/G-01 | LSM BPF for file ops | Med | L | **DEFER** | ABI-stability/dentry upgrade; tracepoint path works; needs CONFIG_BPF_LSM. |
| E-03 | Bundle `merge` | Low–Med | M | **DEFER** | Real for chained droppers, but niche; revisit if users hit it. |
| G-03 | `--follow-exec-into` | Low | M | **DEFER** | cgroup inheritance already covers the common case; document the edge. |
| F-04 | Static single-file HTML viewer | Med | M | **DEFER (small)** | Supports "share one file with non-analysts"; keep *small*, after core. Not a Stratoshark competitor. |
| F-02 | MCP server | Med | L | **DEFER-v2** | No AI in v1 (committed direction); structured bundle is a good future substrate. |
| — | LLM summarization | Low | L | **DEFER-v2** | Same; best-effort AI is not the product. |
| — | SCAP interop / embed `.scap` | Low | M | **CUT** | Competing on the incumbent's turf; no payoff. |
| — | Schema freeze | — | — | **KEEP-v1.0** | The moment third parties can rely on `.vishaya`. Milestone, not a feature. |
| — | Sigstore/Rekor attestation | High | L | **KEEP-v1.0** | Turns tamper-evidence into third-party-verifiable provenance (the A-03 remainder). |

---

## Audit items (Review-2 / Review-3 / in-depth static review)

Code-audit findings (not features). Detailed write-ups live in [backlog.md](backlog.md)
(R2-01…R2-13, R3-remaining). Status:

- **Done:** R2-01…R2-06, R2-08, R2-10; R2-11/C1 (BPF 512-byte stack), R2-12/H1
  (sendmmsg/recvmmsg offsets), R2-13/P2 (chain-of-custody: manifest signing + `verify` +
  `--verify-key`). Plus the 2026-07 in-depth-review fixes: non-UTF-8 event-drop, `tree`
  cycle/recursion guard, PID-reuse enrichment guard, per-event inspect resilience, TCP-DNS
  gate, hostile-bundle `BundleError` wrapping, base64 hardening, `verify` pinned-key display.
- **Deferred (no release blockers):** R2-07 (PID/TGID-reuse tree merge), R2-09 (canonical
  events.ndjson sort at write), R3 H2 (socket_fd per-tgid misses forked children), R3 H3
  (32-bit target msghdr/iovec), and the scalability/hardening notes (whole-file `verify`
  RAM, ustar 8 GiB cap, `cgroup.procs` single-write, child argv fork-malloc, enrichment
  back-pressure).

---

## The notable calls, explained

**What's genuinely CUT (little/no value for the cost):**
- **TUI reader (F-05), Rust SDK, MISP export, proactive BPF rate-limiting, SCAP interop.** Each is either duplicated by a cheaper feature (TUI ← summary+CLI; MISP ← STIX; rate-limiting ← honest drop reporting), a YAGNI (Rust SDK), or a bad-fit fight (SCAP). Cutting them keeps the surface small.

**What's ELEVATED (adds the most product value, wasn't prominent):**
- **`summary` view + trust header, sample fixtures, packaging.** These are what move it from "a project that emits events" to "a product an analyst reaches for." They're mostly cheap and high-impact — and the summary + samples directly serve the "product not project" feeling.

**What earns its keep but is genuinely later (DEFER):**
- Dedup, attach-mode capture, LSM BPF, merge, follow-exec, HTML viewer, MCP/LLM. All real, none first-release, several conditional on demand. Kept on the map, off the near path.

**The v0.5 core (verifiable case-file that's genuinely useful):**
Artifact capture • `--normalize` + `diff` • STIX + Plaso export • HTTPS-via-uprobe (+iovec) • Python SDK • summary/trust-header • samples • packaging • spec published. That set makes a scoped, signed, shareable, analyzable case file — the product the positioning promises.

## Doc-hygiene follow-up

- ✅ **`docs/enterprise-features.md` retired (2026-07)** — replaced with a short stub pointing
  here; its still-valid ideas are captured in the verdict table above; `docs/index.md` updated.
  The original 526-line plan is in git history. It conflicted with the personal-scope/minimal
  direction and was scope gravity.
