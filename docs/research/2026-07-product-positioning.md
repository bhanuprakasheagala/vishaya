# Vishaya Product Positioning — Research Report (2026-07)

## Verdict (executive summary)

The literal "PCAP-for-process-behavior / portable tool-independent capture format" framing is **NOT defensible as stated**, because a standardized, portable, multi-tool syscall capture format already exists and shipped into exactly this niche in January 2026's adjacent timeframe: **`.scap`** (System CAPture), managed by CNCF `libscap`, readable across Sysdig, Falco, and the new **Stratoshark** ("Wireshark-for-syscalls") viewer, and explicitly marketed as "the PCAP-equivalent for system behavior." Aqua Tracee, CAPE, and other sandboxes also already capture the same behavioral scope Vishaya targets (process/file/network), though they emit **loose files or platform-tied directory trees**, not a single self-contained bundle. The genuine, evidence-backed gap Vishaya can own is **not "a capture format" but "a cryptographically verifiable, target-scoped, single-file evidence bundle with chain-of-custody"** — .scap has no Ed25519 signing / manifest / chain-of-custody, existing logical-evidence formats (L01, AFF4-L) have documented integrity weaknesses, and forensic/legal literature treats verifiable custody (not mere capture) as what makes evidence admissible. There is also a fresh, concrete demand signal: recent research (arXiv 2511.04472, CVE-2025-61301 / -61303) shows sandboxes and EDRs silently truncate deeply-nested behavioral reports, validating an append-oriented, robust capture design. **Recommendation: keep the tool, drop the "PCAP-for-process-behavior" tagline, and reposition around "verifiable, portable, target-scoped forensic evidence bundle for a single suspect binary" — signing/chain-of-custody, robustness, and target-scoping are the real differentiators; the "capture format" novelty is not.**

## Findings

See structured findings. Sources are inline. This file mirrors the structured synthesis for future reference.

### 1. A portable, multi-tool syscall/process capture format ALREADY exists (.scap / Stratoshark) — HIGH confidence
`.scap` is an established, standardized syscall-event capture format managed by CNCF `libscap`, read/written by Sysdig CLI, Falco, and Stratoshark. Stratoshark (launched ~Jan 2025, Sysdig+Wireshark) gives a Wireshark-like OFFLINE analysis experience on `.scap`, explicitly for post-incident forensics, and is marketed as bringing "the PCAP experience to system behavior." Captures are portable/offline-readable across tools. This directly overlaps Vishaya's "tool-independent capture file any compatible tool can read offline" positioning at the framing level.
- Caveats: interoperability rests on a shared `libscap`/`libsinsp` lineage (Sysdig origin), not independent implementations against a published spec; `.scap` is host/container-scoped raw syscalls, NOT target-scoped, and has NO signing/manifest/chain-of-custody.
- Sources: cncf.io "From PCAP to SCAP" (2025-01-22); sysdig.com/learn-cloud-native/what-is-an-scap-file; wireshark.org stratoshark(1) man page; falcosecurity/libs.

### 2. Competing capture tools cover Vishaya's behavioral scope but emit loose files / platform-tied trees, not a single portable bundle — HIGH confidence
Aqua Tracee `--capture` writes artifacts (files, executables, kernel modules, BPF bytecode, W+X memory, network) as **loose files into an output directory tree** (default /tmp/tracee, `out` subdir; pcap split by process/command/container). It has **no manifest, no signing, no unified NDJSON event log, no single portable bundle**. CAPE stores results as a **per-task directory tree** (storage/analyses/<task_id>) keyed to CAPE's own IDs, capturing the same behavioral scope (process creation, file ops, errors, process tree, network/DNS/HTTP), and exports multiple report formats (HTML/JSON/MAEC XML/metadata) as separate files — again not one signed bundle. Tracee's network output is standard pcap (portable) but only for packets, not process behavior.
- Sources: aquasecurity.github.io/tracee/latest/docs/flags/capture.1/ (and v0.6.5); aquasec.com blog; capev2.readthedocs.io/en/latest/usage/results.html.

### 3. Interoperability today is achieved by READERS adapting to proprietary formats, not by a shared capture format — HIGH confidence
capa v7.0+ consumes CAPE's JSON, DRAKVUF's drakmon.log, VMRay's zip — each via a bespoke per-sandbox extractor; capa auto-detects the proprietary format and normalizes internally (reader-side abstraction). Adding a new sandbox requires new integration code (e.g. open issue for VMRay). This confirms the ecosystem lacks a shared portable CAPTURE format — supporting Vishaya's premise that one could be valuable, but note MAEC and STIX already occupy the "shared malware-behavior language" role.
- Sources: cloud.google.com/blog Mandiant dynamic-capa-CAPE; mandiant/capa issues #2148, #1517.

### 4. A tool-independent malware-behavior language already exists but is stalled (MAEC → STIX) — HIGH confidence (2-1)
MAEC is a community/MITRE-developed, tool-independent structured language for encoding malware behaviors/artifacts — so the space is NOT wholly unmet. BUT MAEC is effectively frozen (last real push 2020, being migrated into STIX 2.x Malware Object). So a living, thriving, actively-adopted portable behavior format does not dominate — the incumbent is maintenance-mode. Vishaya should EXPORT to STIX/MAEC rather than claim to invent a behavior language.
- Sources: maecproject.github.io/about-maec; maecproject.github.io FAQ.

### 5. The REAL differentiator is verifiable chain-of-custody, which no competitor's capture output provides — HIGH confidence
Chain-of-custody / verifiable integrity (not mere data capture) is foundational to legal admissibility (ISO/IEC 27037, NIST SP 800-86, case law). Existing logical evidence formats (L01, AFF4-L) have DEMONSTRATED integrity weaknesses — no format-level verification values, undetectable metadata manipulation when unencrypted, stress-test failures — and the forensics literature explicitly calls for more advanced, standardized logical image formats. Tracee's capture docs describe NO signing/verification; `.scap` has none either. Vishaya's Ed25519-signed manifest bundle is thus a genuine, defensible gap.
- Sources: sefcom.asu.edu CoC SoK (TPS 2024); sciencedirect S2666281724001355 (DFRWS APAC 2024, L01/AFF4-L); tracee capture docs.

### 6. Fresh demand signal: sandboxes/EDRs silently truncate deeply-nested behavioral reports — HIGH confidence
"Telemetry Complexity Attacks" (arXiv 2511.04472) empirically shows recursive process spawning produces telemetry exceeding serialization limits (JSON/BSON nesting ~100 levels, MongoDB 16MB docs), causing silent truncation/rejection of behavioral reports in CAPEv2, Cuckoo, Wazuh, Velociraptor, Recorded Future Triage (CVE-2025-61301, CVE-2025-61303). This validates an append-oriented, robust NDJSON capture design that avoids monolithic nested documents — a concrete robustness angle for a talk. (Note: the specific "persist-to-forensic-store as mitigation" framing was refuted 1-2; use the truncation problem itself, not that specific mitigation claim.)
- Sources: arxiv.org/html/2511.04472v3; NVD CVE-2025-61301 / -61303.

---

## 7. Positioning recommendation

**Drop the "PCAP-for-process-behavior" tagline.** It is now the *literal marketing line* of `.scap`/Stratoshark (CNCF, Sysdig+Wireshark). Leading with it invites a direct, losing comparison to an incumbent backed by two established projects.

**Reposition around the three things no competitor combines:**

> **Vishaya — a verifiable, portable, target-scoped forensic evidence bundle for a single suspect Linux binary.**

- **Verifiable** (chain-of-custody) — the real, evidence-backed gap. `.scap`, Tracee `--capture`, CAPE dirs: none sign their output. *This is the headline, not a footnote.*
- **Target-scoped** — one binary + descendants via cgroup, not host/container-wide (.scap) or fleet-wide (Falco/Tetragon). A capture is a *case*.
- **Single self-contained bundle** — vs Tracee's loose file tree and CAPE's per-task directory keyed to its own IDs.

Supporting talk narrative (fresh, 2025-26, defensible): **robustness against telemetry-truncation attacks.** Sandboxes/EDRs silently drop deeply-nested behavioral reports (arXiv 2511.04472, CVE-2025-61301/-61303); Vishaya's flat, append-only NDJSON has no nesting limit to exploit. This retroactively justifies the NDJSON choice (backlog C-04) as a *security property*, not just readability.

**Caveat that must be fixed for the headline to be honest:** today's signature is a locally self-generated key whose public half travels inside the bundle (backlog M1) — tamper-*evidence*, not attestation. Until the chain-of-custody is hardened, "verifiable" is overclaiming. See §8 "Add".

## 8. Keep / Cut / Add — mapped to roadmap + backlog + vision

**KEEP & PROMOTE TO CENTERPIECE (research-backed differentiators):**
- Ed25519 signing + chain-of-custody (backlog A-03 / R2-02) — this is the *product*, not a Wave-1 checkbox. Move it to the front of vision.md.
- Target-scoping via cgroup — already core; lean on it harder in positioning.
- Single-bundle + append-only NDJSON — keep; reframe NDJSON as anti-truncation robustness.
- STIX 2.x export (adjust backlog B-02/F-01 from OCSF-first to **STIX/MAEC-first**) — interop today is reader-side (capa writes a bespoke extractor per sandbox); the lingua franca for *malware behavior* is STIX/MAEC, not OCSF. Export to it; do not invent a behavior language.

**CUT or keep DEFERRED (crowded or low-value per research):**
- The "PCAP-for-process-behavior" reframe (backlog I-02) — **reject**; it's `.scap`'s line.
- "Invent/own a portable behavior *format*" as the core novelty — **drop**; .scap + MAEC/STIX already occupy it. The novelty is *verifiability + scoping*, not the format.
- SCAP interop / embedding `.scap` (roadmap v2.0) — **defer indefinitely**; competing on .scap's turf, low payoff.
- MCP server + LLM summaries (roadmap v2.0) — **keep deferred**; research reinforces this is not where the gap is.
- Web UI (roadmap v1.0) — **downgrade**; Stratoshark already delivers "Wireshark-for-syscalls." A viewer is table-stakes, not a standout; a small static/TUI viewer is fine but not a priority.

**ADD (missing entirely):**
- **Make chain-of-custody real** (extends A-03/M1): sign the *whole* manifest (not just the two content hashes), print the pubkey fingerprint at capture time for out-of-band recording, add `vishaya verify` with a loud verdict, support pinned/trusted keys, and put Sigstore/Rekor keyless attestation on the roadmap as the v1.0 credibility milestone.
- **Anti-truncation robustness** as an explicit design tenet + test (tie to the G-group load test): demonstrate a recursive fork-bomb-ish target whose capture stays valid where a nested-JSON sandbox would truncate.
- **STIX 2.x Malware/Observed-Data export** as a first-class `vishaya export --format stix` (bridges into existing DFIR pipelines instead of asking them to adopt a new format).

## 9. Differentiators for a first release + conference talk

1. **"Signed evidence, not just telemetry."** Live demo: capture → `verify` shows ✓; tamper one byte → ✓ integrity catches it; re-hash the manifest → ✗ signature catches it. No other open eBPF capture tool can show this.
2. **"One file, one case."** Contrast on screen: Tracee's `/tmp/tracee/out/...` tree and CAPE's `storage/analyses/<id>/` vs a single portable `curl.vishaya`.
3. **"The report that can't be truncated."** The telemetry-complexity-attack angle — timely (2025-26 CVEs), technical, and it makes the humble NDJSON choice look deliberate and smart.
4. **Target-scoped, not fleet-wide** — a capture is a suspect's case file, not a firehose.

## 10. Open questions & honest caveats

- **Demand is partly inferred, not proven.** The research found strong evidence that the *gap exists* (no signed, scoped, single-file capture) but weaker direct evidence that DFIR analysts are actively *asking* for it. Treat this as a "build it well and show it" bet — appropriate for a personal/conference project, risky as a startup thesis.
- **The moat is one feature deep.** If `.scap`/libscap adds signing, much of the "verifiable capture" edge erodes. Target-scoping + single-bundle + the DFIR case-file workflow are the more durable differentiators; don't rest solely on signing.
- **Consistency debt:** `README.md`, `docs/vision.md`, and the `project-direction` memory currently all lead with the now-deprecated PCAP framing (the README was rewritten around it *before* this research). They need updating if this repositioning is accepted.
- **Verified-but-narrow:** several competitor claims were killed in verification (Tracee is not primarily a malware/DFIR tool; Tracee pcap ≠ decoded app-layer; MAEC's "agnostic" claim is aspirational). The competitive read here is deliberately conservative.

## Method & provenance
Generated by the deep-research workflow (2026-07): 5 angles → 21 sources fetched → 91 claims extracted → 25 adversarially verified (3-vote), 21 confirmed / 4 killed. Full source list and per-claim votes in the workflow task output. Confidence on the core verdict (PCAP framing not defensible; chain-of-custody is the gap): **high**.
