# Vishaya Documentation

Everything you need, in a suggested reading order. All docs use lowercase filenames with hyphens.

## Start here

- **[getting-started.md](getting-started.md)** — install dependencies, build, run your first capture, inspect the bundle. Aim for this before reading anything else.

## Understand the why

- **[vision.md](vision.md)** — the product north star: what Vishaya is, what it deliberately isn't, and what problem it solves that no existing Linux tool cleanly does.
- **[concepts.md](concepts.md)** — background primer. eBPF, cgroups v2, Linux namespaces, DFIR terminology, tar+zstd, and how forensic capture differs from EDR/SIEM. Written for readers new to any of these.
- **[roadmap.md](roadmap.md)** — what's shipped in v0.1, what's coming in v0.5 and v1.0+, and what's permanently out of scope.
- **[roadmap-decisions.md](roadmap-decisions.md)** — the authoritative, attribute-weighted keep/cut/defer verdict on every feature. **The single tracker for status and priority** (features + R2/R3 audit items).
- **[research/2026-07-product-positioning.md](research/2026-07-product-positioning.md)** — the positioning research behind the current direction (why the framing and priorities are what they are).
- **[backlog.md](backlog.md)** — detailed reference archive: the in-depth per-item analysis (problem, fix approach, target files) behind each review finding. Status/priority live in roadmap-decisions.md, not here.
- *(retired: `enterprise-features.md` — superseded by roadmap-decisions.md; kept only as a stub.)*

## Understand the how

- **[architecture.md](architecture.md)** — the v0.1 design: module layout, dependency graph, design decisions with rationale, Session state machine.
- **[flow.md](flow.md)** — end-to-end sequence diagrams for the capture and inspect paths. Read after architecture.md.
- **[code-walkthrough.md](code-walkthrough.md)** — module-by-module tour of every part of the codebase, from the kernel BPF probes up through the CLI dispatcher.
- **[build.md](build.md)** — CMake structure, library dependency graph, external deps, and how to add a new module or dependency.

## Reference material

- **[bundle-spec-v0.1.md](bundle-spec-v0.1.md)** — authoritative specification for the `.vishaya` bundle format. What compliant writers must produce and readers must accept.
- **[event-reference.md](event-reference.md)** — every event family and kind, with the JSON schema, semantics, and origin (which BPF probe emits it).
- **[glossary.md](glossary.md)** — alphabetical reference for terms and acronyms used across the docs and code.

## Verify a build

- **[verification-v0.2.md](verification-v0.2.md)** — manual acceptance checklist to run after building on the VM: confirms the v0.2 changes (artifact capture + review fixes) are present and working, with copy-paste commands and PASS criteria. The fast path is `sudo ./tests/run-tests.sh`; this doc is for eyeballing each new behavior.

## When things break

- **[troubleshooting.md](troubleshooting.md)** — common failures at build, capture, and inspect time, with concrete fixes and debug steps.

## Suggested paths by audience

**Just want to try it?**
getting-started.md → (if it fails: troubleshooting.md)

**Analyst evaluating whether to use it?**
vision.md → getting-started.md → event-reference.md → bundle-spec-v0.1.md → roadmap.md

**Contributor / hacker?**
concepts.md → architecture.md → flow.md → code-walkthrough.md → build.md → (glossary.md as reference)

**Building a third-party tool that reads `.vishaya` files?**
bundle-spec-v0.1.md → event-reference.md → glossary.md

**Understanding the direction / what's planned?**
vision.md → research/2026-07-product-positioning.md → roadmap.md → roadmap-decisions.md

**Just curious what all this is about?**
vision.md → concepts.md → flow.md
