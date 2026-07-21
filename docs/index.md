# Vishaya Documentation

Everything you need, in a suggested reading order. All docs use lowercase filenames with hyphens.

## Start here

- **[getting-started.md](getting-started.md)** — install dependencies, build, run your first capture, inspect the bundle. Aim for this before reading anything else.

## Understand the why

- **[vision.md](vision.md)** — the product north star: what Vishaya is, what it deliberately isn't, and what problem it solves that no existing Linux tool cleanly does.
- **[concepts.md](concepts.md)** — background primer. eBPF, cgroups v2, Linux namespaces, DFIR terminology, tar+zstd, and how forensic capture differs from EDR/SIEM. Written for readers new to any of these.
- **[roadmap.md](roadmap.md)** — what's shipped in v0.1, what's coming in v0.5 and v1.0+, and what's permanently out of scope.
- **[enterprise-features.md](enterprise-features.md)** — detailed plan for the features that move Vishaya toward enterprise adoption: forensic integrity, analyst tooling, ecosystem integrations, deployment, compliance.
- **[backlog.md](backlog.md)** — working tracker for review findings and follow-up work. Status per item (open/in-progress/done/deferred/rejected). Update as you go.

## Understand the how

- **[architecture.md](architecture.md)** — the v0.1 design: module layout, dependency graph, design decisions with rationale, Session state machine.
- **[flow.md](flow.md)** — end-to-end sequence diagrams for the capture and inspect paths. Read after architecture.md.
- **[code-walkthrough.md](code-walkthrough.md)** — module-by-module tour of every part of the codebase, from the kernel BPF probes up through the CLI dispatcher.
- **[build.md](build.md)** — CMake structure, library dependency graph, external deps, and how to add a new module or dependency.

## Reference material

- **[bundle-spec-v0.1.md](bundle-spec-v0.1.md)** — authoritative specification for the `.vishaya` bundle format. What compliant writers must produce and readers must accept.
- **[event-reference.md](event-reference.md)** — every event family and kind, with the JSON schema, semantics, and origin (which BPF probe emits it).
- **[glossary.md](glossary.md)** — alphabetical reference for terms and acronyms used across the docs and code.

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

**Evaluating Vishaya for enterprise adoption?**
vision.md → getting-started.md → enterprise-features.md → roadmap.md

**Just curious what all this is about?**
vision.md → concepts.md → flow.md
