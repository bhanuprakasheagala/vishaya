# Enterprise Features — RETIRED (2026-07)

> **This document is retired. Do not plan from it.**

It described a ~50-feature "path to enterprise adoption" (forensic-integrity, integrations,
analyst-workflow, deployment, compliance clusters). Two things made it the wrong artifact:

1. **It conflicts with the committed direction.** Vishaya is a deliberately **personal-scope,
   minimal** project — a conference/portfolio piece and a scoped forensic *recorder*, not an
   enterprise product a team standardizes on. See [vision.md](vision.md).
2. **It was scope gravity.** A solo maintainer with zero users cannot chase a 50-feature
   enterprise roadmap against funded teams (Falco, Tetragon, Tracee, Sysdig, CAPE). Keeping the
   list around invited exactly the feature-creep that would sink the project. The 2026-07
   positioning research and the honest product review both said: stay ruthlessly narrow.

Some of its ideas were genuinely good and have been **carried forward, re-judged, and
re-prioritized** in the authoritative planning docs:

- **[roadmap-decisions.md](roadmap-decisions.md)** — the attribute-weighted keep/cut/defer verdict on every feature (this is where signing, STIX export, diff, MITRE mapping, YARA, sandbox adapters, viewer, etc. now live with a decision attached).
- **[roadmap.md](roadmap.md)** — v0.1 / v0.5 / v1.0 horizons after the repositioning.
- **[research/2026-07-product-positioning.md](research/2026-07-product-positioning.md)** — why the positioning and priorities changed.

Notably, this doc's "court-admissible provenance / chain-of-custody" framing **overclaimed**:
the current signature is a self-generated local key — tamper-evidence + pinned-key verification,
not third-party attestation. That honest scoping is reflected in [vision.md](vision.md),
[README.md](../README.md), and [bundle-spec-v0.1.md](bundle-spec-v0.1.md); real attestation
(Sigstore/Rekor) is a v1.0 milestone.

The original 526-line plan remains in git history if a specific detail is ever needed.
