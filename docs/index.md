# Vishaya Documentation

> **In a hurry?** [**Build it and run your first capture**](getting-started.md) — that's the
> whole path. Everything else here is depth to reach for *when you need it*, not required reading.

## What do you want to do?

| Your goal | Go straight to |
|---|---|
| **Try it now** — build, capture, inspect | [getting-started.md](getting-started.md) |
| **Decide if it fits** — what it is, what it deliberately isn't | [vision.md](vision.md) |
| **Read a `.vishaya` file / write your own reader** | [bundle-spec-v0.1.md](bundle-spec-v0.1.md) |
| **Something broke** | [troubleshooting.md](troubleshooting.md) |
| **Check what's shipped vs planned** | [roadmap.md](roadmap.md) |

That's all most people need. The rest below is optional depth.

## Everything else (read only the row you need)

| Doc | What's in it | Reach for it when… |
|---|---|---|
| [getting-started.md](getting-started.md) | install, build, first capture + inspect | …always — start here |
| [vision.md](vision.md) | scope, the three real differentiators, non-goals | …deciding whether to use it |
| [bundle-spec-v0.1.md](bundle-spec-v0.1.md) | the authoritative `.vishaya` format contract | …building or validating a reader |
| [event-reference.md](event-reference.md) | every event family + kind, with JSON schemas | …you need field-level detail |
| [troubleshooting.md](troubleshooting.md) | common build/capture/inspect failures + fixes | …something doesn't work |
| [roadmap.md](roadmap.md) | shipped / next / permanently out of scope | …evaluating longevity |
| [concepts.md](concepts.md) | primer: eBPF, cgroups, namespaces, NDJSON, DFIR | …you're new to the stack *(optional)* |
| [architecture.md](architecture.md) | design, module map, isolation model, decisions | …changing or reviewing the code *(optional)* |
| [flow.md](flow.md) | capture & inspect paths as sequence diagrams | …tracing the code path *(optional)* |
| [glossary.md](glossary.md) | terms & acronyms used across docs and code | …you hit an unfamiliar term |

<sub>Filenames are lowercase-with-hyphens. Building a reader? The two you want are
[bundle-spec-v0.1.md](bundle-spec-v0.1.md) then [event-reference.md](event-reference.md).</sub>
