# Glossary

Terms and acronyms that appear across Vishaya's docs and code. Alphabetical. Cross-references in *italics*.

**ABI (Application Binary Interface).** The contract for how compiled code interacts: struct layouts, calling conventions, symbol names. Vishaya's shared *event schema* is an ABI between the *BPF* probes and userspace.

**Aggregator.** `bpf/vishaya.bpf.c` — the file that `#include`s the four probe files so they compile as one BPF translation unit.

**Attack surface.** Everything an attacker can reach or influence. Vishaya reduces its own attack surface by needing root only for `capture`, running no daemon, and having no network listeners.

**BPF (Berkeley Packet Filter).** Historically a packet filtering VM; modern usage means *eBPF*, the general-purpose in-kernel VM.

**Bundle.** A single `.vishaya` file produced by a capture. Contains the manifest, event stream, process tree, and (v0.5+) artifacts. Portable across hosts and tool versions within the schema major.

**BTF (BPF Type Format).** Debug info the kernel exports about its own struct layouts, at `/sys/kernel/btf/vmlinux`. Vishaya uses it via *CO-RE* to make one BPF object work across kernel versions.

**Capture.** A single Vishaya run that observes one target process and produces one bundle. Distinguished from monitoring (continuous, fleet-wide).

**C2 / C&C (Command and Control).** The server that malware phones home to for instructions.

**Cgroup (control group).** Linux kernel feature for grouping processes. Vishaya uses *cgroup v2* to define the boundary of "the target and its descendants" for filtering.

**Cgroup v2.** The unified cgroup hierarchy. All cgroups live under `/sys/fs/cgroup/`; each cgroup is a directory. Contrast with legacy cgroup v1 (per-controller hierarchies).

**Cgroup ID.** The kernel-assigned identifier for a cgroup. Vishaya reads it from `stat().st_ino` on the cgroup directory and gives it to BPF via `bpf_get_current_cgroup_id()`.

**CO-RE (Compile Once, Run Everywhere).** eBPF portability technique: the compiled BPF object references struct fields symbolically, and libbpf relocates them at load time using the target kernel's *BTF*.

**Collector.** The inherited `vishaya::collector` code that loads BPF, attaches probes, and polls the ring buffer. Historically the pre-pivot codebase.

**CSIRT (Computer Security Incident Response Team).** An organizational unit that does *IR*.

**Detonate / detonation.** Running suspicious code in a sandbox to observe its behavior. Vishaya "detonates" a target during capture.

**DFIR (Digital Forensics and Incident Response).** The discipline of investigating security incidents after they occur. Vishaya's primary target audience.

**EDR (Endpoint Detection and Response).** Continuous monitoring tools like CrowdStrike, SentinelOne. Different job from Vishaya — see [vision.md](vision.md).

**Enricher.** The `vishaya::collector::Enricher` — reads `/proc` to fill in fields BPF couldn't populate (long cmdlines, exec paths, cwd).

**Envelope.** The common JSON fields on every event: `ts_ns`, `family`, `kind`, `pid`, `tgid`, `ppid`, `uid`, `gid`, `comm`, `data`.

**Event.** A single record captured from the kernel — one syscall, one process lifecycle change, etc. Serialized to one JSON line in `events.ndjson`.

**Family.** One of the top-level event categories: `process`, `file`, `network`, `syscall`. See [event-reference.md](event-reference.md).

**Fork / exec.** The Linux process creation dance. `fork()` duplicates the current process; `execve()` replaces the duplicate's memory with a new binary. Vishaya's [target_launch.cpp](../src/isolation/target_launch.cpp) uses this pattern.

**IOC (Indicator of Compromise).** A specific artifact (file hash, IP, domain, YARA rule) that says "this thing was touched by known-bad activity."

**IR (Incident Response).** The active investigation and containment of a security incident.

**Isolation.** The boundary Vishaya puts around the target: *cgroup* v2 for filtering, *mount namespace* for filesystem isolation. Documented in [architecture.md §6](architecture.md).

**Kind.** The specific event subtype within a *family*. E.g., `family: process, kind: exec`.

**libbpf.** The C library for interacting with eBPF from userspace: loading, attaching, ring-buffer polling. Vishaya wraps it inside `vishaya::collector`.

**Manifest.** The `manifest.json` file inside a bundle. Carries schema version, tool version, capture metadata, coverage info, event counts, integrity hashes.

**Mount namespace.** Linux namespace that isolates a process's view of mounted filesystems. Vishaya uses `unshare(CLONE_NEWNS)` in the child before exec to prevent target mounts from leaking.

**NDJSON (Newline-Delimited JSON).** One complete JSON object per line, no wrapping array. Vishaya's `events.ndjson` format.

**PID vs TGID.** In Linux, "process" and "thread" are the same kernel object (`task_struct`). `pid` is the thread ID; `tgid` is the thread-group ID, which is what userspace usually calls a "process ID." A single-threaded process has `pid == tgid`.

**Probe.** A BPF program attached to a kernel tracepoint. Vishaya has one per syscall (or lifecycle event) it cares about.

**Protocol decoder.** Userspace module that parses captured network payload bytes into structured DNS or HTTP events. See [protocol_decoder.cpp](../src/capture/protocol_decoder.cpp).

**Ring buffer.** BPF map type optimized for kernel→userspace event streaming. Vishaya uses a 16 MiB ring buffer for all events.

**SIEM (Security Information and Event Management).** Log aggregation/search tools like Splunk, Elastic. Different job from Vishaya — see [vision.md](vision.md).

**Sample.** A specific piece of malware being analyzed.

**Sandbox.** An isolated environment for running suspicious code. Vishaya provides light isolation (namespace + cgroup); heavier options include VMs (DRAKVUF) or specialized hypervisors.

**SCAP file.** Sysdig's binary capture format for system call streams. Interoperable via *Stratoshark*. Vishaya may embed a `.scap` inside a `.vishaya` in v2.0 for interop.

**Schema major.** The X in `schema_version: X.Y.Z`. Bundles with major > reader's major are rejected. Bundles with major ≤ reader's major are accepted; unknown fields are ignored.

**Session.** The `vishaya::capture::Session` class — one instance per capture, wraps the BPF load/attach lifecycle and event pipeline.

**Streaming reader.** A bundle consumer that reads the tar sequentially rather than extracting everything first. Vishaya's `Reader` supports this pattern (manifest parsed first without extracting events).

**Synchronization pipe.** The pipe Vishaya's `launch_target` uses to make the child wait until the parent has attached it to the cgroup.

**Synthesized event.** An event Vishaya's *protocol decoder* produces from captured payload, not directly emitted by BPF. Currently: `dns-query`, `dns-answer`, `http-request`, `http-response`.

**Target.** The binary Vishaya is capturing. Passed as `--target <path>` to `vishaya capture`.

**Target cgroup.** The cgroup Vishaya creates and puts the target (and its descendants) into. Its ID is used by BPF probes to filter events.

**Tracepoint.** A stable in-kernel hook for observability. Vishaya attaches BPF programs to tracepoints like `sched/sched_process_exec`, `syscalls/sys_enter_openat`, etc.

**TTP (Tactics, Techniques, and Procedures).** Higher-level than IOCs; describes how an attacker operates. Catalogued by MITRE ATT&CK.

**WAL (Write-Ahead Log).** The `events.ndjson` file in the scratch dir. Written line-by-line during capture, packaged into the bundle at finalize.

**Verifier.** The kernel component that validates eBPF programs before load. Rejects programs with unbounded loops, arbitrary memory access, or undefined behavior. Strict; many BPF idioms are shaped by verifier requirements.

**Vishaya (विषय).** Sanskrit for "the subject-matter of investigation." The name of this project and its bundle file format.

**Zstd.** Zstandard, Facebook's compression algorithm. Gzip-quality compression at 2-5× the speed. Used to compress Vishaya bundles.
