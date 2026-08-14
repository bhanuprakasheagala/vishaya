# Getting Started

A hands-on first contact with Vishaya: install deps, build, capture, inspect. About 15 minutes if your Linux host is already set up.

## What you need

- A Linux host (kernel 5.15+ recommended; must have eBPF + BTF)
- Root access (needed for `vishaya capture`; inspection needs no privileges)
- A modern C++ toolchain and a handful of libraries listed below

Vishaya is Linux-only by design. It won't build or run on macOS or Windows. WSL2 works if the WSL kernel has BTF (recent Windows 11 does).

## Quick preflight

```bash
./scripts/linux.sh check
```

This prints your kernel version and architecture, verifies the tools it needs (gcc, cmake, clang, bpftool, pkg-config), confirms `/sys/kernel/btf/vmlinux` is readable, and prints a distro-specific package-install hint if anything's missing.

## Install dependencies

Pick the line for your distro:

```bash
# Debian / Ubuntu
sudo apt install build-essential cmake clang llvm pkg-config \
    libelf-dev libbpf-dev bpftool \
    libzstd-dev libarchive-dev nlohmann-json3-dev libcli11-dev libssl-dev

# Fedora / RHEL
sudo dnf install gcc-c++ cmake clang llvm pkgconf elfutils-libelf-devel \
    libbpf-devel bpftool \
    libzstd-devel libarchive-devel json-devel cli11-devel openssl-devel

# Arch
sudo pacman -S base-devel cmake clang llvm pkgconf libelf libbpf bpftool \
    zstd libarchive nlohmann-json cli11 openssl
```

## Build

```bash
./scripts/linux.sh all
```

That does two things: builds the userspace binaries via CMake, then compiles the BPF probes into `bpf/vishaya.bpf.o` using clang.

You'll get three binaries in `build/`:

- **`vishaya`** — the primary product. `capture` + inspect subcommands.
- **`isolation_probe`** — standalone smoke test for the cgroup + namespace subsystem. Useful for debugging isolation issues without loading BPF.
- **`bundle_probe`** — standalone smoke test for the bundle writer. Produces a small synthetic `.vishaya` file from a hand-crafted 3-event stream.

## Your first capture

```bash
sudo ./build/vishaya capture \
    --target /usr/bin/curl \
    --output /tmp/curl.vishaya \
    -- https://example.com
```

Anatomy of that command:

- `sudo` — capture needs root (eBPF probe attach + cgroup v2 write).
- `--target /usr/bin/curl` — the binary Vishaya will launch and observe. Must be an absolute path.
- `--output /tmp/curl.vishaya` — where the bundle will be written.
- Everything after `--` — arguments passed to the target binary (in this case, curl's URL).

To also copy the files the target created or modified into the bundle, add
`--capture-artifacts` (off by default). They're stored content-addressed under
`artifacts/`, hashed, and integrity-checked by `verify`. Bounds are adjustable:
`--artifact-max-size`, `--artifact-max-total`, `--artifact-max-count`. Note the
v0.2 limitation: files the target creates **and deletes** during the run are
recorded (as `missing_at_finalize`) but their bytes are not extracted.

What Vishaya does under the hood:

1. Creates a fresh cgroup at `/sys/fs/cgroup/vishaya-<uuid>` (root required).
2. Creates a scratch working directory at `/tmp/vishaya-capture-<uuid>/`.
3. Loads the BPF probes into the kernel and attaches them to process, file, and network syscall tracepoints.
4. Writes the cgroup ID into a BPF map, activating target-scoped filtering (probes now drop events from any other cgroup).
5. Forks a child, attaches the child to the cgroup, unshares a mount namespace, execs `/usr/bin/curl https://example.com` in the child.
6. Polls the BPF ring buffer while the target runs, decoding events and appending them to `events.ndjson` in the scratch dir.
7. When curl exits, drains the ring buffer, reconstructs the process tree, computes integrity hashes, **signs the canonical manifest** (Ed25519), builds the manifest, packs everything into a tar+zstd archive at `/tmp/curl.vishaya.tmp`, fsyncs, and atomic-renames to `/tmp/curl.vishaya`.
8. Cleans up the cgroup and scratch dir.

You'll see stderr log lines showing each step and a final `bundle: /tmp/curl.vishaya`.

## Inspect the bundle

None of the inspect subcommands need root — the bundle is a plain file you can read anywhere.

```bash
./build/vishaya summary   /tmp/curl.vishaya    # start here
./build/vishaya tree      /tmp/curl.vishaya
./build/vishaya files     /tmp/curl.vishaya
./build/vishaya network   /tmp/curl.vishaya
./build/vishaya timeline  /tmp/curl.vishaya
./build/vishaya verify    /tmp/curl.vishaya    # integrity + signature verdict
./build/vishaya diff      run-a.vishaya run-b.vishaya  # what changed between two runs
./build/vishaya artifacts /tmp/curl.vishaya    # files the target dropped/modified
```

- **`summary`** — the one-screen verdict: trust status (integrity + signature), target, event counts, a shallow process tree, notable DNS/HTTP/endpoints, and files created/deleted/renamed. Reach for it first.
- **`tree`** prints the process lineage rooted at your target, with commands and exit codes.
- **`files`** prints every file operation (openat / unlinkat / renameat2) with PID, command name, operation, return value, and path.
- **`network`** prints every network event: socket lifecycle (connect / accept / send / recv), plus decoded DNS queries/answers and plaintext HTTP requests/responses.
- **`timeline`** prints all events in chronological order (wall-clock UTC) — the "everything, in the order it happened" view.
- **`verify`** re-checks the bundle's integrity hashes and Ed25519 signature and prints a verdict; `--verify-key <b64>` additionally requires a specific signing key.
- **`diff`** semantically compares two bundles (e.g. the same sample run twice) and prints what each did that the other didn't. Exit 0 = identical, 1 = differs.
- **`artifacts`** lists the files captured into `artifacts/` (content hash, size, status, source path) — present only if the bundle was captured with `--capture-artifacts`. Extract them with `zstd -d < bundle.vishaya | tar -x artifacts/` (files are named by SHA-256).

## Look inside the bundle by hand

A `.vishaya` file is just a tar archive compressed with zstd:

```bash
zstd -d < /tmp/curl.vishaya | tar -tv
```

Expected output:

```
-rw-r--r-- 0/0 xxxx <date> manifest.json
-rw-r--r-- 0/0 xxxx <date> events.ndjson
-rw-r--r-- 0/0 xxxx <date> process_tree.json
drwxr-xr-x 0/0    0 <date> artifacts/
```

Extract and view the manifest:

```bash
zstd -d < /tmp/curl.vishaya | tar -xO manifest.json | jq
```

You'll see the schema version, tool version, kernel/arch/hostname, target binary path + SHA-256, isolation info, event coverage, event counts, SHA-256 integrity hashes for events.ndjson and process_tree.json, a clock anchor (for wall-clock timestamps), and an Ed25519 signature block.

## Common issues

**"vishaya capture must run as root"** — capture needs root for eBPF program load and cgroup v2 writes. Prefix with `sudo`.

**"failed to open BPF object: bpf/vishaya.bpf.o"** — you didn't build the BPF object. Run `./scripts/linux.sh bpf`.

**"kernel BTF not available at /sys/kernel/btf/vmlinux"** — your kernel wasn't built with `CONFIG_DEBUG_INFO_BTF=y`. Most modern distro kernels have it; some minimal or custom kernels don't. Check with `zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz`.

**"mkdir(/sys/fs/cgroup/vishaya-…) failed: EACCES"** — you're not root, or the system is on cgroup v1 (legacy hierarchy). Modern systemd-based distros default to cgroup v2 unified hierarchy. Check with `mount | grep cgroup`.

**Capture produces zero network events** — most commonly means you rebuilt the userspace but not the BPF object. Run `./scripts/linux.sh bpf` to recompile the probes, then re-run capture.

## Next

- **What actually got captured, in detail?** → [event-reference.md](event-reference.md)
- **How does all this work?** → [concepts.md](concepts.md) → [architecture.md](architecture.md) → [flow.md](flow.md)
- **What does the file format guarantee?** → [bundle-spec-v0.1.md](bundle-spec-v0.1.md)
- **Where's the project headed?** → [roadmap.md](roadmap.md)
