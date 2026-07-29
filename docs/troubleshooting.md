# Troubleshooting

Common failures and how to fix them, organized by when they happen: build, capture, inspect.

## Build failures

### `Vishaya is Linux-only. Build on a Linux host.`

You're running CMake on macOS or Windows. Move to a Linux host or WSL2 with a modern kernel (must have BTF — check `/sys/kernel/btf/vmlinux` exists).

### `libbpf` / `libzstd` / `libarchive` / `nlohmann_json` / `CLI11` / `OpenSSL` not found

Distro-specific `-dev` / `-devel` packages missing. Run `./scripts/linux.sh check` — it prints the exact install command for your distro.

Quick reference:

```bash
# Debian/Ubuntu
sudo apt install libbpf-dev libzstd-dev libarchive-dev \
    nlohmann-json3-dev libcli11-dev libssl-dev

# Fedora
sudo dnf install libbpf-devel libzstd-devel libarchive-devel \
    json-devel cli11-devel openssl-devel

# Arch
sudo pacman -S libbpf zstd libarchive nlohmann-json cli11 openssl
```

### `clang not found (required for BPF object build)`

Install clang. Vishaya's BPF build script tries `clang`, `clang-18`, `clang-17`, ... in order. If your distro provides a versioned clang only, either symlink `/usr/bin/clang → clang-XX` or export `CLANG=clang-XX` before running the build.

### `kernel BTF not available at /sys/kernel/btf/vmlinux`

Your running kernel wasn't built with `CONFIG_DEBUG_INFO_BTF=y`. Common on:
- Minimal container images (Alpine, distroless — but you wouldn't be building here anyway)
- Custom-compiled kernels
- Very old distros

Check with `zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz` (if `/proc/config.gz` is readable) or `grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)`.

If your distro kernel doesn't have BTF, upgrade to a modern distro. Ubuntu 22.04+, Fedora 35+, Debian 12+, and Arch all ship BTF by default.

### `unsupported architecture: <arch>`

The BPF build script has an explicit switch on `uname -m` for `__TARGET_ARCH_<name>`. If your architecture isn't listed (x86_64, aarch64, arm, riscv64, ppc64le, s390x), edit `scripts/linux.sh` to add it. The name follows the Linux kernel `arch/` directory naming.

### CMake error about C++20 features

Your compiler is too old. Vishaya uses C++20 features (nested namespace syntax `namespace vishaya::collector`, `std::string_view::starts_with`, `std::span`). Minimum: gcc 10+, clang 10+. Upgrade or use a newer distro.

### BPF verifier error at load time

Shows up as a load failure in the collector's stderr, usually mentioning "invalid access" or "loop detected". Very rare unless you've modified the BPF code.

Debug steps:
1. Rebuild the BPF object with `./scripts/linux.sh bpf` and look at the clang output — it may have surfaced warnings.
2. Try loading with verbose libbpf logging: rebuild after temporarily editing `src/collector/collector_libbpf.cpp` to return `1` instead of `0` for `LIBBPF_DEBUG` in `LibbpfPrint`. The verifier's rejection reason will show up.
3. Check your kernel version — Vishaya targets 5.15+; older kernels may not support all features Vishaya's probes use.

## Capture failures

### `vishaya capture must run as root`

Prefix your command with `sudo`. eBPF program load and cgroup v2 writes both require root.

### `mkdir(/sys/fs/cgroup/vishaya-…) failed: EACCES` or `EROFS`

Two possibilities:

1. **Not running as root** — `sudo`.
2. **System is on cgroup v1** — modern systemd distros default to v2 (unified hierarchy). Check with `mount | grep cgroup`. If you see multiple lines with paths like `/sys/fs/cgroup/memory`, `/sys/fs/cgroup/cpu`, etc., you're on v1. Switch to v2 by adding `systemd.unified_cgroup_hierarchy=1` to your kernel boot parameters and rebooting.

### `failed to open BPF object: bpf/vishaya.bpf.o`

You built the userspace but not the BPF object. Run `./scripts/linux.sh bpf`, then re-run the capture.

Or you ran the binary from a directory where the relative path doesn't resolve. The binary looks for `bpf/vishaya.bpf.o` relative to the CMake source dir (compiled in at build time). If you moved the binary elsewhere, set `VISHAYA_BPF_OBJECT=/absolute/path/to/vishaya.bpf.o` in the env.

### Capture completes but bundle is empty (0 events)

Most common cause: **the BPF object was built before Step 6 (cgroup filter) or Step 9 (payload capture) were added**. Rebuild:

```bash
./scripts/linux.sh bpf
sudo ./build/vishaya capture --target ... --output test.vishaya -- ...
```

Second cause: **cgroup filter blocked everything unexpectedly**. Verify: run `./build/vishaya capture` and check stderr for the line `collector: … cgroup_scoping=on/off`. If `on`, filter is active — but if the target somehow escapes its cgroup (very rare with our setup), events would be dropped.

Debug: to confirm the pipeline works independent of the cgroup filter, run once with `--allow-host-wide` (this bypasses the scoping requirement and captures every process). If you see events now, the cgroup filter is the culprit; check that the target actually inherits the cgroup (view `/sys/fs/cgroup/vishaya-*/cgroup.procs` during a running capture).

### `cgroup scoping requested but the loaded BPF object has no target_cgroup_id map`

Capture **refuses to run** in this case rather than silently recording every process on the host — scoped capture is the whole point, and a host-wide bundle mislabeled as target-scoped would be misleading evidence. The cause is a stale BPF object (built before cgroup scoping existed). Fix it by rebuilding:

```bash
./scripts/linux.sh bpf
```

If you genuinely want a host-wide capture (e.g. diagnostics), pass `--allow-host-wide` to override — the bundle will then contain events from every process on the host, and a warning is logged.

### Capture produces process events but no network events

Your BPF object was built before the recent fix that added `vishaya_network.bpf.c` to `vishaya.bpf.c`. Rebuild the BPF object.

Verify: `grep -c 'family":"network"' <extracted-events.ndjson>` — if 0, the network probes aren't attached. Confirm with `sudo bpftool prog show` — you should see programs named like `on_sys_enter_connect`, `on_sys_exit_sendto`, etc.

### `target launched: pid=… waiting for target` but nothing happens

The target is running in isolation but never doing anything observable. Check:
- Did you pass args correctly? `sudo vishaya capture --target /bin/sh --output t.vishaya -- -c "ls /"` (note the `--` separator).
- Is the target reading from stdin and waiting? Most targets need `-c 'command'` or an actual file to operate on.

### `ring buffer poll failed: <errno>` in stderr

libbpf reports a ring buffer error. Common causes:
- Kernel out of memory (unlikely on a workstation).
- BPF program was unloaded (shouldn't happen mid-capture — file a bug).

Usually transient; capture continues.

### Capture crashes mid-run (SIGSEGV, SIGABRT)

Rare. If it happens:
1. Copy the `/tmp/vishaya-capture-<uuid>/events.ndjson` file — it has whatever was captured before the crash.
2. Run the capture again under `valgrind` or `gdb` to get a backtrace.
3. File a bug with the backtrace and, if possible, the target binary or a reproducer.

### `waitpid failed: <errno>`

Usually means the target process was reaped by something else (init got to it first?). Recoverable — session continues.

### Cgroup cleanup warning: `rmdir(...) failed: EBUSY`

The target spawned a background child that outlived the target itself (e.g., `sh -c 'sleep 999 &'`). The child is still in the cgroup, blocking removal.

Manually clean up:
```bash
sudo cat /sys/fs/cgroup/vishaya-<uuid>/cgroup.procs   # list of PIDs still in cgroup
sudo kill <pids>                                       # or SIGKILL them
sudo rmdir /sys/fs/cgroup/vishaya-<uuid>
```

This is a known edge case; the bundle itself is fine.

## Inspect failures

### `bundle major X is newer than this reader supports`

You're trying to open a `.vishaya` bundle created by a newer tool version that bumped the schema major. Update Vishaya to at least match the bundle's schema major.

### `bundle missing manifest.json`

The file isn't a valid Vishaya bundle. Verify:
```bash
zstd -d < case.vishaya | tar -tv
```

If tar can't read it, the file is corrupt or not a tar.zst archive at all. If tar reads but no `manifest.json` appears, this file wasn't produced by Vishaya (or was truncated during write).

### `manifest JSON parse error: <details>`

The `manifest.json` inside the archive is malformed. Likely corruption during transfer (network transfer, tar re-archiving, etc.). Re-transfer the file with checksum verification.

### `integrity mismatch: events.ndjson expected=X got=Y`

`vishaya` recomputes SHA-256 of the events file and it doesn't match what the manifest claims. Two causes:
- **Bundle was tampered with** — someone modified the events stream after Vishaya wrote it.
- **Bundle was re-packaged** — someone extracted, edited, and re-tar'd. Even a re-tar without content changes can break byte-for-byte hashes if tar options differ.

In both cases, treat the bundle as suspect. The events may still be readable, but you can't trust their provenance.

### `vishaya tree` shows only the root; children missing

Two possibilities:
1. **Target never spawned children.** Nothing to show. Verify with `zstd -d < case.vishaya | tar -xO events.ndjson | grep '"kind":"fork"'` — if empty, target didn't fork.
2. **Fork events happened but `child_pid` field wasn't populated.** BPF-side bug or an older BPF object. Rebuild and re-capture.

### `vishaya network` shows connect/close but no dns-query/dns-answer

DNS payload capture requires:
1. BPF object built with Step 9 (`capture_send_payload` and `payload_recv_ptr` support).
2. `manifest.coverage.network_layers` includes `"dns"`.
3. Target actually did a DNS query via `sendto`/`recvfrom` on UDP:53.

Check:
```bash
zstd -d < case.vishaya | tar -xO manifest.json | jq '.coverage.network_layers'
# should show ["socket", "dns", "http"]

zstd -d < case.vishaya | tar -xO events.ndjson | \
    jq -r 'select(.family == "network") | .kind' | sort -u
# should include "sendto" and "recvfrom" if UDP DNS happened
```

If sendto/recvfrom events exist but no dns-query — the userspace protocol decoder didn't recognize the payload. Could be:
- Payload was truncated (< 12 bytes; DNS header requires 12).
- Payload was DNS-over-TLS or DNS-over-HTTPS (not decoded).
- Payload was to a non-port-53 DNS resolver (rare but possible).

### `vishaya network` shows connect/close but no http-request

HTTP requires:
1. BPF built with Step 9 (write/read payload capture).
2. Plaintext HTTP (port 80 typically). HTTPS is encrypted — you'll see TCP connect + byte counts but no `http-request`.
3. Target's HTTP method line + Host header fit in the first 128 bytes (usually true).

If it's HTTPS (port 443), that's expected behavior — encrypted payload can't be parsed without TLS keys.

## Meta: getting more information

Enable debug logging for capture:

```bash
sudo ./build/vishaya -v capture --target ... --output ... -- ...
```

You'll see `[DEBUG]` lines from the isolation setup, BPF load, cgroup attach, and Session lifecycle.

Enable libbpf debug logging by editing `src/collector/collector_libbpf.cpp`'s `LibbpfPrint` function to return `vfprintf(stderr, fmt, args)` for `LIBBPF_DEBUG` too, then rebuild. This is very verbose but shows every step libbpf takes internally.

Check kernel messages during capture:

```bash
sudo dmesg -w &
sudo ./build/vishaya capture ...
```

BPF verifier rejections and kernel-side warnings show up here.

Inspect the ring buffer stats:

```bash
sudo bpftool map dump name bpf_stats
```

Look for `BPF_STAT_RINGBUF_RESERVE_FAIL` > 0 — that means events were dropped because the ring buffer was full. Usually indicates userspace poll thread starvation (system very busy). Not a bug in Vishaya per se, but worth knowing.

## Still stuck?

Open an issue with:
- Kernel version (`uname -r`)
- Distro + version
- Full command you ran
- Full stderr output
- The bundle file (or its manifest.json if the whole bundle is too big) if it's an inspect failure
