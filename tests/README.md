# Vishaya functional tests

A behavior-level pre-release test suite. It captures real targets and **asserts on
the produced `.vishaya` bundles and on the inspect commands' output** — not just
exit codes — so it actually verifies the tool does what it claims.

The suite is plain bash + standard tools (matches the project's `scripts/linux.sh`
style); there is no test framework to install.

## Prerequisites

- **Build first:** `./scripts/linux.sh all` (the suite runs `build/vishaya`).
- **Root:** `capture` needs root (eBPF + cgroup v2 + namespaces). Run the full
  suite with `sudo`. Without root, only the no-capture tests run.
- **Tools:** `jq`, `zstd`, `tar` (needed for bundle-content assertions — all are
  already build/runtime deps), `sha256sum` (integrity cross-checks). Optional:
  `cc` (thread test), `curl` + network (DNS/HTTP decode test). Missing optional
  tools turn the affected checks into **SKIP**, not failures.
- Run with `$HOME` set (the default) so bundle **signing** is exercised — under
  some `sudo` configs `$HOME` is stripped; use `sudo -E` if so.

## Running

```bash
chmod +x tests/*.sh                 # once

sudo ./tests/run-tests.sh           # full suite
sudo ./tests/run-tests.sh --keep    # keep the work dir + all bundles for inspection
./tests/run-tests.sh --no-root      # only the tests that don't need root

# point at a specific binary / pre-made bundle
VISHAYA=/path/to/vishaya sudo ./tests/run-tests.sh
VISHAYA_TEST_BUNDLE=/path/to/case.vishaya ./tests/run-tests.sh   # inspect/integrity without capturing
```

Output is `✓ PASS` / `✗ FAIL` / `• SKIP` per case, with a summary. **Exit code is
0 only if nothing failed** (skips don't fail the run), so it's CI-friendly.

If something misbehaves, re-run with `bash -x tests/run-tests.sh` to trace it.

## What it covers

Every capability, and every fix from the Review-2 pass (`docs/backlog.md`
R2-01…R2-10) that can be checked from userspace, is exercised:

| Group | Tests | Capability / fix verified |
|---|---|---|
| **A. CLI basics** (no root) | A1–A7 | `--version`, `--help`; error handling for missing subcommand / `--target` / bundle arg / missing file; build artifacts present |
| **B. Capture & bundle structure** | B1–B21 | Capture succeeds; bundle is `tar.zst` with manifest/events/process_tree; all JSON valid; NDJSON valid; semver, target SHA-256, event count; **signed by default (R2-02)**; **clock anchor present (R2-08)**; **process/file/network on by default (R2-04)**; integrity hashes match content |
| **C. Event coverage** | C1–C11 | **exec path+cmdline for short-lived procs (R2-03)**; fork/child lineage + tree edges; file events; **`--enable-syscalls` on/off**; **DNS decode (R2-01)** + network events; **threads are not phantom processes (R2-06)** |
| **D. Inspect commands** (no root) | D1–D7 | `tree`/`files`/`network`/`timeline` run without root; **timeline shows UTC wall-clock, ISO-8601 (R2-08)** |
| **E. Integrity & signing** (no root) | E1–E9 | **Good bundle verifies clean; naive events tamper → integrity mismatch; re-hashed tamper → signature INVALID; unsigned bundle noted; newer schema major rejected (R2-02, spec §6/§7/§9)** |
| **F. Flags & signals** | F1–F4 | **`--allow-host-wide` (R2-05)**; non-zero target exit recorded; **SIGINT finalizes a usable partial bundle** |
| **G. Robustness & open format** | G1–G4 | Heavy load stays valid NDJSON; **drops are self-reported, not silent**; bundle readable with `zstd`+`tar`+`jq` alone |

The two tamper tests in Group E are the headline security checks and demonstrate
the layered model: **hashing** catches naive edits, and the **signature** catches
an attacker who re-hashes the manifest (they have no signing key).

## Not automated — check these by hand before release

Some things can't be asserted reliably in a portable script; verify them manually:

- **`--cwd`** — capture `sh -c 'pwd'` with `--cwd /tmp` and confirm behavior; the
  cwd field is best-effort `/proc` enrichment and may be empty for fast procs.
- **HTTPS gives no plaintext** — capture `curl https://…` and confirm you get
  socket/DNS events but *no* `http-request` (TLS is opaque by design in v0.1).
- **R2-05 hard-fail path** — the "refuse to capture host-wide when the BPF object
  can't scope" branch only triggers with a *stale* BPF object lacking the
  `target_cgroup_id` map. Hard to synthesize; verify by reading the code path or
  temporarily building an old object. The suite only checks the `--allow-host-wide`
  override accepts and produces a bundle.
- **R2-07 (deferred)** — PID/TGID reuse merging is a *known* limitation; a very
  long capture with heavy PID churn could show it. Not a regression to test.
- **Cross-arch bundles** — capture on aarch64, inspect the bundle on x86_64 (and
  vice-versa) to confirm the format is portable; syscall numbers are arch-specific
  (see `manifest.capture.host.arch`).
- **BPF verifier acceptance** — a green `run-tests.sh` implies the probes loaded
  (capture wouldn't produce events otherwise), but if any capture yields an empty
  bundle, check stderr / `dmesg` for a verifier rejection (the real gate for the
  R2-03 exec-capture changes).
- **Scale** — multi-minute captures of a busy real workload, to gauge drop rates
  and bundle size in practice.

## Files

- `run-tests.sh` — the suite (grouped A–G; gates each group on root/tools/network).
- `lib.sh` — assertion framework + bundle-inspection helpers (`tar.zst` + `jq`).
