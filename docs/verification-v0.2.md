# Manual Acceptance Checklist — v0.2 (artifact capture + review fixes)

Run this on the Linux (aarch64) VM **after** `./scripts/linux.sh all`, to confirm the v0.2
changes are present and working. Everything here was written on a Windows review host and
is **unverified until this passes**.

**Fastest path:** `sudo ./tests/run-tests.sh` runs Groups A–H automatically (Group H is the
new artifact suite). This document is for eyeballing the specific new behaviors and for a
manual sign-off when you want to *see* each one.

Legend: `[ ]` = to check · **Expect:** = the PASS criteria · commands assume you're at the
repo root.

## Setup

```bash
V=./build/vishaya
W=$(mktemp -d /tmp/vishaya-accept.XXXXXX)
echo "work dir: $W"
# needs: root (capture), jq, zstd, tar, sha256sum
```

---

## Part 0 — Build & smoke

- [ ] **0.1 Build succeeds** — `./scripts/linux.sh all` finishes with no compile/link errors.
  **Expect:** three binaries in `build/`: `vishaya`, `isolation_probe`, `bundle_probe`.
- [ ] **0.2 Version bumped to 0.2.0**
  ```bash
  $V --version
  ```
  **Expect:** `vishaya 0.2.0 (pre-release)`.
- [ ] **0.3 New subcommand present** — `$V --help` lists **`artifacts`** alongside
  capture/summary/tree/files/network/timeline/verify/diff (9 subcommands total).
- [ ] **0.4 bundle_probe still works** (backward-compat smoke, no root)
  ```bash
  $V --help >/dev/null && ./build/bundle_probe "$W/probe.vishaya" && $V verify "$W/probe.vishaya"
  ```
  **Expect:** a bundle is written; `verify` exits 0.

---

## Part 1 — Automated suite (the quick global check)

- [ ] **1.1 Full suite passes**
  ```bash
  sudo ./tests/run-tests.sh
  ```
  **Expect:** ends with all-pass summary (exit 0). SKIPs are fine; **no FAILs**. Watch that
  **Group H (Artifact capture)** and **Group E (Integrity & signing)** both pass — E passing
  proves manifest signing stayed byte-identical after the new manifest fields.

If the suite is green you can stop here. Parts 2–4 are for manual confirmation / deeper looks.

---

## Part 2 — Artifact capture (the headline feature)

### 2A. Basic capture of a dropped file

```bash
DROP="/tmp/vishaya-drop-$$.txt"
sudo $V capture --target /bin/sh --capture-artifacts --output "$W/art.vishaya" \
  -- -c "echo dropper-payload > $DROP"
```

- [ ] **2.1 Bundle contains the artifact entries**
  ```bash
  zstd -dcq "$W/art.vishaya" | tar -t
  ```
  **Expect:** the usual `manifest.json`, `events.ndjson`, `process_tree.json`, `artifacts/`,
  **plus** `artifacts.json` and one `artifacts/<64-hex>` file.
- [ ] **2.2 Manifest records the capture**
  ```bash
  zstd -dcq "$W/art.vishaya" | tar -xO manifest.json | \
    jq '{schema:.schema_version, captured:.coverage.artifacts_captured,
         count:.counts.artifacts_count, idx:.integrity.artifacts_index_sha256}'
  ```
  **Expect:** `schema:"0.2.0"`, `captured:true`, `count` ≥ 1, `idx` a 64-hex string.
- [ ] **2.3 `artifacts` command lists the dropped file**
  ```bash
  $V artifacts "$W/art.vishaya"
  ```
  **Expect:** a `SHA256 / SIZE / STATUS / SOURCE PATH(S)` table with a row `status=ok` whose
  path is `$DROP`, then `N captured, M candidate record(s)` and an `extract:` hint.
- [ ] **2.4 Content-addressing is real** (entry name == its SHA-256)
  ```bash
  mkdir -p "$W/x" && zstd -dcq "$W/art.vishaya" | tar -x -C "$W/x" artifacts
  for f in "$W"/x/artifacts/*; do n=$(basename "$f");
    [ "$n" = "$(sha256sum "$f" | cut -d' ' -f1)" ] && echo "OK  $n" || echo "BAD $n"; done
  ```
  **Expect:** `OK` for every file. Also `cat "$W"/x/artifacts/*` shows `dropper-payload`.
- [ ] **2.5 Full verify chain passes**
  ```bash
  $V verify "$W/art.vishaya"; echo "exit=$?"
  ```
  **Expect:** `integrity: OK`, `signature: … VALID`, `VERDICT: VERIFIED`, `exit=0`.
- [ ] **2.6 Summary shows an artifacts section**
  ```bash
  $V summary "$W/art.vishaya"
  ```
  **Expect:** a `artifacts (N captured)` block listing the dropped path; trust line shows
  `✓ integrity OK` and `✓ signature VALID` (no `✗ artifacts TAMPERED`).

### 2B. Bounds and status vocabulary

- [ ] **2.7 Oversized file is skipped, not captured**
  ```bash
  sudo $V capture --target /bin/sh --capture-artifacts --artifact-max-size 1 \
    --output "$W/big.vishaya" -- -c 'echo more-than-one-byte > /tmp/vishaya-big.txt'
  $V artifacts "$W/big.vishaya"
  zstd -dcq "$W/big.vishaya" | tar -xO manifest.json | jq .counts.artifacts_count
  ```
  **Expect:** the `/tmp/vishaya-big.txt` row shows `status=skipped_too_large`; `artifacts_count` is `0`.
- [ ] **2.8 Created-then-deleted file is recorded but not extracted**
  ```bash
  sudo $V capture --target /bin/sh --capture-artifacts --output "$W/eph.vishaya" \
    -- -c 'echo x > /tmp/vishaya-eph.txt; rm -f /tmp/vishaya-eph.txt'
  $V artifacts "$W/eph.vishaya"
  ```
  **Expect:** a row for `/tmp/vishaya-eph.txt` with `status=missing_at_finalize` (documents the
  drop-then-delete without its bytes — the v0.2 snapshot limitation).

### 2C. Tamper detection on artifacts

- [ ] **2.9 Flipping an artifact byte fails verify**
  ```bash
  mkdir -p "$W/at" && zstd -dcq "$W/art.vishaya" | tar -x -C "$W/at"
  f=$(ls "$W/at"/artifacts/ | grep -E '^[0-9a-f]{64}$' | head -1)
  printf 'X' >> "$W/at/artifacts/$f"
  ( cd "$W/at" && tar -cf - manifest.json events.ndjson process_tree.json artifacts.json artifacts \
      | zstd -qc > "$W/at.vishaya" )
  $V verify "$W/at.vishaya"; echo "exit=$?"
  ```
  **Expect:** stderr shows `artifact content mismatch`; `VERDICT: FAILED`; `exit=1`.

---

## Part 3 — Review/robustness fixes from this session

- [ ] **3.1 PID-reuse guard: start time is captured in-kernel** (the one BPF change)
  ```bash
  zstd -dcq "$W/art.vishaya" | tar -xO events.ndjson | \
    jq -rc 'select(.family=="process" and .kind=="exec").data.start_time_ticks' | head -3
  ```
  **Expect:** **non-zero** integers. (Was always `0` before this change; `0` means your kernel
  lacks `task->start_boottime` and fell back — note it but not a failure.)
- [ ] **3.2 Non-UTF-8 paths no longer drop events** (dump() replacement handler)
  ```bash
  BAD=$(printf '/tmp/vishaya-bad-\xff\xfe.txt')
  sudo $V capture --target /bin/sh --output "$W/utf8.vishaya" -- -c "echo x > \"$BAD\""
  zstd -dcq "$W/utf8.vishaya" | tar -xO events.ndjson | jq -e . >/dev/null \
    && echo "events.ndjson fully valid (no throw-drop)"
  zstd -dcq "$W/utf8.vishaya" | tar -xO events.ndjson | grep -c '"kind":"openat"'
  ```
  **Expect:** "events.ndjson fully valid"; at least one `openat` event present (the file op was
  recorded with the invalid bytes replaced by `�`, not silently dropped).
- [ ] **3.3 Inspect is resilient to one malformed event** (per-event try/catch)
  ```bash
  mkdir -p "$W/mal" && zstd -dcq "$W/art.vishaya" | tar -x -C "$W/mal"
  printf '{"family":"file","kind":"openat","tgid":"not-an-int","data":{}}\n' >> "$W/mal/events.ndjson"
  ( cd "$W/mal" && tar -cf - manifest.json events.ndjson process_tree.json artifacts.json artifacts \
      | zstd -qc > "$W/mal.vishaya" )
  $V files "$W/mal.vishaya"; echo "exit=$?"
  ```
  **Expect:** it still prints the good file rows and a `(1 malformed event(s) skipped)` line;
  `exit=0` (does **not** abort the whole listing or crash). An `integrity mismatch` warning on
  stderr is expected here — you changed events.ndjson.
- [ ] **3.4 `verify --verify-key` pinning + honest display**
  ```bash
  PK=$(zstd -dcq "$W/art.vishaya" | tar -xO manifest.json | jq -r .sig.pubkey_b64)
  $V verify "$W/art.vishaya" --verify-key "$PK";        echo "exit=$?"   # correct key
  $V verify "$W/art.vishaya" --verify-key not-the-key;  echo "exit=$?"   # wrong key
  ```
  **Expect:** correct key → `pinned key: MATCH`, `VERDICT: VERIFIED`, `exit=0`; wrong key →
  `pinned key: MISMATCH`, `VERDICT: FAILED`, `exit=1`.
- [ ] **3.5 (optional, advanced) `tree` survives a cyclic process_tree.json**
  Extract `$W/art.vishaya`, hand-edit `process_tree.json` so two records list each other in
  `children` (a cycle), repack, then `$V tree` on it.
  **Expect:** it prints a ` …cycle)` marker and returns — **no segfault / infinite loop**.

---

## Part 4 — Compatibility (0.1 ↔ 0.2)

- [ ] **4.1 A capture *without* `--capture-artifacts` is unchanged**
  ```bash
  sudo $V capture --target /bin/true --output "$W/noflag.vishaya"
  zstd -dcq "$W/noflag.vishaya" | tar -t | grep -q '^artifacts.json$' \
    && echo "UNEXPECTED artifacts.json" || echo "OK: no artifacts.json"
  zstd -dcq "$W/noflag.vishaya" | tar -xO manifest.json | jq '.coverage.artifacts_captured'
  $V verify "$W/noflag.vishaya"; echo "exit=$?"
  ```
  **Expect:** `OK: no artifacts.json`; `artifacts_captured` is `false`; `verify` exits 0.
- [ ] **4.2 (if you have a pre-0.2 bundle) old bundles still open**
  Run `$V verify` / `$V summary` on any `.vishaya` captured before this session (e.g. from
  `samples/`). **Expect:** opens and verifies fine (the reader defaults the new fields; the
  artifact checks no-op when there's no index).

---

## Sign-off

| Area | Check(s) | Result |
|---|---|---|
| Build + version + 9 commands | 0.1–0.4 | ☐ |
| Automated suite (A–H) | 1.1 | ☐ |
| Artifact capture end-to-end | 2.1–2.6 | ☐ |
| Bounds + status vocabulary | 2.7–2.8 | ☐ |
| Artifact tamper detection | 2.9 | ☐ |
| In-kernel start time (BPF) | 3.1 | ☐ |
| Non-UTF-8 robustness | 3.2 | ☐ |
| Inspect resilience | 3.3 | ☐ |
| verify key pinning | 3.4 | ☐ |
| tree cycle guard (optional) | 3.5 | ☐ |
| 0.1 ↔ 0.2 compatibility | 4.1–4.2 | ☐ |

**Cleanup:** `rm -rf "$W" /tmp/vishaya-drop-*.txt /tmp/vishaya-big.txt`

If anything fails, capture the command + output and the relevant `*.log` under the work dir;
the most likely first hurdle is a C++ compile error in a new module (`artifact_collector`,
`bundle/artifacts`, `inspect/artifacts`, `Sha256Streamer`), which the build output will name.
