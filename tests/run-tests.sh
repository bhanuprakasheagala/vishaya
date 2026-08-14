#!/usr/bin/env bash
#
# Vishaya pre-release functional test suite.
#
# Captures real targets and asserts on the produced .vishaya bundles and on the
# inspect commands' output — so it verifies behaviour, not just exit codes.
#
# USAGE
#   sudo ./tests/run-tests.sh            # full suite (capture needs root)
#   ./tests/run-tests.sh --no-root       # only the tests that don't need root
#   sudo ./tests/run-tests.sh --keep     # keep the work dir + bundles for inspection
#   VISHAYA=/path/to/vishaya sudo ./tests/run-tests.sh
#
# EXIT CODE: 0 if all run tests passed, 1 if any failed. Skips do not fail.
#
# Coverage matrix and manual-only cases: see tests/README.md.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
# shellcheck source=tests/lib.sh
source "$SCRIPT_DIR/lib.sh"

set -u

VISHAYA="${VISHAYA:-$REPO_ROOT/build/vishaya}"
KEEP=0
WANT_ROOT=1
for arg in "$@"; do
  case "$arg" in
    --keep)    KEEP=1 ;;
    --no-root) WANT_ROOT=0 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) warn "unknown arg: $arg" ;;
  esac
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vishaya-tests.XXXXXX")"
cleanup() { [ "$KEEP" = 1 ] && { info "kept work dir: $WORK"; return; }; rm -rf "$WORK"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
group "Preflight"

if [ ! -x "$VISHAYA" ]; then
  fail "vishaya binary present" "not found/executable at $VISHAYA (build first, or set VISHAYA=)"
  print_summary; exit 1
fi
pass "vishaya binary present ($VISHAYA)"

HAVE_ROOT=0; [ "$(id -u)" = 0 ] && HAVE_ROOT=1
HAVE_JQ=0;   command -v jq        >/dev/null 2>&1 && HAVE_JQ=1
HAVE_ZSTD=0; command -v zstd      >/dev/null 2>&1 && HAVE_ZSTD=1
HAVE_TAR=0;  command -v tar       >/dev/null 2>&1 && HAVE_TAR=1
HAVE_SHA=0;  command -v sha256sum >/dev/null 2>&1 && HAVE_SHA=1
HAVE_CC=0;   command -v cc        >/dev/null 2>&1 && HAVE_CC=1
HAVE_CURL=0; command -v curl      >/dev/null 2>&1 && HAVE_CURL=1

[ "$HAVE_JQ"   = 1 ] || warn "jq not found — bundle-content assertions will be skipped"
[ "$HAVE_ZSTD" = 1 ] || warn "zstd not found — bundle inspection will be skipped"

# Network connectivity (best-effort, gates DNS/HTTP tests)
HAVE_NET=0
if [ "$HAVE_CURL" = 1 ] && curl -s -m 5 -o /dev/null http://example.com 2>/dev/null; then
  HAVE_NET=1
fi

info "root=$HAVE_ROOT jq=$HAVE_JQ zstd=$HAVE_ZSTD sha256sum=$HAVE_SHA cc=$HAVE_CC curl=$HAVE_CURL net=$HAVE_NET"

CAN_CAPTURE=0
if [ "$WANT_ROOT" = 1 ] && [ "$HAVE_ROOT" = 1 ]; then CAN_CAPTURE=1; fi
if [ "$WANT_ROOT" = 1 ] && [ "$HAVE_ROOT" = 0 ]; then
  warn "not root — capture tests will be skipped. Re-run with sudo for the full suite."
fi
CAN_BUNDLE=0
[ "$HAVE_JQ" = 1 ] && [ "$HAVE_ZSTD" = 1 ] && [ "$HAVE_TAR" = 1 ] && CAN_BUNDLE=1

# Small helper: capture a target, echo the bundle path. Returns capture exit code.
# cap NAME OUTFILE -- <vishaya capture args...>
cap() {
  local out="$1"; shift
  [ "$1" = "--" ] && shift
  "$VISHAYA" capture --output "$out" "$@" >"$WORK/${out##*/}.log" 2>&1
}

# A pre-made good bundle reused across inspect/integrity groups.
GOOD_BUNDLE="$WORK/good.vishaya"

# ---------------------------------------------------------------------------
# Group A — CLI basics (no root)
# ---------------------------------------------------------------------------
group "A. CLI basics (no root)"

ver="$("$VISHAYA" --version 2>&1)"
help_out="$("$VISHAYA" --help 2>&1)"
assert_match "A1 --version prints a version"        "$ver" 'vishaya|0\.1'
assert_fail  "A2 no subcommand is an error"         "$VISHAYA"
assert_fail  "A3 capture without --target errors"   "$VISHAYA" capture --output "$WORK/x.vishaya"
assert_fail  "A4 tree without bundle errors"        "$VISHAYA" tree
assert_fail  "A5 inspect of missing file errors"    "$VISHAYA" tree "$WORK/does-not-exist.vishaya"
assert_match "A6 --help lists subcommands"          "$help_out" 'capture|tree|network|timeline'

for b in vishaya isolation_probe bundle_probe; do
  if [ -x "$REPO_ROOT/build/$b" ]; then pass "A7 build artifact present: $b"
  else fail "A7 build artifact present: $b" "missing $REPO_ROOT/build/$b"; fi
done

# ---------------------------------------------------------------------------
# Group B — Basic capture + bundle structure (root)
# ---------------------------------------------------------------------------
group "B. Basic capture & bundle structure (root)"

if [ "$CAN_CAPTURE" = 1 ]; then
  if cap "$GOOD_BUNDLE" -- --target /bin/sh -- -c 'echo vishaya-test; /bin/true'; then
    pass "B1 capture of /bin/sh succeeds"
  else
    fail "B1 capture of /bin/sh succeeds" "see $WORK/good.vishaya.log"
  fi
  assert_file "B2 bundle file created" "$GOOD_BUNDLE"

  if [ "$CAN_BUNDLE" = 1 ] && [ -s "$GOOD_BUNDLE" ]; then
    entries="$(bundle_list "$GOOD_BUNDLE")"
    assert_contains "B3 bundle has manifest.json"      "$entries" "manifest.json"
    assert_contains "B4 bundle has events.ndjson"      "$entries" "events.ndjson"
    assert_contains "B5 bundle has process_tree.json"  "$entries" "process_tree.json"

    assert_ok  "B6 manifest.json is valid JSON"        json_valid "$GOOD_BUNDLE" manifest.json
    assert_ok  "B7 events.ndjson is valid NDJSON"      ndjson_valid "$GOOD_BUNDLE"
    assert_ok  "B8 process_tree.json is valid JSON"    json_valid "$GOOD_BUNDLE" process_tree.json

    assert_match "B9 schema_version is semver"         "$(mf "$GOOD_BUNDLE" '.schema_version')" '^[0-9]+\.[0-9]+\.[0-9]+'
    assert_eq    "B10 tool.name is vishaya"            "$(mf "$GOOD_BUNDLE" '.tool.name')" "vishaya"
    assert_match "B11 target.sha256 is 64 hex"         "$(mf "$GOOD_BUNDLE" '.target.sha256')" '^[0-9a-f]{64}$'
    assert_ge    "B12 counts.events_total > 0"         "$(mf "$GOOD_BUNDLE" '.counts.events_total')" 1

    # R2-02: signed by default
    assert_eq  "B13 (R2-02) signature algorithm Ed25519" "$(mf "$GOOD_BUNDLE" '.sig.algorithm')" "Ed25519"
    assert_match "B14 (R2-02) pubkey present (base64)"    "$(mf "$GOOD_BUNDLE" '.sig.pubkey_b64')" '^[A-Za-z0-9+/=]{20,}$'
    assert_eq  "B14b (P2) signature scope is manifest-v1" "$(mf "$GOOD_BUNDLE" '.sig.scope')" "manifest-v1"

    # R2-08: clock anchor present and non-zero
    assert_ge  "B15 (R2-08) clock_realtime_ns set"       "$(mf "$GOOD_BUNDLE" '.capture.clock_realtime_ns')" 1
    assert_ge  "B16 (R2-08) clock_monotonic_ns set"      "$(mf "$GOOD_BUNDLE" '.capture.clock_monotonic_ns')" 1

    # R2-04: process/file/network on by default (no flags)
    fams="$(mf "$GOOD_BUNDLE" '.coverage.families | join(",")')"
    assert_contains "B17 (R2-04) process family default on" "$fams" "process"
    assert_contains "B18 (R2-04) file family default on"    "$fams" "file"
    assert_contains "B19 (R2-04) network family default on" "$fams" "network"

    # integrity hashes match recomputed content
    if [ "$HAVE_SHA" = 1 ]; then
      got_ev="$(bundle_entry "$GOOD_BUNDLE" events.ndjson | sha256sum | cut -d' ' -f1)"
      assert_eq "B20 events integrity hash matches content" "$got_ev" "$(mf "$GOOD_BUNDLE" '.integrity.events_sha256')"
      got_pt="$(bundle_entry "$GOOD_BUNDLE" process_tree.json | sha256sum | cut -d' ' -f1)"
      assert_eq "B21 process_tree integrity hash matches"   "$got_pt" "$(mf "$GOOD_BUNDLE" '.integrity.process_tree_sha256')"
    else
      skip "B20/B21 integrity hash cross-check" "sha256sum unavailable"
    fi
  else
    skip "B3..B21 bundle-content assertions" "jq/zstd/tar unavailable or empty bundle"
  fi
else
  skip "B* capture & structure" "needs root"
fi

# ---------------------------------------------------------------------------
# Group C — Event coverage (root)
# ---------------------------------------------------------------------------
group "C. Event family coverage (root)"

if [ "$CAN_CAPTURE" = 1 ] && [ "$CAN_BUNDLE" = 1 ]; then
  # C1 (R2-03): exec of an ultra-short-lived process still records exec_path+cmdline
  b="$WORK/true.vishaya"
  cap "$b" -- --target /bin/true >/dev/null 2>&1
  if [ -s "$b" ]; then
    execs="$(events_where "$b" '.family=="process" and .kind=="exec"')"
    assert_ge  "C1 (R2-03) at least one exec event" "$(printf '%s' "$execs" | grep -c '.')" 1
    ep="$(printf '%s\n' "$execs" | jq -r '.data.exec_path // .data.filename' 2>/dev/null | grep -m1 'true')"
    assert_match "C2 (R2-03) exec_path populated for short-lived proc" "$ep" 'true'
  else
    skip "C1/C2 short-lived exec" "capture produced no bundle"
  fi

  # C3: fork/child lineage — sh spawns /bin/echo
  b="$WORK/fork.vishaya"
  cap "$b" -- --target /bin/sh -- -c '/bin/echo child-a; /bin/echo child-b' >/dev/null 2>&1
  if [ -s "$b" ]; then
    nproc="$(bundle_entry "$b" process_tree.json | jq '.processes | length' 2>/dev/null)"
    assert_ge "C3 process tree has >= 2 processes (sh + child)" "$nproc" 2
    kids="$(bundle_entry "$b" process_tree.json | jq '[.processes[].children[]] | length' 2>/dev/null)"
    assert_ge "C4 tree records at least one child edge" "$kids" 1
  else
    skip "C3/C4 fork lineage" "capture produced no bundle"
  fi

  # C5: file events — create + delete a temp file
  b="$WORK/file.vishaya"
  tf="/tmp/vishaya_ftest_$$"
  cap "$b" -- --target /bin/sh -- -c "touch $tf; rm -f $tf" >/dev/null 2>&1
  if [ -s "$b" ]; then
    nfile="$(events_where "$b" '.family=="file"' | grep -c '.')"
    assert_ge "C5 file events captured" "$nfile" 1
  else
    skip "C5 file events" "capture produced no bundle"
  fi

  # C6: syscall opt-in
  b="$WORK/syscall.vishaya"
  cap "$b" -- --target /bin/true --enable-syscalls >/dev/null 2>&1
  if [ -s "$b" ]; then
    assert_eq "C6 (--enable-syscalls) coverage flag set" "$(mf "$b" '.coverage.syscalls_captured')" "true"
    nsys="$(events_where "$b" '.family=="syscall"' | grep -c '.')"
    assert_ge "C7 syscall events present when enabled" "$nsys" 1
  else
    skip "C6/C7 syscall capture" "capture produced no bundle"
  fi

  # C8: syscalls OFF by default
  if [ -s "$GOOD_BUNDLE" ]; then
    assert_eq "C8 syscalls OFF by default" "$(mf "$GOOD_BUNDLE" '.coverage.syscalls_captured')" "false"
  fi

  # C9/C10 (R2-01 + network): DNS + HTTP decode (needs connectivity)
  if [ "$HAVE_NET" = 1 ] && [ "$HAVE_CURL" = 1 ]; then
    b="$WORK/net.vishaya"
    cap "$b" -- --target "$(command -v curl)" -- -s -m 10 -o /dev/null http://example.com >/dev/null 2>&1
    if [ -s "$b" ]; then
      nnet="$(events_where "$b" '.family=="network"' | grep -c '.')"
      assert_ge "C9 network events captured" "$nnet" 1
      ndns="$(events_where "$b" '.kind=="dns-query"' | grep -c '.')"
      if [ "${ndns:-0}" -ge 1 ]; then pass "C10 (R2-01) DNS query decoded"
      else skip "C10 DNS query decode" "no dns-query synthesized (resolver path may differ)"; fi
    else
      skip "C9/C10 network capture" "capture produced no bundle"
    fi
  else
    skip "C9/C10 network/DNS/HTTP decode" "no network connectivity"
  fi

  # C11 (R2-06): threads are NOT counted as processes
  if [ "$HAVE_CC" = 1 ]; then
    cat > "$WORK/thr.c" <<'EOF'
#include <pthread.h>
#include <unistd.h>
static void* w(void* a){ (void)a; usleep(50000); return 0; }
int main(void){ pthread_t t[4]; for(int i=0;i<4;i++) pthread_create(&t[i],0,w,0);
  for(int i=0;i<4;i++) pthread_join(t[i],0); return 0; }
EOF
    if cc -O2 -o "$WORK/thr" "$WORK/thr.c" -lpthread 2>/dev/null; then
      b="$WORK/thread.vishaya"
      cap "$b" -- --target "$WORK/thr" >/dev/null 2>&1
      if [ -s "$b" ]; then
        # 4 threads share the leader's tgid: the tree must show exactly 1 process,
        # with no thread nodes and no phantom children.
        nproc="$(bundle_entry "$b" process_tree.json | jq '.processes | length' 2>/dev/null)"
        assert_eq "C11 (R2-06) 4-thread program = 1 process node, no phantoms" "$nproc" "1"
      else
        skip "C11 thread handling" "capture produced no bundle"
      fi
    else
      skip "C11 thread handling" "pthread test program failed to compile"
    fi
  else
    skip "C11 thread handling" "no C compiler"
  fi
else
  skip "C* event coverage" "needs root + jq/zstd/tar"
fi

# If we couldn't capture (no root), fall back to a bundle for the inspect/integrity
# groups so they still run: an explicitly supplied one, else a committed fixture.
if [ ! -s "$GOOD_BUNDLE" ]; then
  if [ -n "${VISHAYA_TEST_BUNDLE:-}" ] && [ -s "${VISHAYA_TEST_BUNDLE:-}" ]; then
    GOOD_BUNDLE="$VISHAYA_TEST_BUNDLE"
    info "using supplied VISHAYA_TEST_BUNDLE for inspect/integrity groups: $GOOD_BUNDLE"
  elif [ -s "$REPO_ROOT/samples/02-shell-pipeline.vishaya" ]; then
    GOOD_BUNDLE="$REPO_ROOT/samples/02-shell-pipeline.vishaya"
    info "using committed sample fixture for inspect/integrity groups: $GOOD_BUNDLE"
  fi
fi

# ---------------------------------------------------------------------------
# Group D — Inspect commands (no root, on the good bundle)
# ---------------------------------------------------------------------------
group "D. Inspect commands"

if [ -s "$GOOD_BUNDLE" ]; then
  t_out="$("$VISHAYA" tree     "$GOOD_BUNDLE" 2>/dev/null)"
  f_out="$("$VISHAYA" files    "$GOOD_BUNDLE" 2>/dev/null)"
  n_out="$("$VISHAYA" network  "$GOOD_BUNDLE" 2>/dev/null)"
  l_out="$("$VISHAYA" timeline "$GOOD_BUNDLE" 2>/dev/null)"

  assert_ok       "D1 tree runs (no root)"       "$VISHAYA" tree     "$GOOD_BUNDLE"
  assert_ok       "D2 files runs (no root)"      "$VISHAYA" files    "$GOOD_BUNDLE"
  assert_ok       "D3 network runs (no root)"    "$VISHAYA" network  "$GOOD_BUNDLE"
  assert_ok       "D4 timeline runs (no root)"   "$VISHAYA" timeline "$GOOD_BUNDLE"

  assert_contains "D5 tree shows target line"    "$t_out" "target"
  # R2-08: timeline shows a wall-clock UTC column and ISO timestamps
  assert_match    "D6 (R2-08) timeline header shows UTC" "$l_out" 'TIME \(UTC\)'
  assert_match    "D7 (R2-08) timeline rows are ISO-8601 UTC" "$l_out" '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z'

  # D8-D10: summary view (the one-screen verdict).
  s_out="$("$VISHAYA" summary "$GOOD_BUNDLE" 2>/dev/null)"
  assert_ok       "D8 summary runs (no root)"     "$VISHAYA" summary "$GOOD_BUNDLE"
  assert_contains "D9 summary shows header"        "$s_out" "Vishaya capture"
  assert_contains "D10 summary shows trust line"   "$s_out" "integrity"

  # D11-D13: semantic diff.
  d_self="$("$VISHAYA" diff "$GOOD_BUNDLE" "$GOOD_BUNDLE" 2>/dev/null)"
  assert_ok       "D11 diff of a bundle vs itself exits 0" "$VISHAYA" diff "$GOOD_BUNDLE" "$GOOD_BUNDLE"
  assert_contains "D12 diff self reports no differences"    "$d_self" "no semantic differences"
  SECOND=""
  for cand in "$WORK/file.vishaya" "$WORK/net.vishaya" "$WORK/fork.vishaya" \
              "$REPO_ROOT/samples/04-http-curl.vishaya" "$REPO_ROOT/samples/06-file-lifecycle.vishaya"; do
    if [ -s "$cand" ] && [ "$cand" != "$GOOD_BUNDLE" ]; then SECOND="$cand"; break; fi
  done
  if [ -n "$SECOND" ]; then
    assert_fail "D13 diff of two different captures reports differences (exit 1)" \
      "$VISHAYA" diff "$GOOD_BUNDLE" "$SECOND"
  else
    skip "D13 diff of two different captures" "no distinct second bundle available"
  fi
else
  skip "D* inspect commands" "no good bundle to inspect (needs a root capture)"
fi

# ---------------------------------------------------------------------------
# Group E — Integrity & signature verification (no root)  [R2-02]
# ---------------------------------------------------------------------------
group "E. Integrity & signature verification (R2-02)"

if [ -s "$GOOD_BUNDLE" ] && [ "$CAN_BUNDLE" = 1 ]; then
  # E1: a good bundle verifies cleanly — no warnings on stderr.
  verr="$("$VISHAYA" tree "$GOOD_BUNDLE" 2>&1 >/dev/null)"
  assert_not_contains "E1 good bundle: no integrity mismatch" "$verr" "integrity mismatch"
  assert_not_contains "E2 good bundle: signature not flagged"  "$verr" "signature INVALID"

  # E3: naive tamper — change events.ndjson only. Integrity must catch it.
  d="$WORK/tamper1"; tb="$WORK/tamper1.vishaya"
  repack_extract "$GOOD_BUNDLE" "$d"
  echo '{"family":"process","kind":"exec","tampered":true}' >> "$d/events.ndjson"
  repack_finish "$d" "$tb"
  verr="$("$VISHAYA" tree "$tb" 2>&1 >/dev/null)"
  assert_contains "E3 (R2-02) events tamper -> integrity mismatch" "$verr" "integrity mismatch"

  # E4: sophisticated tamper — change events AND fix the manifest hash so
  # integrity passes; only the SIGNATURE can catch it (attacker has no key).
  SIGNED=0; [ "$(mf "$GOOD_BUNDLE" '.sig.algorithm')" = "Ed25519" ] && SIGNED=1
  if [ "$SIGNED" = 0 ]; then
    skip "E5 signature-catches-rehash tamper" "good bundle is unsigned (is \$HOME set under sudo?)"
  elif [ "$HAVE_SHA" = 1 ]; then
    d="$WORK/tamper2"; tb="$WORK/tamper2.vishaya"
    repack_extract "$GOOD_BUNDLE" "$d"
    echo '{"family":"process","kind":"exec","tampered":true}' >> "$d/events.ndjson"
    newhash="$(sha256sum "$d/events.ndjson" | cut -d' ' -f1)"
    jq --arg h "$newhash" '.integrity.events_sha256=$h' "$d/manifest.json" > "$d/manifest.json.tmp" \
      && mv "$d/manifest.json.tmp" "$d/manifest.json"
    repack_finish "$d" "$tb"
    verr="$("$VISHAYA" tree "$tb" 2>&1 >/dev/null)"
    assert_contains "E5 (R2-02) manifest re-hash tamper -> signature INVALID" "$verr" "signature INVALID"
  else
    skip "E5 signature-catches-rehash tamper" "sha256sum unavailable"
  fi

  # E6: unsigned bundle is accepted but noted.
  d="$WORK/unsigned"; tb="$WORK/unsigned.vishaya"
  repack_extract "$GOOD_BUNDLE" "$d"
  jq 'del(.sig)' "$d/manifest.json" > "$d/manifest.json.tmp" && mv "$d/manifest.json.tmp" "$d/manifest.json"
  repack_finish "$d" "$tb"
  vout="$("$VISHAYA" tree "$tb" 2>&1)"
  assert_ok       "E7 unsigned bundle still opens"            "$VISHAYA" tree "$tb"
  assert_contains "E8 unsigned bundle is reported as unsigned" "$vout" "unsigned"

  # E9: schema major too new -> reader must refuse.
  d="$WORK/badver"; tb="$WORK/badver.vishaya"
  repack_extract "$GOOD_BUNDLE" "$d"
  jq '.schema_version="99.0.0"' "$d/manifest.json" > "$d/manifest.json.tmp" && mv "$d/manifest.json.tmp" "$d/manifest.json"
  repack_finish "$d" "$tb"
  assert_fail "E9 newer schema major is rejected" "$VISHAYA" tree "$tb"

  # E10 (manifest-v1 headline): tampering manifest METADATA — not content — is now
  # caught by the signature, which covers the whole canonical manifest. The old
  # two-hash scheme would have missed this entirely.
  if [ "$SIGNED" = 1 ]; then
    d="$WORK/metatamper"; tb="$WORK/metatamper.vishaya"
    repack_extract "$GOOD_BUNDLE" "$d"
    jq '.counts.events_total = (.counts.events_total + 999)' "$d/manifest.json" > "$d/manifest.json.tmp" \
      && mv "$d/manifest.json.tmp" "$d/manifest.json"
    repack_finish "$d" "$tb"
    verr="$("$VISHAYA" tree "$tb" 2>&1 >/dev/null)"
    assert_contains "E10 (P2) manifest-metadata tamper -> signature INVALID" "$verr" "signature INVALID"
  else
    skip "E10 manifest-metadata tamper" "good bundle unsigned"
  fi

  # E10b (F1): adding an UNKNOWN field to a signed manifest must invalidate the
  # signature. Verification canonicalizes the ON-DISK manifest bytes (spec §6), so
  # a field this reader doesn't model still counts — a struct-round-trip verifier
  # would silently drop it and wrongly report VALID. Inject with a byte-level edit
  # (not jq, which would also mangle the 64-bit clock ints and mask the point):
  # keep the leading "{" line, add the field, then append the rest verbatim.
  if [ "$SIGNED" = 1 ]; then
    d="$WORK/unknownfield"; tb="$WORK/unknownfield.vishaya"
    repack_extract "$GOOD_BUNDLE" "$d"
    { printf '{\n  "zz_injected_unknown_field": "attacker-controlled",\n'; \
      tail -n +2 "$d/manifest.json"; } > "$d/manifest.json.tmp" \
      && mv "$d/manifest.json.tmp" "$d/manifest.json"
    repack_finish "$d" "$tb"
    verr="$("$VISHAYA" tree "$tb" 2>&1 >/dev/null)"
    assert_contains "E10b (F1) unknown-field manifest tamper -> signature INVALID" "$verr" "signature INVALID"
  else
    skip "E10b unknown-field manifest tamper" "good bundle unsigned"
  fi

  # E11: `vishaya verify` on a good bundle -> exit 0, clear verdict.
  vout="$("$VISHAYA" verify "$GOOD_BUNDLE" 2>/dev/null)"
  assert_ok "E11 verify good bundle exits 0" "$VISHAYA" verify "$GOOD_BUNDLE"
  if [ "$SIGNED" = 1 ]; then
    assert_contains "E11b verify prints VERIFIED" "$vout" "VERIFIED"
  else
    assert_contains "E11b verify notes unsigned"  "$vout" "unsigned"
  fi

  # E12: `vishaya verify` on the tampered bundle from E3 -> non-zero exit.
  assert_fail "E12 verify tampered bundle exits non-zero" "$VISHAYA" verify "$WORK/tamper1.vishaya"

  # E13: --verify-key pinning (only meaningful when signed).
  if [ "$SIGNED" = 1 ]; then
    pk="$(mf "$GOOD_BUNDLE" '.sig.pubkey_b64')"
    assert_ok   "E13 verify --verify-key (correct) exits 0"       "$VISHAYA" verify "$GOOD_BUNDLE" --verify-key "$pk"
    assert_fail "E13b verify --verify-key (wrong) exits non-zero" "$VISHAYA" verify "$GOOD_BUNDLE" --verify-key "not-the-key"
  else
    skip "E13 --verify-key pinning" "good bundle unsigned"
  fi
else
  skip "E* integrity/signature" "needs a root capture + jq/zstd/tar"
fi

# ---------------------------------------------------------------------------
# Group F — Flags & signal handling (root)
# ---------------------------------------------------------------------------
group "F. Flags & signal handling (root)"

if [ "$CAN_CAPTURE" = 1 ]; then
  # F1 (R2-05): --allow-host-wide is accepted and produces a valid bundle.
  b="$WORK/hostwide.vishaya"
  if cap "$b" -- --target /bin/true --allow-host-wide; then
    assert_file "F1 (R2-05) --allow-host-wide produces a bundle" "$b"
  else
    fail "F1 (R2-05) --allow-host-wide" "capture failed; see $WORK/hostwide.vishaya.log"
  fi

  # F2: non-zero target exit is recorded, capture still succeeds.
  b="$WORK/false.vishaya"
  cap "$b" -- --target /bin/false >/dev/null 2>&1
  if [ -s "$b" ] && [ "$CAN_BUNDLE" = 1 ]; then
    ec="$(bundle_entry "$b" process_tree.json | jq '[.processes[].exit_code] | map(select(.!=null)) | .[0] // empty' 2>/dev/null)"
    assert_ge "F2 target exit_code recorded in tree" "$(printf '%s' "$ec" | grep -Ec '^[0-9]+$')" 1
  else
    skip "F2 target exit code" "no bundle / no jq"
  fi

  # F3: SIGINT during capture still finalizes a usable bundle.
  b="$WORK/sigint.vishaya"
  "$VISHAYA" capture --output "$b" --target /bin/sleep -- 30 >"$WORK/sigint.log" 2>&1 &
  cpid=$!
  sleep 2
  kill -INT "$cpid" 2>/dev/null
  wait "$cpid" 2>/dev/null
  if [ -s "$b" ]; then
    pass "F3 SIGINT finalizes a bundle"
    [ "$CAN_BUNDLE" = 1 ] && assert_ok "F4 SIGINT bundle is valid NDJSON" ndjson_valid "$b"
  else
    fail "F3 SIGINT finalizes a bundle" "no bundle after SIGINT; see $WORK/sigint.log"
  fi
else
  skip "F* flags & signals" "needs root"
fi

# ---------------------------------------------------------------------------
# Group G — Robustness under load & open-format (root)
# ---------------------------------------------------------------------------
group "G. Robustness & open format (root)"

if [ "$CAN_CAPTURE" = 1 ] && [ "$CAN_BUNDLE" = 1 ]; then
  # G1: heavy file activity — many opens. Bundle must stay valid; drops (if any)
  # must be reported, not silent.
  b="$WORK/load.vishaya"
  cap "$b" -- --target /bin/sh -- -c 'for i in $(seq 1 2000); do cat /etc/hostname >/dev/null; done' >/dev/null 2>&1
  if [ -s "$b" ]; then
    assert_ok "G1 heavy-load bundle is valid NDJSON" ndjson_valid "$b"
    total="$(mf "$b" '.counts.events_total')"
    dropped="$(mf "$b" '.counts.events_dropped')"
    assert_ge "G2 heavy load produced many events" "$total" 100
    info "     G-load: events_total=$total events_dropped=$dropped (drops are reported, not silent)"
    assert_match "G3 events_dropped is an integer (self-reported)" "$dropped" '^[0-9]+$'
  else
    skip "G1..G3 heavy load" "capture produced no bundle"
  fi

  # G4: open format — read a bundle with only standard tools, no vishaya.
  if [ -s "$GOOD_BUNDLE" ]; then
    manifest_name="$(zstd -dcq "$GOOD_BUNDLE" | tar -xO manifest.json 2>/dev/null | jq -r '.tool.name' 2>/dev/null)"
    assert_eq "G4 bundle readable with zstd+tar+jq only" "$manifest_name" "vishaya"
  fi
else
  skip "G* robustness" "needs root + jq/zstd/tar"
fi

# ---------------------------------------------------------------------------
# Group H — Artifact capture (root)  [v0.5]
# ---------------------------------------------------------------------------
group "H. Artifact capture (--capture-artifacts)"

if [ "$CAN_CAPTURE" = 1 ] && [ "$CAN_BUNDLE" = 1 ]; then
  ART="/tmp/vishaya-art-$$-drop.txt"
  ARTB="$WORK/artifacts.vishaya"
  rm -f "$ART"
  # Target creates a file (openat O_CREAT via '>') that survives to end-of-capture.
  cap "$ARTB" -- --target /bin/sh --capture-artifacts -- \
      -c "echo dropper-payload-$$ > $ART" >/dev/null 2>&1

  if [ -s "$ARTB" ]; then
    entries="$(bundle_list "$ARTB")"
    assert_contains "H1 bundle has artifacts.json"                "$entries" "artifacts.json"
    assert_ok       "H2 artifacts.json is valid JSON"            json_valid "$ARTB" artifacts.json
    assert_eq       "H3 coverage.artifacts_captured is true"     "$(mf "$ARTB" '.coverage.artifacts_captured')" "true"
    assert_ge       "H4 counts.artifacts_count >= 1"             "$(mf "$ARTB" '.counts.artifacts_count')" 1
    assert_match    "H5 integrity.artifacts_index_sha256 is 64 hex" \
                    "$(mf "$ARTB" '.integrity.artifacts_index_sha256')" '^[0-9a-f]{64}$'

    # The dropped file's absolute path is recorded as an ok artifact.
    okpaths="$(bundle_entry "$ARTB" artifacts.json | jq -r '.[] | select(.status=="ok") | .source_paths[]' 2>/dev/null)"
    assert_contains "H6 dropped file recorded as ok artifact"    "$okpaths" "$ART"

    if [ "$HAVE_SHA" = 1 ]; then
      # artifacts.json integrity matches the manifest.
      got_ai="$(bundle_entry "$ARTB" artifacts.json | sha256sum | cut -d' ' -f1)"
      assert_eq "H7 artifacts.json hash matches manifest" "$got_ai" "$(mf "$ARTB" '.integrity.artifacts_index_sha256')"
      # Content-addressing: each artifacts/<sha> entry name equals its content hash.
      aname="$(printf '%s\n' "$entries" | grep -m1 -E '^artifacts/[0-9a-f]{64}$')"
      if [ -n "$aname" ]; then
        asha="${aname#artifacts/}"
        got="$(bundle_entry "$ARTB" "$aname" | sha256sum | cut -d' ' -f1)"
        assert_eq "H8 artifact entry is content-addressed (name == sha256)" "$got" "$asha"
      else
        skip "H8 content-addressed name" "no ok artifact entry found"
      fi
    else
      skip "H7/H8 artifact hash cross-checks" "sha256sum unavailable"
    fi

    # `vishaya artifacts` lists the captured file.
    a_out="$("$VISHAYA" artifacts "$ARTB" 2>/dev/null)"
    assert_ok       "H9 artifacts command runs (no root)" "$VISHAYA" artifacts "$ARTB"
    assert_contains "H10 artifacts command lists the path" "$a_out" "$ART"

    # Full verify chain passes on a clean artifact bundle.
    assert_ok "H11 verify passes on artifact bundle" "$VISHAYA" verify "$ARTB"

    # Tamper an artifact's bytes (index unchanged) -> content check must fail.
    if [ "$HAVE_SHA" = 1 ]; then
      d="$WORK/arttamper"; tb="$WORK/arttamper.vishaya"
      repack_extract "$ARTB" "$d"
      atf="$(ls "$d"/artifacts/ 2>/dev/null | grep -m1 -E '^[0-9a-f]{64}$')"
      if [ -n "$atf" ]; then
        printf 'X' >> "$d/artifacts/$atf"
        repack_finish "$d" "$tb"
        verr="$("$VISHAYA" verify "$tb" 2>&1 >/dev/null)"
        assert_contains "H12 artifact content tamper -> content mismatch" "$verr" "artifact content mismatch"
        assert_fail     "H12b verify tampered artifact exits non-zero"     "$VISHAYA" verify "$tb"
      else
        skip "H12 artifact tamper" "no ok artifact file to tamper"
      fi
    else
      skip "H12 artifact tamper" "sha256sum unavailable"
    fi
  else
    skip "H1..H12 artifact capture" "capture produced no bundle"
  fi
  rm -f "$ART"

  # H13: a file exceeding --artifact-max-size is recorded but not captured.
  ART2="/tmp/vishaya-art-$$-big.txt"; B13="$WORK/arttoolarge.vishaya"; rm -f "$ART2"
  cap "$B13" -- --target /bin/sh --capture-artifacts --artifact-max-size 1 -- \
      -c "echo this-is-more-than-one-byte > $ART2" >/dev/null 2>&1
  if [ -s "$B13" ]; then
    st="$(bundle_entry "$B13" artifacts.json | jq -r --arg p "$ART2" '.[] | select(.source_paths[]?==$p) | .status' 2>/dev/null | head -n1)"
    assert_eq "H13 oversized file -> skipped_too_large" "$st" "skipped_too_large"
    assert_eq "H13b oversized file not counted as captured" "$(mf "$B13" '.counts.artifacts_count')" "0"
  else
    skip "H13 oversized artifact" "capture produced no bundle"
  fi
  rm -f "$ART2"

  # H14: a file created then deleted during the run is recorded as missing.
  ART3="/tmp/vishaya-art-$$-eph.txt"; B14="$WORK/artmissing.vishaya"; rm -f "$ART3"
  cap "$B14" -- --target /bin/sh --capture-artifacts -- \
      -c "echo ephemeral > $ART3; rm -f $ART3" >/dev/null 2>&1
  if [ -s "$B14" ]; then
    st="$(bundle_entry "$B14" artifacts.json | jq -r --arg p "$ART3" '.[] | select(.source_paths[]?==$p) | .status' 2>/dev/null | head -n1)"
    assert_eq "H14 created-then-deleted -> missing_at_finalize" "$st" "missing_at_finalize"
  else
    skip "H14 ephemeral artifact" "capture produced no bundle"
  fi
  rm -f "$ART3"
else
  skip "H* artifact capture" "needs root + jq/zstd/tar"
fi

# H15: a capture WITHOUT the flag emits no artifacts.json and still verifies.
if [ -s "$GOOD_BUNDLE" ] && [ "$CAN_BUNDLE" = 1 ]; then
  assert_not_contains "H15 no-flag capture has no artifacts.json" "$(bundle_list "$GOOD_BUNDLE")" "artifacts.json"
  assert_eq "H15b no-flag artifacts_captured is false" "$(mf "$GOOD_BUNDLE" '.coverage.artifacts_captured // false')" "false"
  assert_ok "H15c no-flag bundle still verifies" "$VISHAYA" verify "$GOOD_BUNDLE"
else
  skip "H15 no-flag compatibility" "no good bundle"
fi

# ---------------------------------------------------------------------------
print_summary
