# shellcheck shell=bash
#
# tests/lib.sh — shared helpers for the Vishaya functional test suite.
#
# Sourced by run-tests.sh. Provides a tiny assertion framework (pass/fail/skip
# counters + a summary), plus helpers to peek inside a .vishaya bundle without
# needing the tool itself (tar.zst + jq), so the tests can independently verify
# what the tool produced.
#
# No `set -e` on purpose: a failed assertion must NOT abort the run — we count it
# and continue so one run reports every problem.

# ---- output -----------------------------------------------------------------

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_CYN=$'\033[36m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
else
  C_RED=; C_GRN=; C_YEL=; C_CYN=; C_DIM=; C_RST=
fi

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_NAMES=()

info()  { printf '%s[info]%s %s\n'  "$C_CYN" "$C_RST" "$*"; }
warn()  { printf '%s[warn]%s %s\n'  "$C_YEL" "$C_RST" "$*" >&2; }
group() { printf '\n%s══ %s ══%s\n' "$C_CYN" "$*" "$C_RST"; }

pass() { PASS_COUNT=$((PASS_COUNT+1)); printf '  %s✓ PASS%s %s\n' "$C_GRN" "$C_RST" "$1"; }
skip() { SKIP_COUNT=$((SKIP_COUNT+1)); printf '  %s• SKIP%s %s%s%s\n' "$C_YEL" "$C_RST" "$1" "${2:+ — }" "${2:-}"; }
fail() {
  FAIL_COUNT=$((FAIL_COUNT+1))
  FAILED_NAMES+=("$1")
  printf '  %s✗ FAIL%s %s\n' "$C_RED" "$C_RST" "$1"
  [ -n "${2:-}" ] && printf '        %s%s%s\n' "$C_DIM" "$2" "$C_RST"
  return 0
}

# ---- assertions -------------------------------------------------------------

# assert_ok NAME CMD...  — pass if the command exits 0.
assert_ok() {
  local name="$1"; shift
  local out
  if out=$("$@" 2>&1); then pass "$name"
  else fail "$name" "exit $? from: $* ${out:+| $out}"; fi
}

# assert_fail NAME CMD... — pass if the command exits NON-zero (expected error).
assert_fail() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$name" "expected non-zero exit from: $*"
  else pass "$name"; fi
}

# assert_contains NAME HAYSTACK NEEDLE
assert_contains() {
  local name="$1" hay="$2" needle="$3"
  case "$hay" in
    *"$needle"*) pass "$name" ;;
    *) fail "$name" "expected to contain: [$needle]" ;;
  esac
}

# assert_not_contains NAME HAYSTACK NEEDLE
assert_not_contains() {
  local name="$1" hay="$2" needle="$3"
  case "$hay" in
    *"$needle"*) fail "$name" "did NOT expect: [$needle]" ;;
    *) pass "$name" ;;
  esac
}

# assert_eq NAME GOT WANT
assert_eq() {
  local name="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then pass "$name"
  else fail "$name" "got [$got] want [$want]"; fi
}

# assert_ge NAME GOT MIN  — numeric got >= min
assert_ge() {
  local name="$1" got="$2" min="$3"
  if [ "${got:-0}" -ge "$min" ] 2>/dev/null; then pass "$name"
  else fail "$name" "got [$got] want >= [$min]"; fi
}

# assert_file NAME PATH
assert_file() {
  local name="$1" path="$2"
  if [ -s "$path" ]; then pass "$name"
  else fail "$name" "missing or empty file: $path"; fi
}

# assert_match NAME STRING REGEX  (POSIX ERE via grep -E)
assert_match() {
  local name="$1" str="$2" re="$3"
  if printf '%s' "$str" | grep -Eq "$re"; then pass "$name"
  else fail "$name" "no match for /$re/ in: $str"; fi
}

# ---- bundle inspection (independent of the vishaya binary) -------------------

# bundle_entry BUNDLE ENTRYNAME  — stream one archive member to stdout.
bundle_entry() {
  zstd -dcq "$1" 2>/dev/null | tar -xO -f - "$2" 2>/dev/null
}

# bundle_list BUNDLE — list archive members.
bundle_list() {
  zstd -dcq "$1" 2>/dev/null | tar -t -f - 2>/dev/null
}

# mf BUNDLE JQ_EXPR — evaluate a jq expression against manifest.json (raw output).
mf() {
  bundle_entry "$1" manifest.json | jq -r "$2" 2>/dev/null
}

# ndjson_valid BUNDLE — 0 if every events.ndjson line is valid JSON.
ndjson_valid() {
  bundle_entry "$1" events.ndjson | jq -e -c . >/dev/null 2>&1
}

# json_valid BUNDLE ENTRY — 0 if the named entry parses as a single JSON value.
json_valid() {
  bundle_entry "$1" "$2" | jq -e . >/dev/null 2>&1
}

# event_count BUNDLE — number of non-empty events.ndjson lines.
event_count() {
  bundle_entry "$1" events.ndjson | grep -c '.' 2>/dev/null || true
}

# events_where BUNDLE JQ_SELECT — print events matching a jq boolean expr.
# e.g. events_where b '.family=="process" and .kind=="exec"'
events_where() {
  bundle_entry "$1" events.ndjson | jq -c "select($2)" 2>/dev/null
}

# repack BUNDLE OUTDIR OUT_BUNDLE — extract BUNDLE to OUTDIR so callers can
# mutate files, then (via repack_finish) re-archive to OUT_BUNDLE.
repack_extract() {
  local bundle="$1" dir="$2"
  mkdir -p "$dir"
  zstd -dcq "$bundle" 2>/dev/null | tar -x -f - -C "$dir" 2>/dev/null
}

repack_finish() {
  local dir="$1" out="$2"
  local entries=()
  for e in manifest.json events.ndjson process_tree.json artifacts; do
    [ -e "$dir/$e" ] && entries+=("$e")
  done
  ( cd "$dir" && tar -cf - "${entries[@]}" 2>/dev/null ) | zstd -qc > "$out" 2>/dev/null
}

# ---- summary ----------------------------------------------------------------

print_summary() {
  printf '\n%s──────── summary ────────%s\n' "$C_CYN" "$C_RST"
  printf '  %spassed: %d%s   %sfailed: %d%s   %sskipped: %d%s\n' \
    "$C_GRN" "$PASS_COUNT" "$C_RST" \
    "$C_RED" "$FAIL_COUNT" "$C_RST" \
    "$C_YEL" "$SKIP_COUNT" "$C_RST"
  if [ "$FAIL_COUNT" -gt 0 ]; then
    printf '  %sfailures:%s\n' "$C_RED" "$C_RST"
    for n in "${FAILED_NAMES[@]}"; do printf '    - %s\n' "$n"; done
    return 1
  fi
  return 0
}
