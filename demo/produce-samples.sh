#!/usr/bin/env bash
set -euo pipefail

# Vishaya sample-capture producer.
# Runs a series of benign targets through `vishaya capture` and writes numbered
# .vishaya bundles into ./samples/ (or $DEMO_DIR). Safe to re-run;
# existing bundles are overwritten.
#
# Requirements: Linux, root, ./build/vishaya + ./bpf/vishaya.bpf.o built.
#
# Usage:
#   sudo ./demo/produce-samples.sh
#   sudo DEMO_DIR=/tmp/vishaya-demo ./demo/produce-samples.sh
#   sudo VISHAYA=/path/to/vishaya ./demo/produce-samples.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VISHAYA="${VISHAYA:-${ROOT_DIR}/build/vishaya}"
BPF_OBJ="${BPF_OBJ:-${ROOT_DIR}/bpf/vishaya.bpf.o}"
DEMO_DIR="${DEMO_DIR:-${ROOT_DIR}/samples}"

pass() { echo "[pass] $1"; }
warn() { echo "[warn] $1"; }
fail() { echo "[fail] $1" >&2; exit 1; }

# --- preflight ---------------------------------------------------------------

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "Linux only (this is $(uname -s))"
fi
if [[ ${EUID} -ne 0 ]]; then
  fail "Must run as root: sudo $0"
fi
if [[ ! -x "${VISHAYA}" ]]; then
  fail "Missing binary: ${VISHAYA} (run ./scripts/linux.sh build)"
fi
if [[ ! -r "${BPF_OBJ}" ]]; then
  fail "Missing BPF object: ${BPF_OBJ} (run ./scripts/linux.sh bpf)"
fi

mkdir -p "${DEMO_DIR}"
pass "output directory: ${DEMO_DIR}"

# --- helpers -----------------------------------------------------------------

# capture <slug> <absolute-binary-path> [args...]
capture() {
  local slug="$1"; shift
  local binary="$1"; shift
  local out="${DEMO_DIR}/${slug}.vishaya"
  if [[ ! -x "${binary}" ]]; then
    warn "skipping ${slug}: ${binary} not found"
    return 0
  fi
  echo
  echo "=== capturing: ${slug} — ${binary} $* ==="
  "${VISHAYA}" capture --target "${binary}" --output "${out}" -- "$@" \
    || { warn "capture ${slug} failed; continuing"; return 0; }
  local size
  size=$(stat -c '%s' "${out}" 2>/dev/null || echo "?")
  pass "wrote ${out} (${size} bytes)"
}

find_bin() {
  local name="$1"
  command -v "${name}" 2>/dev/null || true
}

# --- samples ------------------------------------------------------------------

# 1. Simplest possible — process + file events only.
capture "01-ls-etc" /bin/ls -la /etc

# 2. Process tree — sh spawning a small pipeline of children.
capture "02-shell-pipeline" /bin/sh -c \
  'echo "vishaya demo" && ls /etc | head -5 && whoami && id'

# 3. Pure DNS demo — nslookup makes exactly one DNS query.
NSLOOKUP="$(find_bin nslookup)"
if [[ -n "${NSLOOKUP}" ]]; then
  capture "03-dns-nslookup" "${NSLOOKUP}" example.com 8.8.8.8
else
  warn "nslookup not installed; skipping 03-dns-nslookup"
fi

# 4. DNS + plaintext HTTP — the marquee demo. Shows dns-query, dns-answer,
#    tcp connect, http-request with Host header, http-response with status.
CURL="$(find_bin curl)"
if [[ -n "${CURL}" ]]; then
  capture "04-http-curl" "${CURL}" -s -o /dev/null http://example.com/
else
  warn "curl not installed; skipping 04-http-curl and 05-https-curl"
fi

# 5. DNS + HTTPS — shows encrypted connection metadata (no plaintext payload).
if [[ -n "${CURL}" ]]; then
  capture "05-https-curl" "${CURL}" -s -o /dev/null https://example.com/
fi

# 6. File lifecycle — create, read, unlink. Small, clean demo of file events.
capture "06-file-lifecycle" /bin/sh -c \
  'echo hello > /tmp/vishaya-demo-file && cat /tmp/vishaya-demo-file && rm /tmp/vishaya-demo-file'

# 7. Process tree with rename — write + rename + delete. Exercises renameat2.
capture "07-file-rename" /bin/sh -c \
  'echo x > /tmp/vishaya-a && mv /tmp/vishaya-a /tmp/vishaya-b && rm /tmp/vishaya-b'

# --- summary -----------------------------------------------------------------

echo
echo "=========================================="
echo "All samples written to: ${DEMO_DIR}"
ls -la "${DEMO_DIR}"
echo
echo "Try:"
echo "  ${VISHAYA} tree     ${DEMO_DIR}/02-shell-pipeline.vishaya"
echo "  ${VISHAYA} files    ${DEMO_DIR}/06-file-lifecycle.vishaya"
echo "  ${VISHAYA} network  ${DEMO_DIR}/04-http-curl.vishaya"
echo "  ${VISHAYA} timeline ${DEMO_DIR}/01-ls-etc.vishaya"
echo "  ${VISHAYA} verify   ${DEMO_DIR}/04-http-curl.vishaya"
echo
echo "To refresh the committed try-without-root fixtures:"
echo "  sudo $0   &&   git add samples/*.vishaya"
