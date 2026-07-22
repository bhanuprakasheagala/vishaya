#!/usr/bin/env bash
set -euo pipefail

# Vishaya build helpers. Linux-only. Wraps cmake for the userspace binaries and
# runs clang directly for the BPF object (cmake delegates to this script for
# BPF via the bpf_object custom target).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BPF_SRC="${ROOT_DIR}/bpf/vishaya.bpf.c"
BPF_OBJ="${ROOT_DIR}/bpf/vishaya.bpf.o"
VMLINUX_H="${ROOT_DIR}/bpf/vmlinux.h"

pass() { echo "[pass] $1"; }
warn() { echo "[warn] $1"; }
fail() { echo "[fail] $1"; exit 1; }

ensure_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    fail "Linux host required (found $(uname -s))"
  fi
}

check_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    fail "required tool missing: ${cmd}"
  fi
  pass "tool found: ${cmd}"
}

pick_clang() {
  local clang_bin="${CLANG:-}"
  if [[ -n "${clang_bin}" ]]; then
    echo "${clang_bin}"
    return 0
  fi
  local candidate
  for candidate in clang clang-18 clang-17 clang-16 clang-15 clang-14 clang-13; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}

build_userspace() {
  ensure_linux
  cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/build"
  cmake --build "${ROOT_DIR}/build" -j
  pass "built: ${ROOT_DIR}/build/{vishaya,isolation_probe,bundle_probe}"
}

build_bpf() {
  ensure_linux

  local clang_bin
  clang_bin="$(pick_clang)" || fail "clang not found (required for BPF object build)"

  check_cmd bpftool

  if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    fail "kernel BTF not available at /sys/kernel/btf/vmlinux"
  fi

  local target_arch
  case "$(uname -m)" in
    x86_64) target_arch="x86" ;;
    aarch64|arm64) target_arch="arm64" ;;
    armv7l) target_arch="arm" ;;
    riscv64) target_arch="riscv" ;;
    ppc64le) target_arch="powerpc" ;;
    s390x) target_arch="s390" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac

  bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${VMLINUX_H}"

  # Ubuntu/Debian multiarch include dir for stdint.h when using --target=bpf.
  local gcc_triplet=""
  local multiarch_include=""
  if command -v gcc >/dev/null 2>&1; then
    gcc_triplet="$(gcc -dumpmachine 2>/dev/null || true)"
  fi
  if [[ -n "${gcc_triplet}" && -d "/usr/include/${gcc_triplet}" ]]; then
    multiarch_include="/usr/include/${gcc_triplet}"
  fi

  local extra_include_flags=()
  if [[ -n "${multiarch_include}" ]]; then
    extra_include_flags+=("-I${multiarch_include}")
  fi

  "${clang_bin}" \
    -g -O2 -target bpf \
    -D__TARGET_ARCH_${target_arch} \
    -I"${ROOT_DIR}/bpf" \
    -I"${ROOT_DIR}/include" \
    -mllvm -bpf-stack-size=8192 \
    "${extra_include_flags[@]}" \
    -c "${BPF_SRC}" \
    -o "${BPF_OBJ}"

  pass "built ${BPF_OBJ} (clang=${clang_bin}${multiarch_include:+, multiarch=${multiarch_include}})"
}

host_check() {
  ensure_linux

  echo "[info] kernel: $(uname -r)"
  echo "[info] arch:   $(uname -m)"

  # Minimum kernel: 5.8+ (BPF_MAP_TYPE_RINGBUF). Parse carefully; release
  # strings can be "5.15.0-73-generic" or "6.1.0-rc3" — extract major.minor only.
  local krel maj min
  krel="$(uname -r)"
  maj="${krel%%.*}"
  min="${krel#*.}"; min="${min%%[.-]*}"
  if [[ "${maj}" =~ ^[0-9]+$ && "${min}" =~ ^[0-9]+$ ]]; then
    if (( maj > 5 || ( maj == 5 && min >= 8 ) )); then
      pass "kernel ${krel} meets minimum requirement (5.8+)"
    else
      fail "kernel ${krel} is too old; vishaya requires Linux 5.8+. Ubuntu 20.04: sudo apt install linux-generic-hwe-20.04 then reboot"
    fi
  else
    warn "cannot parse kernel version '${krel}'; verify manually (need 5.8+)"
  fi

  check_cmd gcc
  check_cmd g++
  check_cmd cmake
  check_cmd pkg-config
  check_cmd clang
  check_cmd bpftool

  if [[ -r /sys/kernel/btf/vmlinux ]]; then
    pass "kernel BTF present: /sys/kernel/btf/vmlinux"
  else
    fail "kernel BTF missing: /sys/kernel/btf/vmlinux"
  fi

  # cgroup v2: presence of cgroup.controllers in the root is the authoritative
  # check. It exists on a pure cgroup v2 mount and is absent on cgroup v1 and
  # hybrid-mode roots.
  local cgroup_root="${VISHAYA_CGROUP_ROOT:-/sys/fs/cgroup}"
  if [[ -f "${cgroup_root}/cgroup.controllers" ]]; then
    pass "cgroup v2 unified hierarchy at ${cgroup_root}"
  else
    fail "cgroup v2 not detected at ${cgroup_root}. Vishaya requires cgroup v2. Ubuntu 20.04: add 'systemd.unified_cgroup_hierarchy=1' to GRUB_CMDLINE_LINUX in /etc/default/grub, run update-grub, then reboot. Ubuntu 22.04+/Fedora 31+/Arch Linux: cgroup v2 is the default."
  fi

  if [[ -r /proc/config.gz ]]; then
    zgrep -q '^CONFIG_BPF=y' /proc/config.gz && pass 'CONFIG_BPF=y' || warn 'CONFIG_BPF not confirmed'
    zgrep -q '^CONFIG_BPF_SYSCALL=y' /proc/config.gz && pass 'CONFIG_BPF_SYSCALL=y' || warn 'CONFIG_BPF_SYSCALL not confirmed'
  else
    warn '/proc/config.gz not readable; cannot validate kernel config flags'
  fi

  if [[ ${EUID} -eq 0 ]]; then
    pass 'running as root'
  else
    warn 'not running as root; vishaya capture requires root'
  fi

  echo "[hint] Debian/Ubuntu:  sudo apt install build-essential cmake clang llvm pkg-config libelf-dev libbpf-dev bpftool libzstd-dev libarchive-dev nlohmann-json3-dev libcli11-dev libssl-dev"
  echo "[hint] Fedora/RHEL:    sudo dnf install gcc-c++ cmake clang llvm pkgconf elfutils-libelf-devel libbpf-devel bpftool libzstd-devel libarchive-devel json-devel cli11-devel openssl-devel"
  echo "[hint] Arch:           sudo pacman -S base-devel cmake clang llvm pkgconf libelf libbpf bpftool zstd libarchive nlohmann-json cli11 openssl"
  echo "[hint] OpenSUSE:       sudo zypper install gcc-c++ cmake clang llvm-devel pkgconf-pkg-config libelf-devel libbpf-devel bpftool libzstd-devel libarchive-devel nlohmann_json-devel openssl-devel"
  echo "[hint]                 (CLI11 not in standard OpenSUSE repos; install manually from https://github.com/CLIUtils/CLI11)"

  pass "host prerequisites checked"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/linux.sh <command>

Commands:
  help     Show this help.
  build    Build vishaya userspace binaries (cmake).
  bpf      Build BPF object (clang direct).
  all      Build userspace + BPF object.
  check    Run host prerequisite checks and print install hints.
USAGE
}

main() {
  local cmd="${1:-help}"
  case "${cmd}" in
    help|-h|--help) usage ;;
    build)          build_userspace ;;
    bpf)            build_bpf ;;
    all)            build_userspace; build_bpf ;;
    check)          host_check ;;
    *)              fail "unknown command: ${cmd}. Run ./scripts/linux.sh help" ;;
  esac
}

main "${1:-help}"
