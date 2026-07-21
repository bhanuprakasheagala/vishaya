/*
 * File Notes:
 * - Aggregates the domain-specific kernel modules into one BPF translation unit.
 * - Keeps the build entrypoint stable while splitting code by concern.
 */

#include "vishaya_process.bpf.c"
#include "vishaya_file.bpf.c"
#include "vishaya_network.bpf.c"
#include "vishaya_syscall.bpf.c"
