#pragma once

/*
 * File Notes:
 * - `vishaya diff a.vishaya b.vishaya` — a SEMANTIC comparison of two captures:
 *   what did B do that A didn't, and vice versa. Compares sets of behaviours
 *   (executed binaries, files by operation, DNS names, HTTP requests, network
 *   endpoints), NOT raw event streams — so volatile identifiers (PIDs, absolute
 *   timestamps, addresses) are excluded automatically. This is the "did the same
 *   sample behave differently across two runs / two environments?" workflow.
 * - Read-only, no root.
 */

#include <string>

namespace vishaya::inspect {

// Print a semantic diff of two bundles to stdout.
// Exit code: 0 = no semantic differences, 1 = differences found, 2 = read error.
int run_diff(const std::string& bundle_a, const std::string& bundle_b);

} // namespace vishaya::inspect
