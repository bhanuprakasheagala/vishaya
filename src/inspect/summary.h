#pragma once

/*
 * File Notes:
 * - `vishaya summary` — a one-screen verdict of what a captured target did:
 *   trust status, target, counts, a shallow process tree, notable network
 *   (DNS/HTTP/endpoints), and notable file activity (created/deleted/renamed).
 * - The "reach for it first" view. Read-only, no root.
 */

#include <string>

namespace vishaya::inspect {

// Print a compact one-screen summary of the bundle to stdout, led by a trust
// line (integrity + signature). Returns 0 on success, non-zero on read error.
int run_summary(const std::string& bundle_path);

} // namespace vishaya::inspect
