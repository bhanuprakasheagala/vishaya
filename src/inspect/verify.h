#pragma once

/*
 * File Notes:
 * - `vishaya verify` — open a bundle, check its integrity hashes and signature,
 *   and print an explicit verdict. Optionally require a pinned public key.
 * - Read-only, no root. Exit code 0 = verified, non-zero = failed/unverifiable.
 */

#include <string>

namespace vishaya::inspect {

// Verify integrity + signature of the bundle. If pinned_key_b64 is non-empty,
// also require the bundle's signing key to equal it. Prints a verdict to stdout;
// returns 0 only when integrity holds, any present signature is valid, and the
// pin (if given) matches.
int run_verify(const std::string& bundle_path, const std::string& pinned_key_b64);

} // namespace vishaya::inspect
