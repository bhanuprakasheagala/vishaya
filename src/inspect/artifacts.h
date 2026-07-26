#pragma once

#include <string>

namespace vishaya::inspect {

// Lists the files captured into the bundle's artifacts/ directory: content hash,
// size, status, and the source path(s) that produced each. Verifies the bundle
// first (warnings to stderr). Returns 0 on success, 1 on error.
int run_artifacts(const std::string& bundle_path);

} // namespace vishaya::inspect
