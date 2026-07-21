#pragma once

/*
 * File Notes:
 * - `vishaya tree` subcommand: prints the process tree from a .vishaya bundle
 *   as an indented ASCII tree.
 */

#include <string>

namespace vishaya::inspect {

// Returns process exit code (0 = success, non-zero = error).
int run_tree(const std::string& bundle_path);

} // namespace vishaya::inspect
