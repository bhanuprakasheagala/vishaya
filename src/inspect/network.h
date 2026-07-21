#pragma once

/*
 * File Notes:
 * - `vishaya network` subcommand: prints all network family events from a
 *   bundle. Covers socket lifecycle, DNS, and HTTP kinds.
 */

#include <string>

namespace vishaya::inspect {

int run_network(const std::string& bundle_path);

} // namespace vishaya::inspect
