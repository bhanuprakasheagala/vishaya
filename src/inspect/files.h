#pragma once

/*
 * File Notes:
 * - `vishaya files` subcommand: prints all file family events from a bundle.
 */

#include <string>

namespace vishaya::inspect {

int run_files(const std::string& bundle_path);

} // namespace vishaya::inspect
