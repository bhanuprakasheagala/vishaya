#pragma once

/*
 * File Notes:
 * - `vishaya timeline` subcommand: prints all events in chronological order
 *   with a compact one-line-per-event representation.
 */

#include <string>

namespace vishaya::inspect {

int run_timeline(const std::string& bundle_path);

} // namespace vishaya::inspect
