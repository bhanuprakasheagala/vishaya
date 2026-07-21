#pragma once

/*
 * File Notes:
 * - Top-level CLI dispatcher for the `vishaya` binary. Parses argv, routes to
 *   the appropriate subcommand handler (capture / tree / files / network /
 *   timeline). Returns process exit code.
 */

namespace vishaya::cli {

int dispatch(int argc, char** argv);

} // namespace vishaya::cli
