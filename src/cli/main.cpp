/*
 * vishaya — entry point.
 *
 * Delegates immediately to cli::dispatch(). All argument parsing, subcommand
 * routing, and business logic live under src/cli/, src/inspect/, src/capture/,
 * and src/bundle/. This file exists only to be main().
 */

#include "cli/dispatcher.h"

int main(int argc, char** argv) {
  return vishaya::cli::dispatch(argc, argv);
}
