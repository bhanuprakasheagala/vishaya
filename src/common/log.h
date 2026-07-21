#pragma once

/*
 * File Notes:
 * - Minimal structured logger for Vishaya userspace. Writes ISO-8601 timestamped
 *   lines to stderr. Thread-safe. No async, no rotation, no external deps.
 */

#include <string_view>

namespace vishaya::log {

enum class Level { Debug, Info, Warn, Error };

void set_level(Level lvl);
void write(Level lvl, std::string_view msg);

inline void debug(std::string_view msg) { write(Level::Debug, msg); }
inline void info (std::string_view msg) { write(Level::Info,  msg); }
inline void warn (std::string_view msg) { write(Level::Warn,  msg); }
inline void error(std::string_view msg) { write(Level::Error, msg); }

} // namespace vishaya::log
