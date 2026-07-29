#pragma once

#include <string>
#include <string_view>

namespace vishaya::inspect {

// Make a bundle-derived string safe to print to a terminal.
//
// Strings that come out of a `.vishaya` bundle — process comm, exec paths, command
// lines, file paths, DNS names, HTTP host/path, socket addresses — are attacker-
// controlled: a hostile bundle can embed ANSI escape sequences in them. Printed raw,
// those can rewrite the analyst's terminal, hide or spoof output, or set the window
// title. Since opening hostile artifacts is exactly this tool's job, every untrusted
// string MUST pass through here before reaching std::cout.
//
// Policy: replace ASCII control characters (< 0x20, including newline/tab/ESC) and DEL
// (0x7f) with '?'. High bytes (>= 0x80) are left as-is — they render as UTF-8 or
// harmless mojibake, but cannot drive an escape sequence.
inline std::string scrub_for_terminal(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (unsigned char c : s) {
    out.push_back((c < 0x20 || c == 0x7f) ? '?' : static_cast<char>(c));
  }
  return out;
}

} // namespace vishaya::inspect
