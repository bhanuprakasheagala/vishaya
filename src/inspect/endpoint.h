#pragma once

/*
 * File Notes:
 * - Shared formatter for a network endpoint object (the `remote`/`local` JSON
 *   sub-object carried on network events).
 * - Single source of truth for the "addr:port" / "[v6]:port" / "unix:path"
 *   rendering used by the summary, network, and diff inspect views, so their
 *   output stays consistent and the logic lives in one place.
 */

#include "inspect/render.h"

#include <nlohmann/json.hpp>

#include <string>

namespace vishaya::inspect {

// Render an endpoint JSON object to a display string:
//   - unix socket  -> "unix:<path>"        (when a path is present)
//   - IPv6         -> "[<addr>]:<port>"
//   - IPv4 / other -> "<addr>:<port>"
// Returns "" when the object is absent/empty or carries no usable address.
inline std::string format_remote_endpoint(const nlohmann::json& ep) {
  if (!ep.is_object()) return {};
  // addr/path are attacker-controlled bytes from the bundle — scrub before display.
  const std::string addr = scrub_for_terminal(ep.value("addr", ""));
  const int         port = ep.value("port", 0);
  const std::string path = scrub_for_terminal(ep.value("path", ""));
  if (!path.empty()) return "unix:" + path;
  if (addr.empty()) return {};
  if (ep.value("family", "") == "inet6") return "[" + addr + "]:" + std::to_string(port);
  return addr + ":" + std::to_string(port);
}

}  // namespace vishaya::inspect
