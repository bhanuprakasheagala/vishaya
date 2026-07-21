#pragma once

/*
 * File Notes:
 * - Serializer: vishaya::collector::EventVariant  ->  Vishaya-spec JSON string
 *   (single line, no trailing newline). Output matches
 *   docs/BUNDLE-SPEC-v0.1.md §4 (envelope + family payloads).
 * - The vishaya_collector namespace is the pre-pivot codebase we inherit; we do not
 *   modify its types. This file is the boundary between vishaya_collector's C-struct
 *   world and Vishaya's JSON schema world.
 * - Network kinds emitted here cover the socket-level subset from
 *   include/event_schema.h. DNS + HTTP kinds are added in Step 9 (userspace
 *   payload parsing).
 */

#include "decoder/decoder.h"  // vishaya::collector::EventVariant

#include <string>

namespace vishaya::capture {

// Serialize one event to a JSON object string (no trailing newline).
// Never throws — best-effort; returns "{}" for unknown variant tags.
std::string event_to_json(const vishaya::collector::EventVariant& event);

} // namespace vishaya::capture
