#pragma once

/*
 * File Notes:
 * - Vishaya v0.1 Step 9: parses application-layer protocol payloads captured
 *   by the network probes and emits synthetic events (dns-query, dns-answer)
 *   as JSON strings ready to write to the WAL.
 * - Feeds off the captured payload_prefix in network_event. If payload is
 *   short or does not match a known protocol, returns an empty vector.
 * - v0.1 covers UDP:53 DNS only. HTTP over TCP is deferred to a follow-up
 *   Step-9 iteration.
 */

#include "decoder/decoder.h"  // vishaya::collector::EventVariant

#include <string>
#include <vector>

namespace vishaya::capture {

// Given a decoded event, produce zero or more synthetic protocol events as
// serialized JSON strings (each one line, no trailing newline). Called after
// the original event is emitted to the WAL; synthetic events are appended.
// Returns an empty vector for non-network events or when no protocol is
// recognized in the captured payload.
std::vector<std::string> synthesize_protocol_events(
    const vishaya::collector::EventVariant& event);

} // namespace vishaya::capture
