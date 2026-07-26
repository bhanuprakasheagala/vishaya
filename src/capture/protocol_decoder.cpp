#include "capture/protocol_decoder.h"

#include "event_schema.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <type_traits>
#include <vector>

namespace vishaya::capture {

namespace {

using json = nlohmann::json;

template <size_t N>
std::string safe_str(const char (&arr)[N]) {
  return std::string(arr, ::strnlen(arr, N));
}

// ---- DNS wire-format parser (RFC 1035, minimal) -----------------------------

// Parse a domain name starting at offset `pos` into `payload` of `plen` bytes.
// Returns the parsed name (e.g. "example.com") and updates `pos` past the
// name. Supports compression pointers (needed for responses). Returns empty on
// malformed input.
std::string dns_parse_name(const uint8_t* payload, size_t plen, size_t& pos,
                           int recursion_depth = 0) {
  if (recursion_depth > 16) return {};  // guard against pointer loops
  std::string name;
  bool                jumped = false;
  size_t              orig_pos = pos;

  while (true) {
    if (pos >= plen) return {};
    const uint8_t len_byte = payload[pos];
    if (len_byte == 0) {
      ++pos;
      break;
    }
    if ((len_byte & 0xC0) == 0xC0) {
      // Compression pointer: high 2 bits set, next 14 bits = offset.
      if (pos + 1 >= plen) return {};
      const uint16_t ptr = ((static_cast<uint16_t>(len_byte) & 0x3F) << 8) |
                           payload[pos + 1];
      if (!jumped) {
        orig_pos = pos + 2;
        jumped   = true;
      }
      pos = ptr;
      if (recursion_depth > 16) return {};
      // Recurse to follow pointer.
      const std::string tail =
          dns_parse_name(payload, plen, pos, recursion_depth + 1);
      if (!name.empty() && !tail.empty()) name.push_back('.');
      name += tail;
      pos = jumped ? orig_pos : pos;
      return name;
    }
    if ((len_byte & 0xC0) != 0) return {};  // reserved/unused bits set
    const size_t label_len = len_byte;
    ++pos;
    if (pos + label_len > plen) return {};
    if (!name.empty()) name.push_back('.');
    name.append(reinterpret_cast<const char*>(payload + pos), label_len);
    pos += label_len;
  }

  if (jumped) pos = orig_pos;
  return name;
}

const char* dns_type_name(uint16_t t) {
  switch (t) {
    case 1:   return "A";
    case 2:   return "NS";
    case 5:   return "CNAME";
    case 6:   return "SOA";
    case 12:  return "PTR";
    case 15:  return "MX";
    case 16:  return "TXT";
    case 28:  return "AAAA";
    case 33:  return "SRV";
    case 41:  return "OPT";
    case 65:  return "HTTPS";
    case 255: return "ANY";
    default:  return nullptr;  // caller falls back to "TYPE<n>"
  }
}

std::string dns_type_str(uint16_t t) {
  if (const char* n = dns_type_name(t); n) return n;
  return "TYPE" + std::to_string(t);
}

const char* dns_class_str(uint16_t c) {
  return c == 1 ? "IN" : "OTHER";
}

// Format a resource-record's rdata based on type. Returns empty for unknown/
// binary types (we don't hex-dump in v0.1 to keep the JSON readable).
std::string dns_format_rdata(uint16_t type, const uint8_t* rdata, uint16_t rdlen,
                             const uint8_t* payload, size_t plen) {
  if (type == 1 && rdlen == 4) {
    // A record: IPv4 address
    char buf[INET_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET, rdata, buf, sizeof(buf))) return buf;
    return {};
  }
  if (type == 28 && rdlen == 16) {
    // AAAA record: IPv6 address
    char buf[INET6_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET6, rdata, buf, sizeof(buf))) return buf;
    return {};
  }
  if (type == 5 || type == 2 || type == 12) {
    // CNAME/NS/PTR: rdata is a domain name (with compression).
    size_t local_pos = static_cast<size_t>(rdata - payload);
    if (local_pos >= plen) return {};
    return dns_parse_name(payload, plen, local_pos);
  }
  return {};
}

// Header envelope shared with the network event to keep sender identity.
json make_envelope(const network_event& e, const char* kind) {
  return json{
    {"ts_ns",  e.hdr.ts_ns},
    {"family", "network"},
    {"kind",   kind},
    {"pid",    e.hdr.pid},
    {"tgid",   e.hdr.tgid},
    {"ppid",   e.hdr.ppid},
    {"uid",    e.hdr.uid},
    {"gid",    e.hdr.gid},
    {"comm",   safe_str(e.hdr.comm)},
  };
}

json endpoint_json(const network_endpoint& ep) {
  json j;
  j["family"] = ep.family == 2 ? "inet" : ep.family == 10 ? "inet6"
                                        : ep.family == 1  ? "unix" : "other";
  j["port"]   = ep.port;
  j["addr"]   = "";
  if (ep.family == 2) {
    char buf[INET_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET, ep.addr, buf, sizeof(buf))) j["addr"] = buf;
  } else if (ep.family == 10) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET6, ep.addr, buf, sizeof(buf))) j["addr"] = buf;
  }
  return j;
}

// Extract synthesized DNS events (query and/or answers) from a network_event's
// captured payload. Returns empty when payload is not DNS-shaped.
std::vector<std::string> try_decode_dns(const network_event& e) {
  std::vector<std::string> out;

  // Only consider send/recv paths that captured payload from UDP:53.
  if (e.payload_len < 12) return out;               // DNS header is 12 bytes
  const bool is_send = (e.kind == NETWORK_SENDTO || e.kind == NETWORK_SENDMSG);
  const bool is_recv = (e.kind == NETWORK_RECVFROM || e.kind == NETWORK_RECVMSG);
  if (!is_send && !is_recv) return out;

  // v0.1 decodes UDP DNS only. DNS-over-TCP prepends a 2-byte length field that
  // would misparse as the DNS header (ID/flags), so skip flows we know are TCP.
  // UNKNOWN transport is still allowed through: an early recvfrom can reach us
  // before socket-state enrichment has classified the transport (see port note).
  if (e.transport == NETWORK_TRANSPORT_TCP) return out;

  const uint16_t remote_port = static_cast<uint16_t>(e.remote.port);
  const uint16_t local_port  = static_cast<uint16_t>(e.local.port);
  // Match either direction's port 53. UDP transport preferred; be lenient
  // because transport may be "unknown" for early recvfrom before we've
  // enriched from socket state.
  const bool port_matches =
      (is_send && remote_port == 53) || (is_recv && local_port == 53) ||
      (is_recv && remote_port == 53);
  if (!port_matches) return out;

  const uint8_t*  p    = e.payload_prefix;
  // Clamp to the physical buffer capacity. payload_len is set by the BPF probe
  // and copied verbatim by the decoder (which validates struct size but not this
  // field), so a buggy/ABI-mismatched producer or a decode skew could present a
  // value beyond the fixed payload_prefix[] size. Only the first
  // VISHAYA_NET_PAYLOAD_LEN bytes are ever valid; the live BPF producer already
  // clamps at capture time, so this is a no-op in normal operation and pure
  // defense-in-depth against an out-of-bounds read on the parse below.
  const size_t    plen = std::min<size_t>(e.payload_len, VISHAYA_NET_PAYLOAD_LEN);

  const uint16_t id      = static_cast<uint16_t>((p[0] << 8) | p[1]);
  const uint16_t flags   = static_cast<uint16_t>((p[2] << 8) | p[3]);
  const uint16_t qdcount = static_cast<uint16_t>((p[4] << 8) | p[5]);
  const uint16_t ancount = static_cast<uint16_t>((p[6] << 8) | p[7]);

  const bool is_response = (flags & 0x8000) != 0;

  // Parse first question (if any).
  size_t      pos = 12;
  std::string qname;
  uint16_t    qtype = 0, qclass = 0;
  if (qdcount >= 1 && pos < plen) {
    qname = dns_parse_name(p, plen, pos);
    if (pos + 4 <= plen) {
      qtype  = static_cast<uint16_t>((p[pos] << 8) | p[pos + 1]);
      qclass = static_cast<uint16_t>((p[pos + 2] << 8) | p[pos + 3]);
      pos += 4;
    } else {
      qname.clear();  // truncated question section
    }
  }

  if (qname.empty()) return out;  // not enough payload to be useful

  json dns;
  dns["id"]     = id;
  dns["qname"]  = qname;
  dns["qtype"]  = dns_type_str(qtype);
  dns["qclass"] = dns_class_str(qclass);

  if (is_response) {
    // Parse answers section (up to ancount records or truncation).
    json answers = json::array();
    for (uint16_t i = 0; i < ancount; ++i) {
      if (pos + 10 > plen) break;
      const std::string name = dns_parse_name(p, plen, pos);
      if (pos + 10 > plen) break;
      const uint16_t atype  = static_cast<uint16_t>((p[pos] << 8) | p[pos + 1]);
      const uint16_t aclass = static_cast<uint16_t>((p[pos + 2] << 8) | p[pos + 3]);
      const uint32_t ttl    = (static_cast<uint32_t>(p[pos + 4]) << 24) |
                              (static_cast<uint32_t>(p[pos + 5]) << 16) |
                              (static_cast<uint32_t>(p[pos + 6]) << 8) |
                              static_cast<uint32_t>(p[pos + 7]);
      const uint16_t rdlen  = static_cast<uint16_t>((p[pos + 8] << 8) | p[pos + 9]);
      pos += 10;
      if (pos + rdlen > plen) break;
      const std::string rdata = dns_format_rdata(atype, p + pos, rdlen, p, plen);
      pos += rdlen;

      json ans;
      ans["name"]  = name;
      ans["type"]  = dns_type_str(atype);
      ans["class"] = dns_class_str(aclass);
      ans["ttl"]   = ttl;
      if (!rdata.empty()) ans["rdata"] = rdata;
      answers.push_back(std::move(ans));
    }
    dns["answers"] = std::move(answers);
  }

  const char* kind = is_response ? "dns-answer" : "dns-query";
  json env = make_envelope(e, kind);
  json data;
  data["transport"] = "udp";
  data["remote"]    = endpoint_json(e.remote);
  data["dns"]       = std::move(dns);
  env["data"]       = std::move(data);
  // Payload-derived strings (DNS qname, HTTP host/path) can carry non-UTF-8
  // bytes; use the 'replace' handler so dump() never throws and drops the event.
  out.push_back(env.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
  return out;
}

// ---- HTTP plaintext detector (RFC 7230 method line + Host header) -----------

// True if payload looks like an HTTP/1.x response status line ("HTTP/1.0 200 OK").
bool looks_like_http_response(std::string_view p) {
  return p.size() >= 12 &&
         (p.compare(0, 7, "HTTP/1.") == 0);
}

// Return the HTTP method as string_view if the payload starts with a known
// method followed by a space; empty view otherwise.
std::string_view leading_http_method(std::string_view p) {
  static constexpr const char* kMethods[] = {
      "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
      "PATCH ", "OPTIONS ", "CONNECT ", "TRACE ",
  };
  for (const char* m : kMethods) {
    const size_t len = std::strlen(m);
    if (p.size() >= len && p.compare(0, len, m) == 0) {
      return std::string_view(m, len - 1);  // strip trailing space
    }
  }
  return {};
}

std::vector<std::string> try_decode_http(const network_event& e) {
  std::vector<std::string> out;

  if (e.payload_len < 12) return out;

  // HTTP travels over write/read/sendto (TCP)/recvfrom (TCP)/sendmsg/recvmsg.
  const bool is_send = e.kind == NETWORK_WRITE   || e.kind == NETWORK_SENDTO ||
                       e.kind == NETWORK_SENDMSG;
  const bool is_recv = e.kind == NETWORK_READ    || e.kind == NETWORK_RECVFROM ||
                       e.kind == NETWORK_RECVMSG;
  if (!is_send && !is_recv) return out;

  // Skip if remote port is 53 (DNS; already handled by try_decode_dns).
  if (e.remote.port == 53 || e.local.port == 53) return out;

  // Clamp to the physical buffer capacity (see try_decode_dns): defense-in-depth
  // against a payload_len that exceeds payload_prefix[] on the live decode path.
  const size_t plen = std::min<size_t>(e.payload_len, VISHAYA_NET_PAYLOAD_LEN);
  const std::string_view payload(
      reinterpret_cast<const char*>(e.payload_prefix), plen);

  // ---- Response ("HTTP/1.1 200 OK\r\n...") -----------------------------
  if (looks_like_http_response(payload)) {
    const size_t sp1 = payload.find(' ');
    if (sp1 == std::string_view::npos || sp1 + 4 > payload.size()) return out;
    const size_t sp2 = payload.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return out;

    const std::string version(payload.substr(0, sp1));
    const std::string_view status_sv = payload.substr(sp1 + 1, sp2 - sp1 - 1);
    if (status_sv.size() != 3 ||
        !std::isdigit(static_cast<unsigned char>(status_sv[0])) ||
        !std::isdigit(static_cast<unsigned char>(status_sv[1])) ||
        !std::isdigit(static_cast<unsigned char>(status_sv[2]))) {
      return out;
    }
    const int status_code = (status_sv[0] - '0') * 100 +
                            (status_sv[1] - '0') * 10 +
                            (status_sv[2] - '0');
    if (status_code < 100 || status_code > 599) return out;

    size_t eol = payload.find('\r', sp2 + 1);
    if (eol == std::string_view::npos) eol = payload.size();
    const std::string reason(payload.substr(sp2 + 1, eol - sp2 - 1));

    json env = make_envelope(e, "http-response");
    json http;
    http["version"]       = version;
    http["status_code"]   = status_code;
    http["status_reason"] = reason;
    json data;
    data["transport"] = "tcp";
    data["remote"]    = endpoint_json(e.remote);
    data["http"]      = std::move(http);
    env["data"]       = std::move(data);
    // Payload-derived strings (DNS qname, HTTP host/path) can carry non-UTF-8
  // bytes; use the 'replace' handler so dump() never throws and drops the event.
  out.push_back(env.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
    return out;
  }

  // ---- Request ("GET /path HTTP/1.1\r\nHost: example.com\r\n...") ------
  const std::string_view method_sv = leading_http_method(payload);
  if (method_sv.empty()) return out;

  const size_t method_end = method_sv.size();
  if (method_end + 1 >= payload.size()) return out;
  const size_t sp2 = payload.find(' ', method_end + 1);
  if (sp2 == std::string_view::npos) return out;
  const std::string path(payload.substr(method_end + 1, sp2 - method_end - 1));
  if (path.empty()) return out;

  size_t eol = payload.find('\r', sp2 + 1);
  if (eol == std::string_view::npos) eol = payload.size();
  const std::string_view version_sv = payload.substr(sp2 + 1, eol - sp2 - 1);
  if (version_sv.size() < 5 || version_sv.compare(0, 5, "HTTP/") != 0) return out;
  const std::string version(version_sv);

  // Look for Host: header. HTTP header names are case-insensitive per RFC 7230;
  // real clients almost always use "Host: ". Cover the three common casings
  // (Host / host / HOST) without paying for a full case-insensitive scan.
  std::string host;
  {
    size_t hpos = payload.find("\r\nHost: ");
    if (hpos == std::string_view::npos) hpos = payload.find("\r\nhost: ");
    if (hpos == std::string_view::npos) hpos = payload.find("\r\nHOST: ");
    if (hpos != std::string_view::npos) {
      const size_t host_start = hpos + 8;
      size_t host_end = payload.find('\r', host_start);
      if (host_end == std::string_view::npos) host_end = payload.size();
      host = std::string(payload.substr(host_start, host_end - host_start));
    }
  }

  json env = make_envelope(e, "http-request");
  json http;
  http["method"]  = std::string(method_sv);
  http["path"]    = path;
  http["version"] = version;
  if (!host.empty()) http["host"] = host;
  json data;
  data["transport"] = "tcp";
  data["remote"]    = endpoint_json(e.remote);
  data["http"]      = std::move(http);
  env["data"]       = std::move(data);
  // Payload-derived strings (DNS qname, HTTP host/path) can carry non-UTF-8
  // bytes; use the 'replace' handler so dump() never throws and drops the event.
  out.push_back(env.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
  return out;
}

} // namespace

std::vector<std::string> synthesize_protocol_events(
    const vishaya::collector::EventVariant& event) {
  return std::visit(
      [](const auto& e) -> std::vector<std::string> {
        using T = std::decay_t<decltype(e)>;
        if constexpr (std::is_same_v<T, network_event>) {
          std::vector<std::string> out = try_decode_dns(e);
          // If DNS didn't match, try HTTP.
          if (out.empty()) {
            out = try_decode_http(e);
          }
          return out;
        }
        return {};
      },
      event);
}

} // namespace vishaya::capture
