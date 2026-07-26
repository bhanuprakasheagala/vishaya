#include "bundle/manifest.h"

#include "bundle/schema_version.h"
#include "common/errors.h"

#include <cstdio>
#include <nlohmann/json.hpp>
#include <string>

namespace vishaya::bundle {

namespace {

using json = nlohmann::json;

json host_to_json(const HostInfo& h) {
  return json{
    {"kernel",   h.kernel},
    {"arch",     h.arch},
    {"distro",   h.distro},
    {"hostname", h.hostname},
  };
}

HostInfo host_from_json(const json& j) {
  HostInfo h;
  h.kernel   = j.value("kernel",   "");
  h.arch     = j.value("arch",     "");
  h.distro   = j.value("distro",   "");
  h.hostname = j.value("hostname", "");
  return h;
}

json target_to_json(const TargetInfo& t) {
  return json{
    {"path",      t.path},
    {"sha256",    t.sha256},
    {"size",      t.size},
    {"args",      t.args},
    {"env_count", t.env_count},
  };
}

TargetInfo target_from_json(const json& j) {
  TargetInfo t;
  t.path   = j.value("path",   "");
  t.sha256 = j.value("sha256", "");
  t.size   = j.value("size",   uint64_t{0});
  if (j.contains("args") && j["args"].is_array()) {
    t.args = j["args"].get<std::vector<std::string>>();
  }
  t.env_count = j.value("env_count", 0);
  return t;
}

int parse_major(const std::string& semver) {
  int major = -1;
  std::sscanf(semver.c_str(), "%d", &major);
  return major;
}

} // namespace

namespace {

// Build the manifest as a json object. Single source of truth for both the
// on-disk manifest.json and the canonical signing payload (manifest_signing_payload).
//
// INVARIANT: every field emitted here MUST be parsed back by manifest_from_json.
// The "manifest-v1" signature is computed over this object (minus `sig`), and the
// reader re-derives it from the *parsed* struct — so a field written here but not
// parsed there would make the reader's payload differ and silently fail every
// signature verification. (End-to-end tests E10/E11 in tests/run-tests.sh catch a
// violation.) Keep to_json and from_json in lockstep.
json manifest_to_jobject(const Manifest& m) {
  json j;
  j["schema_version"] = m.schema_version;
  j["tool"] = json{
    {"name",    m.tool_name},
    {"version", m.tool_version},
  };
  j["capture"] = json{
    {"started_at",         m.capture.started_at},
    {"ended_at",           m.capture.ended_at},
    {"duration_seconds",   m.capture.duration_seconds},
    {"clock_realtime_ns",  m.capture.clock_realtime_ns},
    {"clock_monotonic_ns", m.capture.clock_monotonic_ns},
    {"host",               host_to_json(m.capture.host)},
  };
  j["target"] = target_to_json(m.target);
  j["isolation"] = json{
    {"namespaces",  m.isolation.namespaces},
    {"cgroup_path", m.isolation.cgroup_path},
    {"cgroup_id",   m.isolation.cgroup_id},
  };
  j["coverage"] = json{
    {"families",           m.coverage.families},
    {"syscalls_captured",  m.coverage.syscalls_captured},
    {"network_layers",     m.coverage.network_layers},
    {"artifacts_captured", m.coverage.artifacts_captured},
  };
  j["counts"] = json{
    {"events_total",    m.counts.events_total},
    {"events_dropped",  m.counts.events_dropped},
    {"processes_seen",  m.counts.processes_seen},
    {"artifacts_count", m.counts.artifacts_count},
  };
  j["integrity"] = json{
    {"events_sha256",          m.integrity.events_sha256},
    {"process_tree_sha256",    m.integrity.process_tree_sha256},
    {"artifacts_index_sha256", m.integrity.artifacts_index_sha256},
  };
  j["sig"] = json{
    {"algorithm",  m.sig.algorithm},
    {"scope",      m.sig.scope},
    {"pubkey_b64", m.sig.pubkey_b64},
    {"sig_b64",    m.sig.sig_b64},
  };
  return j;
}

} // namespace

std::string manifest_to_json(const Manifest& m) {
  return manifest_to_jobject(m).dump(2);
}

std::string manifest_signing_payload(const Manifest& m) {
  json j = manifest_to_jobject(m);
  j.erase("sig");            // the signature cannot cover itself
  return j.dump();           // compact + nlohmann's deterministic key order
}

Manifest manifest_from_json(const std::string& jstr) {
  json j;
  try {
    j = json::parse(jstr);
  } catch (const json::parse_error& e) {
    throw BundleError(std::string("manifest JSON parse error: ") + e.what());
  }

  // A hostile or corrupt manifest may carry a field of the wrong JSON type (e.g.
  // a number where a string is expected), which makes nlohmann's value()/get<>()
  // throw json::type_error. Wrap the whole extraction so that surfaces as a
  // BundleError per this function's contract rather than an unexpected exception.
  // (BundleError thrown by the schema checks below is not a json::exception, so it
  // propagates unchanged through this catch.)
  try {
  Manifest m;
  m.schema_version = j.value("schema_version", "");
  if (m.schema_version.empty()) {
    throw BundleError("manifest missing required field: schema_version");
  }

  // Spec §7: reject bundles whose major > this reader's major.
  const int bundle_major = parse_major(m.schema_version);
  if (bundle_major < 0) {
    throw BundleError("manifest schema_version is not semver: " + m.schema_version);
  }
  if (bundle_major > kSchemaMajor) {
    throw BundleError(
        "bundle schema major " + std::to_string(bundle_major) +
        " is newer than this reader supports (max major " +
        std::to_string(kSchemaMajor) + ")");
  }

  if (j.contains("tool") && j["tool"].is_object()) {
    m.tool_name    = j["tool"].value("name",    "");
    m.tool_version = j["tool"].value("version", "");
  }

  if (j.contains("capture") && j["capture"].is_object()) {
    const auto& c = j["capture"];
    m.capture.started_at         = c.value("started_at",         "");
    m.capture.ended_at           = c.value("ended_at",           "");
    m.capture.duration_seconds   = c.value("duration_seconds",   uint64_t{0});
    m.capture.clock_realtime_ns  = c.value("clock_realtime_ns",  uint64_t{0});
    m.capture.clock_monotonic_ns = c.value("clock_monotonic_ns", uint64_t{0});
    if (c.contains("host") && c["host"].is_object()) {
      m.capture.host = host_from_json(c["host"]);
    }
  }

  if (j.contains("target") && j["target"].is_object()) {
    m.target = target_from_json(j["target"]);
  }

  if (j.contains("isolation") && j["isolation"].is_object()) {
    const auto& i = j["isolation"];
    if (i.contains("namespaces") && i["namespaces"].is_array()) {
      m.isolation.namespaces = i["namespaces"].get<std::vector<std::string>>();
    }
    m.isolation.cgroup_path = i.value("cgroup_path", "");
    m.isolation.cgroup_id   = i.value("cgroup_id",   uint64_t{0});
  }

  if (j.contains("coverage") && j["coverage"].is_object()) {
    const auto& c = j["coverage"];
    if (c.contains("families") && c["families"].is_array()) {
      m.coverage.families = c["families"].get<std::vector<std::string>>();
    }
    m.coverage.syscalls_captured = c.value("syscalls_captured", false);
    if (c.contains("network_layers") && c["network_layers"].is_array()) {
      m.coverage.network_layers =
          c["network_layers"].get<std::vector<std::string>>();
    }
    m.coverage.artifacts_captured = c.value("artifacts_captured", false);
  }

  if (j.contains("counts") && j["counts"].is_object()) {
    const auto& c = j["counts"];
    m.counts.events_total    = c.value("events_total",    uint64_t{0});
    m.counts.events_dropped  = c.value("events_dropped",  uint64_t{0});
    m.counts.processes_seen  = c.value("processes_seen",  uint64_t{0});
    m.counts.artifacts_count = c.value("artifacts_count", uint64_t{0});
  }

  if (j.contains("integrity") && j["integrity"].is_object()) {
    const auto& i = j["integrity"];
    m.integrity.events_sha256          = i.value("events_sha256",          "");
    m.integrity.process_tree_sha256    = i.value("process_tree_sha256",    "");
    m.integrity.artifacts_index_sha256 = i.value("artifacts_index_sha256", "");
  }

  if (j.contains("sig") && j["sig"].is_object()) {
    const auto& s = j["sig"];
    m.sig.algorithm  = s.value("algorithm",  "");
    m.sig.scope      = s.value("scope",      "");  // "" = legacy two-hash signature
    m.sig.pubkey_b64 = s.value("pubkey_b64", "");
    m.sig.sig_b64    = s.value("sig_b64",    "");
  }

  return m;
  } catch (const json::exception& e) {
    throw BundleError(std::string("manifest has a field of unexpected type: ") +
                      e.what());
  }
}

} // namespace vishaya::bundle
