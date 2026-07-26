#include "bundle/artifacts.h"

#include "common/errors.h"

#include <nlohmann/json.hpp>

namespace vishaya::bundle {

using json = nlohmann::json;

std::string artifacts_to_json(const std::vector<ArtifactRecord>& records) {
  json arr = json::array();
  for (const auto& r : records) {
    json j;
    j["sha256"]       = r.sha256;
    j["size"]         = r.size;
    j["mode"]         = r.mode;
    j["source_paths"] = r.source_paths;
    j["status"]       = r.status;
    arr.push_back(std::move(j));
  }
  // source_paths carry raw kernel bytes; replace invalid UTF-8 so dump() never
  // throws. Byte-for-byte reproducibility is not required here — the writer hashes
  // exactly the string it stores, and the reader hashes the stored entry bytes.
  return arr.dump(2, ' ', false, json::error_handler_t::replace);
}

std::vector<ArtifactRecord> artifacts_from_json(const std::string& jstr) {
  json j;
  try {
    j = json::parse(jstr);
  } catch (const json::parse_error& e) {
    throw BundleError(std::string("artifacts.json parse error: ") + e.what());
  }

  // Wrap field extraction: a wrong-typed field in a hostile/corrupt index makes
  // nlohmann throw json::type_error; surface it as BundleError per contract.
  try {
  std::vector<ArtifactRecord> out;
  if (!j.is_array()) {
    throw BundleError("artifacts.json must be a JSON array");
  }
  for (const auto& e : j) {
    ArtifactRecord r;
    r.sha256 = e.value("sha256", "");
    r.size   = e.value("size", uint64_t{0});
    r.mode   = e.value("mode", uint32_t{0});
    r.status = e.value("status", "");
    if (e.contains("source_paths") && e["source_paths"].is_array()) {
      r.source_paths = e["source_paths"].get<std::vector<std::string>>();
    }
    out.push_back(std::move(r));
  }
  return out;
  } catch (const json::exception& e) {
    throw BundleError(std::string("artifacts.json has a field of unexpected type: ") +
                      e.what());
  }
}

} // namespace vishaya::bundle
