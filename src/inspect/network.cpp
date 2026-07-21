#include "inspect/network.h"

#include "bundle/reader.h"
#include "common/errors.h"
#include "common/log.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace vishaya::inspect {

namespace {

std::string format_endpoint(const nlohmann::json& ep) {
  if (ep.is_null() || !ep.is_object()) return "";
  const std::string family = ep.value("family", "");
  const std::string addr   = ep.value("addr", "");
  const int         port   = ep.value("port", 0);
  const std::string path   = ep.value("path", "");
  if (family == "unix" && !path.empty()) {
    return "unix:" + path;
  }
  if (addr.empty() && port == 0) return "";
  std::ostringstream oss;
  if (family == "inet6" && !addr.empty()) {
    oss << "[" << addr << "]:" << port;
  } else if (!addr.empty()) {
    oss << addr << ":" << port;
  } else {
    oss << ":" << port;
  }
  return oss.str();
}

std::string format_extra(const std::string& kind, const nlohmann::json& data) {
  if (kind == "dns-query" || kind == "dns-answer") {
    const auto& dns = data.contains("dns") ? data["dns"] : nlohmann::json::object();
    std::ostringstream oss;
    oss << dns.value("qtype", "") << " " << dns.value("qname", "");
    if (kind == "dns-answer" && dns.contains("answers") &&
        dns["answers"].is_array() && !dns["answers"].empty()) {
      oss << " ->";
      for (const auto& ans : dns["answers"]) {
        oss << " " << ans.value("rdata", "");
      }
    }
    return oss.str();
  }
  if (kind == "http-request") {
    const auto& http = data.contains("http") ? data["http"] : nlohmann::json::object();
    std::ostringstream oss;
    oss << http.value("method", "") << " " << http.value("host", "")
        << http.value("path", "");
    return oss.str();
  }
  if (kind == "http-response") {
    const auto& http = data.contains("http") ? data["http"] : nlohmann::json::object();
    std::ostringstream oss;
    oss << http.value("status_code", 0) << " " << http.value("status_reason", "");
    return oss.str();
  }
  // Socket-level: show bytes if any traffic
  const uint64_t bytes = data.value("bytes_transferred", uint64_t{0});
  if (bytes > 0) {
    std::ostringstream oss;
    oss << bytes << "B";
    return oss.str();
  }
  return "";
}

} // namespace

int run_network(const std::string& bundle_path) {
  try {
    vishaya::bundle::Reader reader(bundle_path);
    reader.verify();  // spec §6/§9: verify integrity + signature at load (warns on failure)

    std::cout << "bundle: " << bundle_path << "\n\n";
    std::cout << std::left
              << std::setw(8)  << "PID"
              << std::setw(18) << "COMM"
              << std::setw(16) << "KIND"
              << std::setw(24) << "REMOTE"
              << "DETAIL\n";
    std::cout << std::string(96, '-') << "\n";

    size_t count = 0;
    reader.for_each_event([&](const nlohmann::json& e) {
      if (e.value("family", "") != "network") return;
      const std::string kind = e.value("kind", "");
      const auto&       data = e.contains("data") ? e["data"] : nlohmann::json::object();
      const std::string remote =
          data.contains("remote") ? format_endpoint(data["remote"]) : "";

      std::cout << std::left
                << std::setw(8)  << e.value("tgid", 0)
                << std::setw(18) << e.value("comm", "")
                << std::setw(16) << kind
                << std::setw(24) << (remote.empty() ? "-" : remote)
                << format_extra(kind, data) << "\n";
      ++count;
    });

    if (count == 0) {
      std::cout << "(no network events)\n";
    } else {
      std::cout << "\n" << count << " network event(s)\n";
    }
    return 0;
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("network failed: ") + e.what());
    return 1;
  }
}

} // namespace vishaya::inspect
