#include "inspect/artifacts.h"

#include "bundle/reader.h"
#include "common/log.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>

namespace vishaya::inspect {

namespace {
// source_paths are raw kernel bytes (attacker-controlled). Scrub ASCII control
// characters so a crafted path can't inject terminal escape sequences or break
// the table when listed. High bytes are left as-is (may render as UTF-8 or mojibake).
std::string scrub(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (unsigned char c : s) {
    out.push_back((c < 0x20 || c == 0x7f) ? '?' : static_cast<char>(c));
  }
  return out;
}
} // namespace

int run_artifacts(const std::string& bundle_path) {
  try {
    vishaya::bundle::Reader reader(bundle_path);
    reader.verify();  // integrity + signature + artifact warnings go to stderr
    const auto& arts = reader.artifacts();

    std::cout << "bundle: " << bundle_path << "\n\n";
    if (arts.empty()) {
      std::cout << "(no artifacts captured — run capture with --capture-artifacts)\n";
      return 0;
    }

    std::cout << std::left
              << std::setw(18) << "SHA256"
              << std::setw(14) << "SIZE"
              << std::setw(24) << "STATUS"
              << "SOURCE PATH(S)\n";
    std::cout << std::string(96, '-') << "\n";

    uint64_t ok = 0;
    for (const auto& a : arts) {
      const std::string sha =
          a.sha256.empty() ? "-" : a.sha256.substr(0, 16);
      std::string paths;
      for (size_t i = 0; i < a.source_paths.size(); ++i) {
        if (i) paths += ", ";
        paths += scrub(a.source_paths[i]);
      }
      std::cout << std::left
                << std::setw(18) << sha
                << std::setw(14) << a.size
                << std::setw(24) << a.status
                << paths << "\n";
      if (a.status == vishaya::bundle::artifact_status::kOk) ++ok;
    }

    std::cout << "\n" << ok << " captured, " << arts.size()
              << " candidate record(s)\n";
    std::cout << "extract: zstd -d < " << bundle_path
              << " | tar -x artifacts/  (files are named by SHA-256)\n";
    return 0;
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("artifacts failed: ") + e.what());
    return 1;
  }
}

} // namespace vishaya::inspect
