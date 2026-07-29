#include "inspect/artifacts.h"

#include "bundle/reader.h"
#include "common/log.h"
#include "inspect/render.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>

namespace vishaya::inspect {

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
        paths += scrub_for_terminal(a.source_paths[i]);
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
