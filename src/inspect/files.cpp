#include "inspect/files.h"

#include "bundle/reader.h"
#include "common/errors.h"
#include "common/log.h"

#include <iomanip>
#include <iostream>
#include <string>

namespace vishaya::inspect {

int run_files(const std::string& bundle_path) {
  try {
    vishaya::bundle::Reader reader(bundle_path);
    reader.verify();  // spec §6/§9: verify integrity + signature at load (warns on failure)

    std::cout << "bundle: " << bundle_path << "\n\n";
    std::cout << std::left
              << std::setw(8)  << "PID"
              << std::setw(18) << "COMM"
              << std::setw(12) << "OP"
              << std::setw(8)  << "RET"
              << "PATH\n";
    std::cout << std::string(72, '-') << "\n";

    size_t count = 0;
    reader.for_each_event([&](const nlohmann::json& e) {
      if (e.value("family", "") != "file") return;
      const std::string kind = e.value("kind", "");
      const auto&       data = e.contains("data") ? e["data"] : nlohmann::json::object();
      const std::string path_a = data.value("path_a", "");
      const std::string path_b = data.value("path_b", "");
      const int32_t     ret    = data.value("ret", 0);

      std::string path = path_a;
      if (kind == "renameat2" && !path_b.empty()) {
        path = path_a + " -> " + path_b;
      }

      std::cout << std::left
                << std::setw(8)  << e.value("tgid", 0)
                << std::setw(18) << e.value("comm", "")
                << std::setw(12) << kind
                << std::setw(8)  << ret
                << path << "\n";
      ++count;
    });

    if (count == 0) {
      std::cout << "(no file events)\n";
    } else {
      std::cout << "\n" << count << " file event(s)\n";
    }
    return 0;
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("files failed: ") + e.what());
    return 1;
  }
}

} // namespace vishaya::inspect
