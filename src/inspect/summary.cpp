#include "inspect/summary.h"

#include "bundle/reader.h"
#include "bundle/sign.h"
#include "common/errors.h"
#include "common/log.h"
#include "inspect/endpoint.h"
#include "inspect/render.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace vishaya::inspect {

using json = nlohmann::json;

namespace {

// Insertion-ordered unique collector (values are naturally bounded by target
// behaviour; we cap only the *display*, not the collection).
struct UniqueList {
  std::vector<std::string> items;
  std::set<std::string>    seen;
  void add(const std::string& raw) {
    // Everything collected here (paths, DNS names, HTTP lines, endpoints) is
    // attacker-controlled; scrub terminal-control bytes at the single choke point.
    const std::string v = scrub_for_terminal(raw);
    if (v.empty()) return;
    if (seen.insert(v).second) items.push_back(v);
  }
  bool empty() const { return items.empty(); }
  size_t size() const { return items.size(); }
};

// Print "  <label>  item1, item2, … (+N more)" with a display cap.
void print_inline(const char* label, const UniqueList& u, size_t cap = 8) {
  if (u.empty()) return;
  std::cout << "    " << label;
  const size_t n = std::min(cap, u.items.size());
  for (size_t i = 0; i < n; ++i) std::cout << (i ? ", " : " ") << u.items[i];
  if (u.items.size() > cap) std::cout << "  (+" << (u.items.size() - cap) << " more)";
  std::cout << "\n";
}

// Print each item on its own indented line, capped.
void print_lines(const char* label, const UniqueList& u, size_t cap = 6) {
  if (u.empty()) return;
  const size_t n = std::min(cap, u.items.size());
  for (size_t i = 0; i < n; ++i)
    std::cout << "    " << label << "  " << u.items[i] << "\n";
  if (u.items.size() > cap)
    std::cout << "    " << label << "  (+" << (u.items.size() - cap) << " more)\n";
}

std::string lower_copy(const std::string& s) {
  std::string out = s;
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

void add_unique_obs(std::vector<std::string>& obs, const std::string& entry) {
  if (entry.empty()) return;
  const std::string v = scrub_for_terminal(entry);
  if (v.empty()) return;
  if (std::find(obs.begin(), obs.end(), v) == obs.end()) obs.push_back(v);
}

// A short bounded process-tree print (root + descendants) under a line budget.
void print_tree(const std::unordered_map<int32_t, const vishaya::bundle::ProcessRecord*>& by_tgid,
                int32_t tgid, const std::string& prefix, bool is_last, int& budget) {
  if (budget <= 0) return;
  auto it = by_tgid.find(tgid);
  if (it == by_tgid.end()) return;
  const auto& r = *it->second;
  --budget;
  std::cout << "    " << prefix << (prefix.empty() ? "" : (is_last ? "└─ " : "├─ "))
            << (r.comm.empty() ? "<unknown>" : scrub_for_terminal(r.comm)) << " (pid=" << r.tgid;
  if (!r.exec_path.empty()) std::cout << " " << scrub_for_terminal(r.exec_path);
  if (r.exit_code.has_value()) std::cout << " exit=" << *r.exit_code;
  std::cout << ")\n";
  const std::string next = prefix + (prefix.empty() ? "" : (is_last ? "   " : "│  "));
  for (size_t i = 0; i < r.children.size(); ++i) {
    if (budget <= 0) { std::cout << "    " << next << "…\n"; break; }
    print_tree(by_tgid, r.children[i], next.empty() ? " " : next,
               i + 1 == r.children.size(), budget);
  }
}

} // namespace

int run_summary(const std::string& bundle_path, bool json_output) {
  try {
    vishaya::bundle::Reader reader(bundle_path);
    const auto& m      = reader.manifest();
    const auto  report = reader.verify();  // warnings (if any) go to stderr

    if (json_output) {
      nlohmann::json summary = {
          {"bundle_path", bundle_path},
          {"schema_version", m.schema_version},
          {"tool", m.tool_name + " " + m.tool_version},
          {"integrity_ok", report.integrity_ok},
          {"signature_present", report.signature_present},
          {"signature_ok", report.signature_ok},
          {"overall_ok", report.ok()},
          {"artifacts_index_ok", report.artifacts_index_ok},
          {"artifacts_content_ok", report.artifacts_content_ok},
          {"target", {"path", m.target.path, "sha256", m.target.sha256}},
          {"capture", {"started_at", m.capture.started_at,
                        "ended_at", m.capture.ended_at,
                        "duration_seconds", m.capture.duration_seconds,
                        "host", {"distro", m.capture.host.distro,
                                  "kernel", m.capture.host.kernel,
                                  "arch", m.capture.host.arch}}},
          {"counts", {"events_total", m.counts.events_total,
                       "events_dropped", m.counts.events_dropped}}
      };

      uint64_t n_process = 0, n_file = 0, n_network = 0, n_syscall = 0;
      reader.for_each_event([&](const json& e) {
        try {
          const std::string fam = e.value("family", "");
          const std::string kind = e.value("kind", "");
          if (fam == "process") ++n_process;
          else if (fam == "syscall") ++n_syscall;
          else if (fam == "file") ++n_file;
          else if (fam == "network") {
            ++n_network;
            if (kind == "http-request") {
              summary["http_requests"] = summary.value("http_requests", 0) + 1;
            }
            if (kind == "dns-query" || kind == "dns-answer") {
              summary["dns_events"] = summary.value("dns_events", 0) + 1;
            }
          }
        } catch (const nlohmann::json::exception&) {}
      });
      summary["counts"]["process"] = n_process;
      summary["counts"]["file"] = n_file;
      summary["counts"]["network"] = n_network;
      summary["counts"]["syscall"] = n_syscall;
      summary["verdict"] = report.ok() ? "verified" : "failed";
      std::cout << summary.dump(2) << "\n";
      return report.ok() ? 0 : 1;
    }

    // ---- aggregate the event stream once --------------------------------
    uint64_t n_process = 0, n_file = 0, n_network = 0, n_syscall = 0;
    UniqueList dns, http, endpoints, created, deleted, renamed, opened;
    std::unordered_map<std::string, std::string> dns_answer;  // qname -> first ip

    reader.for_each_event([&](const json& e) {
      // Skip a malformed event (wrong-typed field → json::type_error) rather than
      // aborting the whole summary — same resilience as the files/network views.
      try {
      const std::string fam  = e.value("family", "");
      const std::string kind = e.value("kind", "");
      const json&       d    = e.contains("data") ? e["data"] : json::object();

      if (fam == "process") { ++n_process; return; }
      if (fam == "syscall") { ++n_syscall; return; }
      if (fam == "file") {
        ++n_file;
        const std::string a = d.value("path_a", "");
        if (kind == "unlinkat")        deleted.add(a);
        else if (kind == "renameat2")  renamed.add(a + " → " + d.value("path_b", ""));
        else if (kind == "openat") {
          const int64_t flags = d.value("flags", int64_t{0});  // int64: no type_error on large flags
          if (flags & 0100 /*O_CREAT*/) created.add(a); else opened.add(a);
        }
        return;
      }
      if (fam == "network") {
        ++n_network;
        const json& r = d.contains("remote") ? d["remote"] : json::object();
        if (kind == "connect") { const auto ep = format_remote_endpoint(r); endpoints.add(ep); }
        else if (kind == "dns-answer" || kind == "dns-query") {
          const json& dj = d.contains("dns") ? d["dns"] : json::object();
          const std::string q = dj.value("qname", "");
          if (kind == "dns-answer" && dj.contains("answers") && dj["answers"].is_array()) {
            for (const auto& ans : dj["answers"]) {
              const std::string rd = ans.value("rdata", "");
              if (!q.empty() && !rd.empty() && !dns_answer.count(q)) { dns_answer[q] = rd; }
            }
          }
          if (!q.empty()) dns.add(q);
        }
        else if (kind == "http-request") {
          const json& h = d.contains("http") ? d["http"] : json::object();
          std::string line = h.value("method", "") + " " + h.value("host", "") + h.value("path", "");
          const auto ep = format_remote_endpoint(r);
          if (!ep.empty()) line += "  (→ " + ep + ")";
          http.add(line);
        }
        return;
      }
      } catch (const nlohmann::json::exception&) { /* skip malformed event */ }
    });

    // Resolve DNS display: "qname → ip" where an answer exists.
    UniqueList dns_disp;
    for (const auto& q : dns.items) {
      auto it = dns_answer.find(q);
      dns_disp.add(it != dns_answer.end() ? (q + " → " + it->second) : q);
    }

    // ---- header + trust line --------------------------------------------
    std::cout << "Vishaya capture — " << bundle_path << "\n";

    std::string trust = "  ";
    trust += report.integrity_ok ? "[+] integrity OK" : "[x] integrity MISMATCH";
    if (!report.signature_present) {
      trust += "   [-] unsigned";
    } else if (report.signature_ok) {
      trust += "   [+] signature VALID (Ed25519 " +
               vishaya::bundle::pubkey_fingerprint(m.sig.pubkey_b64) + ")";
    } else {
      trust += "   [x] signature INVALID";
    }
    if (!report.artifacts_index_ok || !report.artifacts_content_ok) {
      trust += "   [x] artifacts TAMPERED";
    }
    if (m.counts.events_dropped > 0) {
      trust += "   [!] " + std::to_string(m.counts.events_dropped) +
               " events dropped (reduced confidence)";
    }
    std::cout << trust << "\n\n";

    // ---- identity + counts ----------------------------------------------
    // target.path, timestamps, and host.* are manifest strings from an
    // attacker-controlled bundle → scrub before display (sha256 is hex).
    std::cout << "  format    schema " << scrub_for_terminal(m.schema_version)
              << "  | tool " << scrub_for_terminal(m.tool_name) << " "
              << scrub_for_terminal(m.tool_version) << "\n";
    std::cout << "  target    " << scrub_for_terminal(m.target.path);
    if (m.target.sha256.size() >= 12)
      std::cout << "  sha256 " << m.target.sha256.substr(0, 12) << "…";
    std::cout << "\n";
    std::cout << "  captured  " << scrub_for_terminal(m.capture.started_at)
              << "  · " << m.capture.duration_seconds << "s"
              << "  · " << scrub_for_terminal(m.capture.host.distro)
              << " (" << scrub_for_terminal(m.capture.host.kernel)
              << "/" << scrub_for_terminal(m.capture.host.arch) << ")\n";
    std::cout << "  events    " << m.counts.events_total
              << "   process " << n_process << "  file " << n_file
              << "  network " << n_network;
    if (m.coverage.syscalls_captured) std::cout << "  syscall " << n_syscall;
    std::cout << "\n";

    // ---- process tree ----------------------------------------------------
    const auto& tree = reader.process_tree();
    if (!tree.processes.empty()) {
      std::unordered_map<int32_t, const vishaya::bundle::ProcessRecord*> by_tgid;
      for (const auto& r : tree.processes) by_tgid[r.tgid] = &r;
      std::cout << "\n  processes (" << tree.processes.size() << ")\n";
      int budget = 12;
      print_tree(by_tgid, tree.root_pid, "", true, budget);
    }

    // ---- network ---------------------------------------------------------
    if (!dns_disp.empty() || !http.empty() || !endpoints.empty()) {
      std::cout << "\n  network\n";
      print_lines("DNS ", dns_disp, 8);
      print_lines("HTTP", http, 8);
      print_inline("conn", endpoints, 10);
    }

    // ---- files -----------------------------------------------------------
    if (!created.empty() || !deleted.empty() || !renamed.empty() || !opened.empty()) {
      std::cout << "\n  files\n";
      print_lines("created", created, 6);
      print_lines("deleted", deleted, 6);
      print_lines("renamed", renamed, 6);
      if (!opened.empty())
        std::cout << "    opened   " << opened.size() << " path(s)\n";
    }

    // ---- highlights -----------------------------------------------------
    std::vector<std::string> observations;
    if (!tree.processes.empty() && tree.processes.size() > 1) {
      add_unique_obs(observations,
                     "target spawned " + std::to_string(tree.processes.size() - 1) +
                         " descendant process(es)");
    }
    if (!dns_disp.empty()) {
      add_unique_obs(observations,
                     "observed DNS lookups for " + std::to_string(dns_disp.size()) +
                         " name(s)");
    }
    if (!http.empty()) {
      add_unique_obs(observations,
                     "observed HTTP activity for " + std::to_string(http.size()) +
                         " request(s)");
    }
    if (!created.empty()) {
      add_unique_obs(observations,
                     "file creation observed for " + std::to_string(created.size()) +
                         " path(s)");
    }
    if (!deleted.empty() || !renamed.empty()) {
      add_unique_obs(observations,
                     "file mutations or renames observed");
    }
    for (const auto& r : tree.processes) {
      const std::string name = r.exec_path.empty() ? r.comm : r.exec_path;
      const std::string lower = lower_copy(name);
      if (lower.find("/bin/sh") != std::string::npos ||
          lower.find("bash") != std::string::npos ||
          lower.find("dash") != std::string::npos) {
        add_unique_obs(observations, "shell execution observed");
      }
      if (lower.find("curl") != std::string::npos ||
          lower.find("wget") != std::string::npos ||
          lower.find("python") != std::string::npos ||
          lower.find("perl") != std::string::npos) {
        add_unique_obs(observations, "command or downloader activity observed");
      }
    }
    if (!observations.empty()) {
      std::cout << "\n  highlights\n";
      for (const auto& obs : observations) std::cout << "    * " << obs << "\n";
    }

    // ---- artifacts -------------------------------------------------------
    const auto& arts = reader.artifacts();
    if (!arts.empty()) {
      uint64_t ok = 0;
      for (const auto& a : arts)
        if (a.status == vishaya::bundle::artifact_status::kOk) ++ok;
      std::cout << "\n  artifacts (" << ok << " captured)\n";
      uint64_t shown = 0;
      for (const auto& a : arts) {
        if (a.status != vishaya::bundle::artifact_status::kOk) continue;
        if (shown >= 6) { std::cout << "    (+" << (ok - shown) << " more)\n"; break; }
        ++shown;
        const std::string sha  = a.sha256.substr(0, 12);
        const std::string path =
            a.source_paths.empty() ? "" : scrub_for_terminal(a.source_paths.front());
        std::cout << "    " << sha << "  " << a.size << "  " << path << "\n";
      }
    }

    return 0;
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("summary failed: ") + e.what());
    return 1;
  }
}

} // namespace vishaya::inspect
