#include "inspect/diff.h"

#include "bundle/reader.h"
#include "common/log.h"
#include "inspect/endpoint.h"
#include "inspect/render.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <set>
#include <string>
#include <vector>

namespace vishaya::inspect {

using json = nlohmann::json;

namespace {

// The behavioural facts we compare. Sets, so identifiers that vary run-to-run
// (PIDs, timestamps) never enter the comparison — the diff is normalized by
// construction. Plain file *opens* are deliberately excluded (libs, /etc, …) as
// noise; created/deleted/renamed are the behaviourally meaningful ones.
struct Facts {
  std::string           target_path;
  std::string           target_sha;
  uint64_t              events = 0;
  std::set<std::string> execs;      // executed binary paths
  std::set<std::string> created;    // files created
  std::set<std::string> deleted;    // files deleted
  std::set<std::string> renamed;    // "old → new"
  std::set<std::string> dns;        // resolved names
  std::set<std::string> http;       // "METHOD host path"
  std::set<std::string> endpoints;  // "ip:port" connected to
};

Facts collect(vishaya::bundle::Reader& reader) {
  Facts f;
  const auto& m = reader.manifest();
  f.target_path = scrub_for_terminal(m.target.path);
  f.target_sha  = m.target.sha256;  // hex; printed via substr
  f.events      = m.counts.events_total;

  reader.for_each_event([&](const json& e) {
    // Skip a malformed event rather than aborting the whole diff. All strings that
    // enter the fact sets are attacker-controlled → scrub before insert (also keeps
    // the A/B set comparison consistent and terminal-safe when printed).
    try {
    const std::string fam  = e.value("family", "");
    const std::string kind = e.value("kind", "");
    const json&       d    = e.contains("data") ? e["data"] : json::object();

    if (fam == "process") {
      if (kind == "exec") {
        std::string p = d.value("exec_path", "");
        if (p.empty()) p = d.value("filename", "");
        if (!p.empty()) f.execs.insert(scrub_for_terminal(p));
      }
    } else if (fam == "file") {
      const std::string a = d.value("path_a", "");
      if (kind == "unlinkat")       { if (!a.empty()) f.deleted.insert(scrub_for_terminal(a)); }
      else if (kind == "renameat2") { f.renamed.insert(scrub_for_terminal(a + " → " + d.value("path_b", ""))); }
      else if (kind == "openat") {
        // int64 default: read any JSON-integer flags value without a type_error.
        if ((d.value("flags", int64_t{0}) & 0100 /*O_CREAT*/) && !a.empty()) f.created.insert(scrub_for_terminal(a));
      }
    } else if (fam == "network") {
      const json& r = d.contains("remote") ? d["remote"] : json::object();
      if (kind == "connect") { const auto ep = format_remote_endpoint(r); if (!ep.empty()) f.endpoints.insert(ep); }
      else if (kind == "dns-query" || kind == "dns-answer") {
        const json& dj = d.contains("dns") ? d["dns"] : json::object();
        const std::string q = dj.value("qname", "");
        if (!q.empty()) f.dns.insert(scrub_for_terminal(q));
      } else if (kind == "http-request") {
        const json& h = d.contains("http") ? d["http"] : json::object();
        f.http.insert(scrub_for_terminal(h.value("method", "") + " " + h.value("host", "") + h.value("path", "")));
      }
    }
    } catch (const nlohmann::json::exception&) { /* skip malformed event */ }
  });
  return f;
}

// Print "only in A" (as "- ") and "only in B" (as "+ ") for one category.
// Returns true if any difference was printed. Caps the display.
bool diff_set(const char* label, const std::set<std::string>& a,
              const std::set<std::string>& b, size_t cap = 50) {
  std::vector<std::string> only_a, only_b;
  std::set_difference(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(only_a));
  std::set_difference(b.begin(), b.end(), a.begin(), a.end(), std::back_inserter(only_b));
  if (only_a.empty() && only_b.empty()) return false;

  std::cout << "\n" << label << "\n";
  size_t shown = 0;
  for (const auto& x : only_a) { if (shown++ >= cap) break; std::cout << "  - " << x << "\n"; }
  shown = 0;
  for (const auto& x : only_b) { if (shown++ >= cap) break; std::cout << "  + " << x << "\n"; }
  if (only_a.size() > cap) std::cout << "  - (+" << (only_a.size() - cap) << " more only in A)\n";
  if (only_b.size() > cap) std::cout << "  + (+" << (only_b.size() - cap) << " more only in B)\n";
  return true;
}

} // namespace

int run_diff(const std::string& bundle_a, const std::string& bundle_b) {
  Facts fa, fb;
  try {
    vishaya::bundle::Reader ra(bundle_a);
    ra.verify();  // warns on stderr if a or b is tampered
    fa = collect(ra);
    vishaya::bundle::Reader rb(bundle_b);
    rb.verify();
    fb = collect(rb);
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("diff failed: ") + e.what());
    return 2;
  }

  std::cout << "diff   A = " << bundle_a << "\n"
            << "       B = " << bundle_b << "\n";
  std::cout << "  A target " << fa.target_path;
  if (fa.target_sha.size() >= 12) std::cout << " (sha " << fa.target_sha.substr(0, 12) << "…)";
  std::cout << "\n  B target " << fb.target_path;
  if (fb.target_sha.size() >= 12) std::cout << " (sha " << fb.target_sha.substr(0, 12) << "…)";
  std::cout << "\n";
  if (!fa.target_sha.empty() && !fb.target_sha.empty() && fa.target_sha != fb.target_sha) {
    std::cout << "  [!] different target binaries — behavioural diff may not be meaningful\n";
  }
  std::cout << "  legend: '-' only in A, '+' only in B\n";

  bool diff = false;
  diff |= diff_set("processes executed", fa.execs,     fb.execs);
  diff |= diff_set("files created",      fa.created,   fb.created);
  diff |= diff_set("files deleted",      fa.deleted,   fb.deleted);
  diff |= diff_set("files renamed",      fa.renamed,   fb.renamed);
  diff |= diff_set("DNS names",          fa.dns,       fb.dns);
  diff |= diff_set("HTTP requests",      fa.http,      fb.http);
  diff |= diff_set("network endpoints",  fa.endpoints, fb.endpoints);

  if (!diff) {
    std::cout << "\nno semantic differences\n";
    return 0;
  }
  return 1;
}

} // namespace vishaya::inspect
