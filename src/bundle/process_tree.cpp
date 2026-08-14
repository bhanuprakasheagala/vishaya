#include "bundle/process_tree.h"

#include "common/errors.h"
#include "common/log.h"

#include <algorithm>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace vishaya::bundle {

namespace {

using json = nlohmann::json;

// Ensures a record exists for tgid, seeded with basic identity fields from the
// event envelope. Returns a reference to the record in the map.
//
// Known limitation (TGID reuse): records are keyed by tgid alone, so if the
// kernel recycles a tgid within one capture (process A exits, B reuses the
// number), A and B collapse into a single record — later exec/exit fields
// overwrite or attach to the wrong lifecycle, and a `children` edge to that tgid
// is ambiguous. A race-free fix needs per-node identity keyed on (tgid,
// start-time); process events already carry data.start_time_ticks, but file/
// network headers do not, so the complete fix is an event-schema change (add a
// start-time to the shared event_header) — deferred to a schema bump, matching
// the same note in capture/event_to_json.cpp. Rare for short, target-scoped
// captures; likelier under fork-heavy or long-running targets.
ProcessRecord& touch_record(std::unordered_map<int32_t, ProcessRecord>& by_tgid,
                            const json& e,
                            int32_t     tgid) {
  auto& rec = by_tgid[tgid];
  if (rec.tgid == 0) {
    rec.tgid        = tgid;
    rec.pid         = e.value("pid",   int32_t{0});
    rec.ppid        = e.value("ppid",  int32_t{0});
    rec.comm        = e.value("comm",  "");
    rec.uid         = e.value("uid",   uint32_t{0});
    rec.gid         = e.value("gid",   uint32_t{0});
    rec.start_ts_ns = e.value("ts_ns", uint64_t{0});
  }
  return rec;
}

} // namespace

ProcessTree reconstruct_tree(const std::string& events_ndjson_path,
                             int32_t            root_pid) {
  ProcessTree tree;
  tree.root_pid = root_pid;

  std::ifstream in(events_ndjson_path);
  if (!in) {
    throw BundleError("failed to open events file: " + events_ndjson_path);
  }

  std::unordered_map<int32_t, ProcessRecord> by_tgid;

  // Candidate parent->child edges from fork/clone events, resolved after the full
  // stream is read (see below). We defer resolution because a child is only a
  // real process if it is itself observed as a process tgid — which we can only
  // know once the whole stream has been scanned.
  std::vector<std::pair<int32_t, int32_t>> candidate_edges;  // (parent_tgid, child_pid)

  std::string line;
  size_t      malformed_lines = 0;

  while (std::getline(in, line)) {
    if (line.empty()) continue;

    json e;
    try {
      e = json::parse(line);
    } catch (const json::parse_error&) {
      ++malformed_lines;
      continue;
    }

    if (e.value("family", "") != "process") continue;

    const int32_t tgid = e.value("tgid", int32_t{0});
    if (tgid == 0) continue;

    // A record is created only for a tgid that actually emitted a process event
    // — i.e. a real thread-group leader. Threads emit under their leader's tgid
    // (hdr.pid = TID, hdr.tgid = leader), so they never create a record here.
    ProcessRecord& rec = touch_record(by_tgid, e, tgid);

    const std::string kind = e.value("kind", "");
    const json        data = e.value("data", json::object());

    if (kind == "exec") {
      rec.exec_path = data.value("exec_path", "");
      rec.cmdline   = data.value("cmdline",   "");
      rec.cwd       = data.value("cwd",       "");
      if (rec.comm.empty()) rec.comm = e.value("comm", "");
    } else if (kind == "fork"   || kind == "clone" ||
               kind == "clone3" || kind == "vfork") {
      const int32_t child_pid = data.value("child_pid", int32_t{0});
      if (child_pid != 0 && child_pid != tgid) {
        candidate_edges.emplace_back(tgid, child_pid);
      }
    } else if (kind == "exit") {
      rec.end_ts_ns = e.value("ts_ns", uint64_t{0});
      rec.exit_code = data.value("exit_code", int32_t{0});
    }
  }

  // Resolve parent->child edges. Keep an edge only when the child was observed as
  // its own process tgid (present in by_tgid). This drops CLONE_THREAD "children"
  // — a new thread's TID shares the parent's tgid and never appears as a distinct
  // process, so it must not become a process node. Duplicate edges are collapsed:
  // a fork() surfaces via BOTH sched_process_fork and sys_exit_clone, so the same
  // (parent, child) pair is emitted more than once.
  for (const auto& [parent, child] : candidate_edges) {
    if (parent == child) continue;
    auto pit = by_tgid.find(parent);
    if (pit == by_tgid.end()) continue;
    if (by_tgid.find(child) == by_tgid.end()) continue;  // thread or dropped-child
    auto& kids = pit->second.children;
    if (std::find(kids.begin(), kids.end(), child) == kids.end()) {
      kids.push_back(child);
    }
  }

  if (malformed_lines > 0) {
    log::warn("process tree: skipped " + std::to_string(malformed_lines) +
              " malformed event line(s)");
  }

  // Emit records sorted by (start_ts_ns, tgid) for deterministic output — the
  // tgid tiebreaker keeps ordering stable when two processes share a timestamp.
  tree.processes.reserve(by_tgid.size());
  for (auto& [tgid, rec] : by_tgid) tree.processes.push_back(std::move(rec));
  std::sort(tree.processes.begin(), tree.processes.end(),
            [](const ProcessRecord& a, const ProcessRecord& b) {
              if (a.start_ts_ns != b.start_ts_ns) return a.start_ts_ns < b.start_ts_ns;
              return a.tgid < b.tgid;
            });

  return tree;
}

std::string tree_to_json(const ProcessTree& t) {
  json j;
  j["root_pid"] = t.root_pid;

  json procs = json::array();
  for (const auto& r : t.processes) {
    json rj;
    rj["pid"]         = r.pid;
    rj["tgid"]        = r.tgid;
    rj["ppid"]        = r.ppid;
    rj["comm"]        = r.comm;
    rj["exec_path"]   = r.exec_path;
    rj["cmdline"]     = r.cmdline;
    rj["cwd"]         = r.cwd;
    rj["uid"]         = r.uid;
    rj["gid"]         = r.gid;
    rj["start_ts_ns"] = r.start_ts_ns;
    rj["end_ts_ns"]   = r.end_ts_ns.has_value() ? json(*r.end_ts_ns) : json(nullptr);
    rj["exit_code"]   = r.exit_code.has_value() ? json(*r.exit_code) : json(nullptr);
    rj["children"]    = r.children;
    procs.push_back(std::move(rj));
  }
  j["processes"] = std::move(procs);
  return j.dump(2);
}

ProcessTree tree_from_json(const std::string& jstr) {
  json j;
  try {
    j = json::parse(jstr);
  } catch (const json::parse_error& e) {
    throw BundleError(std::string("process_tree JSON parse error: ") + e.what());
  }

  // Wrap field extraction: a wrong-typed field in a hostile/corrupt tree makes
  // nlohmann throw json::type_error; surface it as BundleError per contract.
  try {
  ProcessTree t;
  t.root_pid = j.value("root_pid", int32_t{0});

  if (j.contains("processes") && j["processes"].is_array()) {
    for (const auto& rj : j["processes"]) {
      ProcessRecord r;
      r.pid         = rj.value("pid",         int32_t{0});
      r.tgid        = rj.value("tgid",        int32_t{0});
      r.ppid        = rj.value("ppid",        int32_t{0});
      r.comm        = rj.value("comm",        "");
      r.exec_path   = rj.value("exec_path",   "");
      r.cmdline     = rj.value("cmdline",     "");
      r.cwd         = rj.value("cwd",         "");
      r.uid         = rj.value("uid",         uint32_t{0});
      r.gid         = rj.value("gid",         uint32_t{0});
      r.start_ts_ns = rj.value("start_ts_ns", uint64_t{0});
      if (rj.contains("end_ts_ns") && !rj["end_ts_ns"].is_null()) {
        r.end_ts_ns = rj["end_ts_ns"].get<uint64_t>();
      }
      if (rj.contains("exit_code") && !rj["exit_code"].is_null()) {
        r.exit_code = rj["exit_code"].get<int32_t>();
      }
      if (rj.contains("children") && rj["children"].is_array()) {
        r.children = rj["children"].get<std::vector<int32_t>>();
      }
      t.processes.push_back(std::move(r));
    }
  }
  return t;
  } catch (const json::exception& e) {
    throw BundleError(std::string("process_tree has a field of unexpected type: ") +
                      e.what());
  }
}

} // namespace vishaya::bundle
