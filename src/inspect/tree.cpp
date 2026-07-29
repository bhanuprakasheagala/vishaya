#include "inspect/tree.h"

#include "bundle/reader.h"
#include "common/errors.h"
#include "common/log.h"
#include "inspect/render.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace vishaya::inspect {

namespace {

// Guard rails for untrusted input: process_tree.json comes from a bundle we did
// not necessarily produce. A crafted/corrupt tree can contain a cycle (A→B→A) or
// a pathologically deep chain; either would drive this recursion into a stack
// overflow (SIGSEGV) that no try/catch can intercept. `visited` breaks cycles;
// `kMaxDepth` bounds legitimate-but-deep trees (real process trees are shallow).
constexpr int kMaxDepth = 512;

void print_node(const std::unordered_map<int32_t, const vishaya::bundle::ProcessRecord*>& by_tgid,
                int32_t                             tgid,
                const std::string&                  prefix,
                bool                                is_last,
                std::unordered_set<int32_t>&        visited,
                int                                 depth) {
  auto it = by_tgid.find(tgid);
  if (it == by_tgid.end()) {
    std::cout << prefix << (is_last ? "└── " : "├── ")
              << "(missing pid=" << tgid << ")\n";
    return;
  }
  const auto& r = *it->second;

  std::cout << prefix
            << (is_last ? "└── " : "├── ")
            << (r.comm.empty() ? "<unknown>" : scrub_for_terminal(r.comm))
            << " (pid=" << r.tgid;
  if (!r.exec_path.empty()) {
    std::cout << " exec=" << scrub_for_terminal(r.exec_path);
  }
  if (r.exit_code.has_value()) {
    std::cout << " exit=" << *r.exit_code;
  }

  // Cycle detection: if we've already printed this pid on the path down, stop.
  if (!visited.insert(tgid).second) {
    std::cout << " …cycle)\n";
    return;
  }
  std::cout << ")\n";

  if (depth + 1 >= kMaxDepth) {
    const std::string next_prefix = prefix + (is_last ? "    " : "│   ");
    if (!r.children.empty()) std::cout << next_prefix << "… (max depth)\n";
    visited.erase(tgid);
    return;
  }

  const std::string next_prefix = prefix + (is_last ? "    " : "│   ");
  const auto&       children    = r.children;
  for (size_t i = 0; i < children.size(); ++i) {
    print_node(by_tgid, children[i], next_prefix, i + 1 == children.size(),
               visited, depth + 1);
  }
  // Allow the same pid to appear under a different sibling subtree (a DAG is not
  // a cycle); only paths that revisit an ancestor are treated as cycles.
  visited.erase(tgid);
}

} // namespace

int run_tree(const std::string& bundle_path) {
  try {
    vishaya::bundle::Reader    reader(bundle_path);
    reader.verify();  // spec §6/§9: verify integrity + signature at load (warns on failure)
    const auto&                tree = reader.process_tree();

    std::unordered_map<int32_t, const vishaya::bundle::ProcessRecord*> by_tgid;
    for (const auto& r : tree.processes) by_tgid[r.tgid] = &r;

    std::cout << "bundle: " << bundle_path << "\n";
    std::cout << "target: pid=" << tree.root_pid;
    if (auto it = by_tgid.find(tree.root_pid); it != by_tgid.end()) {
      const auto& r = *it->second;
      if (!r.exec_path.empty()) std::cout << " exec=" << scrub_for_terminal(r.exec_path);
      if (!r.cmdline.empty())   std::cout << " cmdline=\"" << scrub_for_terminal(r.cmdline) << "\"";
    }
    std::cout << "\n\n";

    if (tree.processes.empty()) {
      std::cout << "(no processes captured)\n";
      return 0;
    }

    // Print root subtree.
    std::unordered_set<int32_t> visited;
    print_node(by_tgid, tree.root_pid, "", true, visited, 0);

    // Print orphans (processes not reachable from root).
    std::vector<int32_t> orphans;
    for (const auto& r : tree.processes) {
      if (r.tgid == tree.root_pid) continue;
      // Reachable from root?
      bool reachable = false;
      int32_t cur = r.tgid;
      for (int hop = 0; hop < 1000; ++hop) {
        if (cur == tree.root_pid) { reachable = true; break; }
        auto it = by_tgid.find(cur);
        if (it == by_tgid.end() || it->second->ppid == 0 || it->second->ppid == cur) break;
        cur = it->second->ppid;
      }
      if (!reachable) orphans.push_back(r.tgid);
    }
    if (!orphans.empty()) {
      std::cout << "\n(orphans not reachable from root):\n";
      for (size_t i = 0; i < orphans.size(); ++i) {
        visited.clear();
        print_node(by_tgid, orphans[i], "", i + 1 == orphans.size(), visited, 0);
      }
    }
    return 0;
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("tree failed: ") + e.what());
    return 1;
  }
}

} // namespace vishaya::inspect
