# Build System

CMake structure, library graph, external dependencies, and how to extend the build without breaking it.

## Two-step build

Vishaya builds in two independent steps because BPF and userspace use different toolchains:

1. **Userspace binaries** — built by CMake using your system C++ compiler.
2. **BPF object** — built by `scripts/linux.sh bpf` using clang directly with `-target bpf`. CMake defines a `bpf_object` custom target that delegates to the script, but you can also run it standalone.

```bash
./scripts/linux.sh all         # both steps
./scripts/linux.sh build       # userspace only (calls cmake internally)
./scripts/linux.sh bpf         # BPF object only
```

## External dependencies

| Dependency | Why | License |
|---|---|---|
| libbpf | Kernel eBPF load/attach/ring-buffer polling | BSD-2 |
| bpftool | BTF dump at build time (produces `bpf/vmlinux.h`) | GPL-2 |
| clang / LLVM | Compiles BPF C into eBPF bytecode | Apache-2 |
| CMake ≥ 3.20 | Userspace build system | BSD-3 |
| pkg-config | Locates C libraries at configure time | GPL-2 |
| libzstd | Zstd compression for `.vishaya` bundles | BSD-3 |
| libarchive | Tar container read/write for `.vishaya` bundles | BSD-2 |
| nlohmann/json ≥ 3.9 | JSON ser/de (manifest, process_tree, events) | MIT |
| CLI11 ≥ 2.2 | Command-line argument parsing | BSD-3 |
| OpenSSL libcrypto ≥ 1.1 | SHA-256 for bundle integrity hashes | Apache-2 |

All are available in mainstream Linux distro package repos. `./scripts/linux.sh check` prints install commands per distro.

## Library graph

Vishaya's userspace is built as several small STATIC libraries linked into three executables. The dependency graph is strictly acyclic:

```
vishaya (executable)
  └── vishaya_cli
        ├── vishaya_inspect ─── vishaya_bundle ─── vishaya_common
        ├── vishaya_capture ─── vishaya_collector_core ─── libbpf
        │                   └── vishaya_bundle
        │                   └── vishaya_common
        ├── vishaya_isolation ─── vishaya_common
        └── vishaya_common
        └── CLI11

isolation_probe (executable)
  ├── vishaya_isolation
  ├── vishaya_common
  └── CLI11

bundle_probe (executable)
  ├── vishaya_bundle
  ├── vishaya_common
  └── CLI11

vishaya_bundle
  ├── vishaya_common
  ├── nlohmann_json  (PUBLIC — types appear in bundle headers)
  ├── libzstd        (PRIVATE — only used inside writer.cpp)
  ├── libarchive     (PRIVATE)
  └── OpenSSL::Crypto (PRIVATE — SHA-256 in writer.cpp + reader.cpp)

vishaya_collector_core
  ├── src/collector/collector_libbpf.cpp
  ├── src/decoder/decoder.cpp
  ├── src/enricher/enricher.cpp
  └── libbpf (PUBLIC — collector headers include <bpf/*.h>)
```

**Rules used:**
- **PUBLIC** deps are re-exported to consumers (needed when public headers `#include` from the dep).
- **PRIVATE** deps are only linked; consumers don't see them.
- **INTERFACE** deps carry no source but propagate flags/includes.

## CMakeLists.txt walkthrough

The file is short (~190 lines). Read it top to bottom:

1. **Project + platform guard** (lines 1-11) — `project(vishaya)`, C++20 required, hard-fail on non-Linux.
2. **External dependency detection** (lines 13-48) — `pkg_check_modules` for libbpf/libzstd/libarchive; `find_package` for nlohmann_json/CLI11/OpenSSL. Every dep has a version constraint. Missing deps produce a helpful error message pointing at `apt`/`dnf`/`pacman` install commands.
3. **BPF custom target** (lines 50-59) — `add_custom_target(bpf_object COMMAND ${CMAKE_SOURCE_DIR}/scripts/linux.sh bpf)`. Delegates to the shell script because clang's `-target bpf` invocation needs per-arch flags CMake doesn't handle cleanly.
4. **`vishaya_collector_core` library** (lines 61-85) — the inherited BPF-load/attach/poll code. Marked with `VISHAYA_HAVE_LIBBPF=1` and `VISHAYA_DEFAULT_BPF_OBJECT="${CMAKE_SOURCE_DIR}/bpf/vishaya.bpf.o"` for path resolution at runtime. The `add_dependencies(vishaya_collector_core bpf_object)` call appears at the end of this block (after `add_library`) so CMake can resolve the target name before the dependency is registered.
5. **`vishaya_common`** (lines 86-91) — logging + errors + RAII helpers.
6. **`vishaya_isolation`** (lines 93-99) — cgroup + namespace + fork/exec.
7. **`vishaya_bundle`** (lines 101-121) — writer + reader; PUBLIC nlohmann_json (types appear in headers), PRIVATE libzstd/libarchive/OpenSSL (implementation details).
8. **`vishaya_capture`** (lines 123-136) — Session + protocol_decoder. Links vishaya_collector_core PUBLIC.
9. **`vishaya_inspect`** (lines 138-149) — the four subcommand implementations.
10. **`vishaya_cli`** (lines 151-163) — argument parser + subcommand router.
11. **Executables** (lines 169-189) — `vishaya`, `isolation_probe`, `bundle_probe`.

## Adding a new module

Say you want to add a `vishaya_analyze` module for post-capture analysis. The pattern:

1. Create `src/analyze/` with your `.h`/`.cpp` files.
2. In `CMakeLists.txt`, add:

```cmake
add_library(vishaya_analyze STATIC
  src/analyze/foo.cpp
  src/analyze/bar.cpp
)
target_include_directories(vishaya_analyze PUBLIC src include)
target_link_libraries(vishaya_analyze PUBLIC
  vishaya_bundle     # if you read bundles
  vishaya_common
)
target_compile_options(vishaya_analyze PRIVATE -Wall -Wextra -Wpedantic)
```

3. Link into wherever it's needed. If it's used by `vishaya_cli` (a new subcommand), add `vishaya_analyze` to `vishaya_cli`'s `target_link_libraries`.

**Rules to follow:**
- Every library gets `-Wall -Wextra -Wpedantic`.
- Include directories are PUBLIC (`src include`) so consumers can `#include "analyze/foo.h"`.
- Cross-module dependencies go one direction: `cli → capture/inspect/analyze → bundle/isolation → collector → common`. No cycles.
- No PUBLIC linkage of a private-implementation library.

## Adding a new external dependency

Weigh it first. Vishaya deliberately has few dependencies. Adding one increases build friction for every user.

If you must:

1. Pick something in mainstream distro package repos (Debian, Fedora, Arch). If it's not packaged, users have to build it themselves.
2. Add the detection block in `CMakeLists.txt`, following the pattern of the existing deps:

```cmake
find_package(YourDep 1.0 QUIET)
if(NOT YourDep_FOUND)
  message(FATAL_ERROR
    "YourDep (>=1.0) not found. Install with:\n"
    "  Ubuntu/Debian: sudo apt install libyourdep-dev\n"
    "  Fedora:        sudo dnf install yourdep-devel\n"
    "  Arch:          sudo pacman -S yourdep")
endif()
message(STATUS "  YourDep:       ${YourDep_VERSION}")
```

3. Link it to the library that uses it, with the right visibility (PUBLIC if used in headers, PRIVATE if only in .cpp).
4. Update the dependency table at the top of this document.
5. Update `scripts/linux.sh check` hints to include the new package.
6. Update `README.md` dependency list.

## Debug vs release builds

Vishaya doesn't currently ship a preset for either. CMake defaults to no optimization + no debug info. For useful builds:

```bash
# Debug (asserts on, no optimization, debug symbols)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j

# Release (optimized, no asserts, debug symbols for stack traces)
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
```

BPF object build is always `-g -O2` per the script; that's the recommended combination for the verifier.

## BPF build details

`scripts/linux.sh bpf` does:

1. Dumps `/sys/kernel/btf/vmlinux` (kernel BTF debug info) to `bpf/vmlinux.h` via `bpftool btf dump ... format c`.
2. Detects your architecture (`x86_64`, `aarch64`, etc.) and picks the right `__TARGET_ARCH_*` define.
3. Locates a clang binary (`CLANG` env var, or a `clang`/`clang-XX` in PATH).
4. Handles Debian/Ubuntu multiarch include paths so `stdint.h` resolves inside `-target bpf` compilation.
5. Invokes clang with `-g -O2 -target bpf -mllvm -bpf-stack-size=8192` on `bpf/vishaya.bpf.c` → `bpf/vishaya.bpf.o`.

The stack size of 8192 (vs. default 512) is required because our `network_state_value` struct is large after adding payload capture in Step 9.

`bpf/vmlinux.h` is regenerated on every BPF build so it always matches the running kernel. Don't commit it — it's inherently host-specific.

## Cleaning up

```bash
rm -rf build/            # userspace build artifacts
rm bpf/vishaya.bpf.o     # BPF object
rm bpf/vmlinux.h         # regenerated on next `bpf` build
```

Or nuke everything and re-run:

```bash
rm -rf build/ bpf/vishaya.bpf.o bpf/vmlinux.h
./scripts/linux.sh all
```

## CI hints

If you set up continuous integration:

- Test on multiple LTS kernels (5.15, 6.1, 6.6+). BPF behavior can vary.
- Run `./scripts/linux.sh check` first — fail fast on missing tools.
- Build BPF object first (`./scripts/linux.sh bpf`) before userspace — the userspace embeds the BPF object path.
- Run `isolation_probe` as a smoke test (needs root; use a privileged container or `sudo`).
- Run `bundle_probe` as an unprivileged smoke test (no root needed).
