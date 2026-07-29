cmake_minimum_required(VERSION 3.20)
project(vishaya LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "Vishaya is Linux-only. Build on a Linux host.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# External dependencies
# ---------------------------------------------------------------------------

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF     REQUIRED libbpf>=0.8)
pkg_check_modules(LIBZSTD    REQUIRED libzstd>=1.4.0)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive>=3.4.0)  # zstd write filter support

find_package(nlohmann_json 3.9 QUIET)
if(NOT nlohmann_json_FOUND)
  message(FATAL_ERROR
    "nlohmann_json (>=3.9) not found. Install with:\n"
    "  Ubuntu/Debian: sudo apt install nlohmann-json3-dev\n"
    "  Fedora:        sudo dnf install json-devel\n"
    "  Arch:          sudo pacman -S nlohmann-json")
endif()

find_package(CLI11 2.2 QUIET)
if(NOT CLI11_FOUND)
  message(FATAL_ERROR
    "CLI11 (>=2.2) not found. Install with:\n"
    "  Ubuntu/Debian: sudo apt install libcli11-dev\n"
    "  Fedora:        sudo dnf install cli11-devel\n"
    "  Arch:          sudo pacman -S cli11")
endif()

# 1.1.1 (not 1.1.0) is the real floor: bundle signing/verification uses Ed25519
# (EVP_PKEY_ED25519, EVP_PKEY_new_raw_public_key, one-shot EVP_DigestSign/Verify),
# all introduced in OpenSSL 1.1.1.
find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)

message(STATUS "Vishaya v0.2 build")
message(STATUS "  libbpf:        ${LIBBPF_VERSION}")
message(STATUS "  libzstd:       ${LIBZSTD_VERSION}")
message(STATUS "  libarchive:    ${LIBARCHIVE_VERSION}")
message(STATUS "  nlohmann_json: ${nlohmann_json_VERSION}")
message(STATUS "  CLI11:         ${CLI11_VERSION}")
message(STATUS "  OpenSSL:       ${OPENSSL_VERSION}")

# ---------------------------------------------------------------------------
# Security hardening (defense-in-depth). This binary parses hostile bundles and
# `capture` runs as root, so the standard Linux hardening set is applied to every
# target defined below. Cheap and widely supported by GCC/Clang.
#   - stack-protector-strong: canary against stack smashing
#   - _FORTIFY_SOURCE=2:      fortified libc calls (needs optimization → non-Debug)
#   - PIE + full RELRO + BIND_NOW: ASLR for the executable, read-only GOT
#   - -fno-strict-overflow:  no surprising signed-overflow optimizations
# ---------------------------------------------------------------------------
add_compile_options(
  -fstack-protector-strong
  -fno-strict-overflow
  $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:-D_FORTIFY_SOURCE=2>
)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_link_options(-pie -Wl,-z,relro,-z,now)

# ---------------------------------------------------------------------------
# BPF object generation (delegated to scripts/linux.sh which knows the
# per-arch clang flags, vmlinux.h dump, etc.).
# ---------------------------------------------------------------------------

add_custom_target(bpf_object
  COMMAND "${CMAKE_SOURCE_DIR}/scripts/linux.sh" bpf
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Build Vishaya BPF object (bpf/vishaya.bpf.o)"
)

# ---------------------------------------------------------------------------
# Shared collector library (inherited vishaya_collector namespace).
# Manages libbpf load/attach/poll for the BPF probes. Internal to Vishaya;
# treated as a stable inherited dependency.
# ---------------------------------------------------------------------------

add_library(vishaya_collector_core STATIC
  src/collector/collector_libbpf.cpp
  src/decoder/decoder.cpp
  src/enricher/enricher.cpp
)
target_include_directories(vishaya_collector_core PUBLIC
  src include
  ${LIBBPF_INCLUDE_DIRS}
)
target_link_libraries(vishaya_collector_core PUBLIC ${LIBBPF_LIBRARIES})
target_compile_definitions(vishaya_collector_core PUBLIC
  VISHAYA_HAVE_LIBBPF=1
  VISHAYA_DEFAULT_BPF_OBJECT="${CMAKE_SOURCE_DIR}/bpf/vishaya.bpf.o"
)
target_compile_options(vishaya_collector_core PRIVATE -Wall -Wextra -Wpedantic)
# Ensure the BPF object is compiled before the collector that embeds its path.
# Without this, `cmake --build` may link vishaya_collector_core before the
# .bpf.o file exists at the VISHAYA_DEFAULT_BPF_OBJECT path.
add_dependencies(vishaya_collector_core bpf_object)

# ---------------------------------------------------------------------------
# Vishaya modules
# ---------------------------------------------------------------------------

add_library(vishaya_common STATIC
  src/common/log.cpp
  src/common/tmp_dir.cpp
)
target_include_directories(vishaya_common PUBLIC src include)
target_compile_options(vishaya_common PRIVATE -Wall -Wextra -Wpedantic)

add_library(vishaya_isolation STATIC
  src/isolation/cgroup.cpp
  src/isolation/target_launch.cpp
)
target_include_directories(vishaya_isolation PUBLIC src include)
target_link_libraries(vishaya_isolation PUBLIC vishaya_common)
target_compile_options(vishaya_isolation PRIVATE -Wall -Wextra -Wpedantic)

add_library(vishaya_bundle STATIC
  src/bundle/hash.cpp
  src/bundle/manifest.cpp
  src/bundle/artifacts.cpp
  src/bundle/process_tree.cpp
  src/bundle/sign.cpp
  src/bundle/writer.cpp
  src/bundle/reader.cpp
)
target_include_directories(vishaya_bundle PUBLIC
  src include
  ${LIBZSTD_INCLUDE_DIRS}
  ${LIBARCHIVE_INCLUDE_DIRS}
)
target_link_libraries(vishaya_bundle
  PUBLIC
    vishaya_common
    nlohmann_json::nlohmann_json
  PRIVATE
    ${LIBZSTD_LIBRARIES}
    ${LIBARCHIVE_LIBRARIES}
    OpenSSL::Crypto
)
target_compile_options(vishaya_bundle PRIVATE -Wall -Wextra -Wpedantic)

add_library(vishaya_capture STATIC
  src/capture/wal_writer.cpp
  src/capture/event_to_json.cpp
  src/capture/protocol_decoder.cpp
  src/capture/artifact_collector.cpp
  src/capture/session.cpp
)
target_include_directories(vishaya_capture PUBLIC src include)
target_link_libraries(vishaya_capture PUBLIC
  vishaya_collector_core
  vishaya_bundle
  vishaya_common
  nlohmann_json::nlohmann_json
)
target_compile_options(vishaya_capture PRIVATE -Wall -Wextra -Wpedantic)

add_library(vishaya_inspect STATIC
  src/inspect/tree.cpp
  src/inspect/files.cpp
  src/inspect/network.cpp
  src/inspect/timeline.cpp
  src/inspect/verify.cpp
  src/inspect/summary.cpp
  src/inspect/diff.cpp
  src/inspect/artifacts.cpp
)
target_include_directories(vishaya_inspect PUBLIC src include)
target_link_libraries(vishaya_inspect PUBLIC
  vishaya_bundle
  vishaya_common
)
target_compile_options(vishaya_inspect PRIVATE -Wall -Wextra -Wpedantic)

add_library(vishaya_cli STATIC
  src/cli/dispatcher.cpp
  src/cli/capture_cmd.cpp
)
target_include_directories(vishaya_cli PUBLIC src include)
target_link_libraries(vishaya_cli PUBLIC
  vishaya_inspect
  vishaya_capture
  vishaya_isolation
  vishaya_common
  CLI11::CLI11
)
target_compile_options(vishaya_cli PRIVATE -Wall -Wextra -Wpedantic)

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------

# Primary product binary.
add_executable(vishaya src/cli/main.cpp)
target_link_libraries(vishaya PRIVATE vishaya_cli vishaya_common)
target_compile_options(vishaya PRIVATE -Wall -Wextra -Wpedantic)

# Standalone smoke test for the isolation subsystem (no eBPF).
add_executable(isolation_probe src/isolation/isolation_probe.cpp)
target_link_libraries(isolation_probe PRIVATE
  vishaya_isolation
  vishaya_common
  CLI11::CLI11
)
target_compile_options(isolation_probe PRIVATE -Wall -Wextra -Wpedantic)

# Standalone smoke test for the bundle writer (no eBPF, no isolation).
add_executable(bundle_probe src/bundle/bundle_probe.cpp)
target_link_libraries(bundle_probe PRIVATE
  vishaya_bundle
  vishaya_common
  CLI11::CLI11
)
target_compile_options(bundle_probe PRIVATE -Wall -Wextra -Wpedantic)
