#pragma once

#include <cstddef>
#include <string>

namespace vishaya::bundle {

// Incremental SHA-256. Feed bytes with update() (any number of calls), then call
// finalize_hex() exactly once to obtain the lowercase hex digest. Used to hash
// data that arrives in chunks without buffering the whole input — e.g. copying an
// artifact while hashing it, or hashing a tar entry as it streams out of libarchive.
//
// The OpenSSL context is held as an opaque void* so this header stays free of
// <openssl/evp.h>: OpenSSL is a PRIVATE dependency of vishaya_bundle, so capture-
// layer TUs that include this header must not pull in OpenSSL include paths.
//
// Throws BundleError on any OpenSSL failure. Not copyable.
class Sha256Streamer {
 public:
  Sha256Streamer();
  ~Sha256Streamer();
  Sha256Streamer(const Sha256Streamer&)            = delete;
  Sha256Streamer& operator=(const Sha256Streamer&) = delete;

  void        update(const void* data, size_t len);
  std::string finalize_hex();  // call once

 private:
  void* ctx_;  // EVP_MD_CTX*
};

// Returns lowercase hex SHA-256 of the file at path (streamed).
// Throws BundleError on any failure (open, read, OpenSSL).
std::string sha256_hex_of_file(const std::string& path);

// Returns lowercase hex SHA-256 of in-memory bytes.
// Throws BundleError on any OpenSSL failure.
std::string sha256_hex_of_bytes(const std::string& data);

} // namespace vishaya::bundle
