#pragma once

#include <string>

namespace vishaya::bundle {

// Returns lowercase hex SHA-256 of the file at path.
// Throws BundleError on any failure (open, read, OpenSSL).
std::string sha256_hex_of_file(const std::string& path);

// Returns lowercase hex SHA-256 of in-memory bytes.
// Throws BundleError on any OpenSSL failure.
std::string sha256_hex_of_bytes(const std::string& data);

} // namespace vishaya::bundle
