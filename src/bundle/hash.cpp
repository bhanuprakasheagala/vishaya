#include "bundle/hash.h"

#include "common/errors.h"

#include <fstream>
#include <openssl/evp.h>

namespace vishaya::bundle {

namespace {

std::string hex_encode(const unsigned char* hash, unsigned int len) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(static_cast<size_t>(len) * 2);
  for (unsigned i = 0; i < len; ++i) {
    hex.push_back(kHex[(hash[i] >> 4) & 0xf]);
    hex.push_back(kHex[hash[i] & 0xf]);
  }
  return hex;
}

} // namespace

Sha256Streamer::Sha256Streamer() : ctx_(EVP_MD_CTX_new()) {
  if (!ctx_) throw BundleError("EVP_MD_CTX_new failed");
  if (EVP_DigestInit_ex(static_cast<EVP_MD_CTX*>(ctx_), EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
    ctx_ = nullptr;
    throw BundleError("EVP_DigestInit_ex failed");
  }
}

Sha256Streamer::~Sha256Streamer() {
  if (ctx_) EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
}

void Sha256Streamer::update(const void* data, size_t len) {
  if (len == 0) return;
  if (EVP_DigestUpdate(static_cast<EVP_MD_CTX*>(ctx_), data, len) != 1) {
    throw BundleError("EVP_DigestUpdate failed");
  }
}

std::string Sha256Streamer::finalize_hex() {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int  hash_len = 0;
  if (EVP_DigestFinal_ex(static_cast<EVP_MD_CTX*>(ctx_), hash, &hash_len) != 1) {
    throw BundleError("EVP_DigestFinal_ex failed");
  }
  return hex_encode(hash, hash_len);
}

std::string sha256_hex_of_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw BundleError("open for hashing failed: " + path);

  Sha256Streamer s;
  char buf[65536];
  while (in) {
    in.read(buf, sizeof(buf));
    const std::streamsize got = in.gcount();
    if (got > 0) s.update(buf, static_cast<size_t>(got));
  }
  return s.finalize_hex();
}

std::string sha256_hex_of_bytes(const std::string& data) {
  Sha256Streamer s;
  s.update(data.data(), data.size());
  return s.finalize_hex();
}

} // namespace vishaya::bundle
