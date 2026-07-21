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

std::string sha256_hex_of_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw BundleError("open for hashing failed: " + path);

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) throw BundleError("EVP_MD_CTX_new failed");
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    throw BundleError("EVP_DigestInit_ex failed");
  }

  char buf[65536];
  while (in) {
    in.read(buf, sizeof(buf));
    const std::streamsize got = in.gcount();
    if (got > 0) {
      if (EVP_DigestUpdate(ctx, buf, static_cast<size_t>(got)) != 1) {
        EVP_MD_CTX_free(ctx);
        throw BundleError("EVP_DigestUpdate failed");
      }
    }
  }

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int  hash_len = 0;
  if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    EVP_MD_CTX_free(ctx);
    throw BundleError("EVP_DigestFinal_ex failed");
  }
  EVP_MD_CTX_free(ctx);
  return hex_encode(hash, hash_len);
}

std::string sha256_hex_of_bytes(const std::string& data) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) throw BundleError("EVP_MD_CTX_new failed");
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    throw BundleError("EVP_DigestInit_ex failed");
  }
  if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
    EVP_MD_CTX_free(ctx);
    throw BundleError("EVP_DigestUpdate failed");
  }

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int  hash_len = 0;
  if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    EVP_MD_CTX_free(ctx);
    throw BundleError("EVP_DigestFinal_ex failed");
  }
  EVP_MD_CTX_free(ctx);
  return hex_encode(hash, hash_len);
}

} // namespace vishaya::bundle
