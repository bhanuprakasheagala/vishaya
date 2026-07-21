#include "bundle/sign.h"

#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace vishaya::bundle {

namespace {

std::string base64_encode(const unsigned char* data, size_t len) {
  const size_t out_len = 4 * ((len + 2) / 3);
  std::string result(out_len, '\0');
  const int actual = EVP_EncodeBlock(
      reinterpret_cast<unsigned char*>(&result[0]), data, static_cast<int>(len));
  result.resize(static_cast<size_t>(actual >= 0 ? actual : 0));
  return result;
}

// Decode standard base64 into raw bytes. Expects input length to be a multiple
// of 4 (as produced by EVP_EncodeBlock). Returns empty on malformed input.
std::string base64_decode(const std::string& in) {
  if (in.empty() || (in.size() % 4) != 0) return {};
  std::string out(3 * (in.size() / 4), '\0');
  const int len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                                  reinterpret_cast<const unsigned char*>(in.data()),
                                  static_cast<int>(in.size()));
  if (len < 0) return {};
  // EVP_DecodeBlock returns a length rounded up to a multiple of 3 and does not
  // account for '=' padding; subtract the padding count to get the true size.
  size_t pad = 0;
  if (in[in.size() - 1] == '=') ++pad;
  if (in.size() >= 2 && in[in.size() - 2] == '=') ++pad;
  out.resize(static_cast<size_t>(len) - pad);
  return out;
}

std::string key_path_from_home() {
  const char* home = std::getenv("HOME");
  if (!home || home[0] == '\0') return {};
  return std::string(home) + "/.config/vishaya/keys/signing.key";
}

bool read_file_to_string(const std::string& path, std::string& out) {
  std::ifstream in(path);
  if (!in.is_open()) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool mkdir_if_missing(const std::string& path) {
  struct stat st{};
  if (::stat(path.c_str(), &st) == 0) return true;  // already exists
  return ::mkdir(path.c_str(), 0755) == 0;
}

bool ensure_key_dir(const char* home) {
  if (!mkdir_if_missing(std::string(home) + "/.config")) return false;
  if (!mkdir_if_missing(std::string(home) + "/.config/vishaya")) return false;
  return mkdir_if_missing(std::string(home) + "/.config/vishaya/keys");
}

bool generate_and_save_key(const std::string& path, std::string& pem_out) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!ctx) return false;

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return false;
  }
  EVP_PKEY_CTX_free(ctx);

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    EVP_PKEY_free(pkey);
    return false;
  }

  if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return false;
  }
  EVP_PKEY_free(pkey);

  BUF_MEM* mem = nullptr;
  if (BIO_get_mem_ptr(bio, &mem) != 1 || !mem) {
    BIO_free(bio);
    return false;
  }
  std::string pem(mem->data, mem->length);
  BIO_free(bio);

  // Write with O_EXCL so a race between two processes writing simultaneously
  // is harmless — the loser simply skips the file write and uses the in-memory key.
  // On partial write (e.g. full filesystem), remove the truncated file so the
  // next run can regenerate rather than loading an unparseable PEM.
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd >= 0) {
    const ssize_t written = ::write(fd, pem.data(), pem.size());
    ::close(fd);
    if (written != static_cast<ssize_t>(pem.size())) {
      ::unlink(path.c_str());
    }
  }

  pem_out = std::move(pem);
  return true;
}

} // namespace

bool load_or_generate_signing_key(std::string& pem_out) {
  const std::string path = key_path_from_home();
  if (path.empty()) return false;

  // Fast path: load existing key.
  std::string pem;
  if (read_file_to_string(path, pem)) {
    pem_out = std::move(pem);
    return true;
  }

  // Slow path: ensure directory and generate.
  const char* home = std::getenv("HOME");
  if (!home || !ensure_key_dir(home)) return false;

  return generate_and_save_key(path, pem_out);
}

BundleSignature sign_data(const std::string& pem_private_key, const std::string& data) {
  BundleSignature result;

  BIO* bio = BIO_new_mem_buf(pem_private_key.data(),
                             static_cast<int>(pem_private_key.size()));
  if (!bio) return result;

  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!pkey) return result;

  // Extract the 32-byte raw public key.
  size_t pub_len = 32;
  unsigned char pub_bytes[32] = {};
  if (EVP_PKEY_get_raw_public_key(pkey, pub_bytes, &pub_len) != 1) {
    EVP_PKEY_free(pkey);
    return result;
  }

  // Sign. Ed25519 is a pure-message scheme; md must be NULL.
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    EVP_PKEY_free(pkey);
    return result;
  }

  if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) != 1) {
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return result;
  }

  size_t sig_len = 64;
  unsigned char sig_bytes[64] = {};
  const int signed_ok = EVP_DigestSign(
      mdctx, sig_bytes, &sig_len,
      reinterpret_cast<const unsigned char*>(data.data()), data.size());

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);

  if (signed_ok != 1) return result;

  result.algorithm  = "Ed25519";
  result.pubkey_b64 = base64_encode(pub_bytes, pub_len);
  result.sig_b64    = base64_encode(sig_bytes, sig_len);
  return result;
}

bool verify_signature(const BundleSignature& sig, const std::string& data) {
  if (sig.algorithm != "Ed25519") return false;

  const std::string pub = base64_decode(sig.pubkey_b64);
  const std::string sg  = base64_decode(sig.sig_b64);
  if (pub.size() != 32 || sg.size() != 64) return false;

  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(pub.data()), pub.size());
  if (!pkey) return false;

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  bool ok = false;
  // Ed25519 is a pure-message scheme; md must be NULL (matches sign_data()).
  if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) == 1) {
    const int rc = EVP_DigestVerify(
        mdctx,
        reinterpret_cast<const unsigned char*>(sg.data()), sg.size(),
        reinterpret_cast<const unsigned char*>(data.data()), data.size());
    ok = (rc == 1);
  }

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return ok;
}

} // namespace vishaya::bundle
