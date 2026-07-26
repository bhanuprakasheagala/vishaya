#pragma once

/*
 * File Notes:
 * - Ed25519 bundle signing interface. Uses the BundleSignature type defined in
 *   manifest.h so callers do not need a separate struct.
 * - The keypair is loaded from (or generated at) ~/.config/vishaya/keys/signing.key.
 *   The private key file is written with mode 0600. Signing is best-effort:
 *   callers log a warning and continue without a signature if the key is unavailable.
 */

#include "bundle/manifest.h"

#include <string>

namespace vishaya::bundle {

// Load the Ed25519 private key from ~/.config/vishaya/keys/signing.key.
// If the file does not exist, a new keypair is generated and saved there.
// Returns false if the key cannot be loaded or generated; pem_out is
// unmodified in that case. Logs no output — the caller decides on warning policy.
bool load_or_generate_signing_key(std::string& pem_out);

// Sign `data` with the PEM-encoded Ed25519 private key. On success returns a
// BundleSignature with algorithm="Ed25519" and the base64-encoded public key
// and signature. Returns a zero-value BundleSignature (algorithm="") on failure.
BundleSignature sign_data(const std::string& pem_private_key, const std::string& data);

// Short, stable fingerprint of a base64 Ed25519 public key: the first 16 hex
// chars of SHA-256(raw 32-byte key). Returns "unknown" if the key can't be
// decoded to 32 bytes. For out-of-band recording and pinned-key display.
std::string pubkey_fingerprint(const std::string& pubkey_b64);

// Verify a BundleSignature over `data`. Returns true iff the signature block is
// present (algorithm == "Ed25519"), its base64 fields decode to the expected
// lengths (32-byte public key, 64-byte signature), and the signature is valid
// for `data` under the embedded public key. Returns false on any failure —
// unsupported/empty algorithm, malformed base64, wrong length, or bad signature.
// Does not log; the caller decides on warning policy.
bool verify_signature(const BundleSignature& sig, const std::string& data);

} // namespace vishaya::bundle
